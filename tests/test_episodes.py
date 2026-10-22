import ipaddress
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from live.episodes import EpisodeTracker  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakeResponse:
    def __init__(self, mode='suggest', webhook=None):
        self.mode, self.webhook, self.blocked = mode, webhook, []

    def config(self):
        return {'mode': self.mode, 'backend': 'dry-run', 'notify': {'slackWebhook': self.webhook}}

    def block(self, ip, reason, ttl_minutes=None, source='analyst', alert_id=None):
        if ip.startswith('127.'):
            return {'ip': ip, 'status': 'failed', 'error': 'refused: loopback address'}
        self.blocked.append(ip)
        return {'ip': ip, 'status': 'active', 'error': None}

    def _tell(self, text):
        pass


def feed(tr, clock, secs, per_sec, **kw):
    for _ in range(secs):
        for i in range(per_sec):
            tr.add(kw.get('family', 'DDoS'), 'Distributed denial of service', kw.get('sev', 'critical'),
                   '192.168.1.10', f'198.51.100.{i % 250 + 1}', rule=True)
        clock.t += 1


def only(tr):
    eps = tr.snapshot()['episodes']
    assert len(eps) == 1
    return eps[0]


def test_lifecycle_active_contained_resolved():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('auto'), clock=clk)
    feed(tr, clk, 5, 40)
    ep = only(tr)
    assert ep['state'] == 'active' and ep['flows'] == 200 and ep['sources'] == 40
    assert tr.snapshot()['status']['level'] == 'under-attack'
    clk.t += 10  # attack stops: rate falls below 20 % of peak
    assert only(tr)['state'] == 'contained'
    assert tr.snapshot()['status']['level'] == 'calm'
    clk.t += 25  # 30+ s without alerts
    ep = only(tr)
    assert ep['state'] == 'resolved'
    clk.t += 5
    tr.add('DDoS', 'x', 'critical', '192.168.1.10', '198.51.100.1', rule=True)  # a new alert opens a new episode
    states = [e['state'] for e in tr.snapshot()['episodes']]
    assert states[0] == 'active' and 'resolved' in states


def test_severity_escalation_and_dedupe_by_key():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('suggest'), clock=clk)
    tr.add('DoS', 'Denial of service', 'low', '10.0.0.5', '198.51.100.7', rule=True)
    assert [a['kind'] for a in only(tr)['actions']] == ['logged']
    clk.t += 1
    tr.add('DoS', 'Denial of service', 'high', '10.0.0.5', '198.51.100.7', rule=True)
    ep = only(tr)
    assert ep['severity'] == 'high' and ep['actions'][-1]['kind'] == 'blocked'
    tr.add('DoS', 'Denial of service', 'low', '10.0.0.5', '198.51.100.7', rule=True)
    assert only(tr)['severity'] == 'high'  # max severity kept
    tr.add('DoS', 'Denial of service', 'low', '10.0.0.6', '198.51.100.7', rule=True)  # different target: new episode
    assert len(tr.snapshot()['episodes']) == 2


def test_suggest_mode_only_recommends():
    clk = Clock()
    resp = FakeResponse('suggest')
    tr = EpisodeTracker(resp, clock=clk)
    feed(tr, clk, 3, 30)
    ep = only(tr)
    kinds = {a['kind']: a for a in ep['actions']}
    assert kinds['blocked']['status'] == 'recommended' and kinds['blocked']['detail'].startswith('Recommended')
    assert resp.blocked == [] and ep['blocked'] == []


def test_auto_mode_blocks_top_sources_and_upstream():
    clk = Clock()
    resp = FakeResponse('auto')
    tr = EpisodeTracker(resp, clock=clk)
    feed(tr, clk, 1, 5)
    feed(tr, clk, 1, 60)  # source count passes 20 -> upstream protection
    ep = only(tr)
    kinds = [a['kind'] for a in ep['actions']]
    assert 'blocked' in kinds and 'upstream-protection' in kinds
    assert 0 < len(resp.blocked) <= 10 and set(resp.blocked) == set(ep['blocked'])
    assert 'Cloudflare' in [a for a in ep['actions'] if a['kind'] == 'upstream-protection'][0]['detail']


def test_refused_blocks_are_not_recorded_as_blocked():
    clk = Clock()
    resp = FakeResponse('auto')
    tr = EpisodeTracker(resp, clock=clk)
    tr.add('BruteForce', 'Brute force', 'high', '192.168.1.10', '127.0.0.1', rule=True)
    ep = only(tr)
    assert resp.blocked == [] and ep['blocked'] == []
    assert ep['actions'][-1]['status'] == 'refused'


def test_single_model_alert_is_not_an_episode():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('auto'), clock=clk)
    tr.add('WebAttack', 'Web attack', 'critical', '192.168.1.6', '198.51.100.1')
    snap = tr.snapshot()
    assert snap['episodes'] == [] and snap['status']['level'] == 'calm'
    tr.add('WebAttack', 'Web attack', 'critical', '192.168.1.6', '198.51.100.1', n=2)
    assert len(tr.snapshot()['episodes']) == 1


def test_medium_notifies_and_insider_critical_isolates():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('auto'), clock=clk)
    tr.add('WebAttack', 'Web attack', 'medium', '192.168.1.10', '198.51.100.9', rule=True)
    assert [a['kind'] for a in only(tr)['actions']] == ['notified']
    tr2 = EpisodeTracker(FakeResponse('auto'), clock=clk)
    tr2.add('Insider', 'x', 'critical', '192.168.1.50', '192.168.1.20', rule=True)
    assert 'isolated' in [a['kind'] for a in only(tr2)['actions']]


def test_status_levels_and_resolve_and_reset():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('suggest'), clock=clk)
    assert tr.snapshot()['status']['level'] == 'calm'
    tr.add('PortScan', 'Port scan', 'medium', '192.168.1.10', '198.51.100.1', rule=True)
    assert tr.snapshot()['status']['level'] == 'elevated'
    tr.add('DDoS', 'DDoS', 'critical', '192.168.1.10', '198.51.100.2', rule=True)
    st = tr.snapshot()['status']
    assert st['level'] == 'under-attack' and st['activeEpisodes'] == 2 and '192.168.1.10' in st['headline']
    eid = tr.snapshot()['episodes'][0]['id']
    assert tr.resolve(eid)['state'] == 'resolved'
    with pytest.raises(KeyError):
        tr.resolve('nope')
    clk.t += 1
    # alert flood alone (>= 20 alerts/s) is under-attack even for a medium episode
    tr3 = EpisodeTracker(None, clock=clk)
    for _ in range(110):
        tr3.add('Bot', 'Botnet', 'medium', '10.0.0.1', '10.0.0.2', rule=True)
    assert tr3.snapshot()['status']['level'] == 'under-attack'
    tr.reset()
    snap = tr.snapshot()
    assert snap['episodes'] == [] and snap['status']['level'] == 'calm'


def test_pipeline_sensors_and_episodes():
    from live.pipeline import LivePipeline

    class Eng:  # the pipeline only touches the engine while scoring; heartbeats do not
        pass

    lp = LivePipeline(Eng())
    lp.ingest({'sensor': {'id': 'simulator', 'iface': 'sim', 'mode': 'sim'}, 'flows': []})
    assert lp.snapshot()['sensor']['id'] == 'simulator'  # only sensor
    lp.ingest({'sensor': {'id': 'en0', 'iface': 'en0', 'mode': 'pcap'}, 'flows': []})
    lp.ingest({'sensor': {'id': 'simulator', 'iface': 'sim', 'mode': 'sim'}, 'flows': []})
    snap = lp.snapshot()
    assert snap['sensor']['id'] == 'en0' and snap['sensor']['connected']
    assert {s['id'] for s in snap['sensors']} == {'simulator', 'en0'}
    assert all(s['connected'] for s in snap['sensors']) and snap['status']['level'] == 'calm'
    lp.episodes.add('DDoS', 'x', 'critical', '1.1.1.1', '2.2.2.2', rule=True)
    assert len(lp.snapshot()['episodes']) == 1
    lp.reset()
    assert lp.snapshot()['episodes'] == []


def test_simulator_ddos_batch_has_no_network():
    lib_path = ROOT / 'data' / 'sim_library.parquet'
    if not lib_path.exists():
        pytest.skip('no sim library')
    import socket
    import simulate

    calls = []
    orig = socket.socket.connect
    socket.socket.connect = lambda *a, **k: calls.append(a)
    try:
        sim = simulate.Simulator(simulate.load_library(), '192.168.1.10')
        flows = sim.batch('ddos', 'low')
        scan = sim.batch('portscan', 'low')
        ins = sim.batch('insider', 'low')
    finally:
        socket.socket.connect = orig
    assert not calls and len(flows) == 40
    ok = [ipaddress.ip_network(n) for n in ('198.51.100.0/24', '203.0.113.0/24', '10.66.0.0/16')]
    srcs = {f['Src IP'] for f in flows}
    assert len(srcs) > 1 and all(any(ipaddress.ip_address(s) in n for n in ok) for s in srcs)
    assert all(f['Dst IP'] == '192.168.1.10' and f['Dst Port'] in (80, 443) and f['Protocol'] == 6 for f in flows)
    assert all(f['Destination Port'] == f['Dst Port'] and 'Flow Duration' in f and f['Timestamp'] for f in flows)
    assert len({f['Dst Port'] for f in scan}) == len(scan) and len({f['Src IP'] for f in scan}) == 1
    assert any(f['Dst IP'] == '192.168.1.50' and f['Dst Port'] == 5432 for f in ins)
    assert simulate.SENSOR['mode'] == 'sim'


def test_novel_alerts_join_the_open_incident_on_their_target():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('suggest'), clock=clk)
    feed(tr, clk, 3, 20)                                            # DDoS on 192.168.1.10
    for i in range(10):                                             # same bots, seen as "Novel" by the anomaly path
        tr.add('Novel', 'Unknown anomalous behaviour', 'critical', '192.168.1.10', f'203.0.113.{i + 1}')
    ep = only(tr)
    assert ep['family'] == 'DDoS' and ep['sources'] >= 30


def test_named_alert_from_a_known_source_joins_its_incident():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('suggest'), clock=clk)
    for _ in range(3):
        tr.add('BruteForce', 'Credential brute force', 'critical', '10.0.0.5', '198.51.100.7', rule=True)
    for _ in range(3):  # the classifier calls a few of the same attacker's flows WebAttack
        tr.add('WebAttack', 'Web application attack', 'high', '10.0.0.5', '198.51.100.7')
    assert only(tr)['family'] == 'BruteForce'
    for _ in range(3):  # a different source on the same target is a separate incident
        tr.add('WebAttack', 'Web application attack', 'high', '10.0.0.5', '203.0.113.50')
    assert len(tr.snapshot()['episodes']) == 2


def test_scattered_false_positives_do_not_open_an_incident():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('suggest'), clock=clk)
    for _ in range(6):  # one stray model alert every 20 s on the same target
        tr.add('WebAttack', 'Web application attack', 'high', '192.168.1.5', '192.168.1.20')
        clk.t += 20
    assert tr.snapshot()['episodes'] == []
    for _ in range(3):  # three within a few seconds do
        tr.add('WebAttack', 'Web application attack', 'high', '192.168.1.5', '192.168.1.20')
        clk.t += 1
    assert len(tr.snapshot()['episodes']) == 1


def test_novel_incident_is_upgraded_when_the_attack_is_named():
    clk = Clock()
    tr = EpisodeTracker(FakeResponse('suggest'), clock=clk)
    for i in range(5):  # first flows: only the anomaly path fires
        tr.add('Novel', 'Unknown anomalous behaviour', 'critical', '192.168.1.10', f'203.0.113.{i + 1}')
    feed(tr, clk, 2, 30)  # then the DDoS rule names it (different bots)
    ep = only(tr)
    assert ep['family'] == 'DDoS'
    assert any(a['kind'] == 'identified' for a in ep['actions'])
