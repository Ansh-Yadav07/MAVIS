import http.client
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from live.profiles import HostProfiles, service_class  # noqa: E402

ENGINE_DIR = ROOT / 'results' / 'engine'
needs_engine = pytest.mark.skipif(not (ENGINE_DIR / 'engine.joblib').exists(), reason='no trained engine')
T0 = datetime(2026, 10, 19, 22, 0, 0, tzinfo=timezone.utc)


def flow(src, dst, port, secs, fid=None):
    return {'id': fid or f'f{secs}', 'ts': (T0 + timedelta(seconds=secs)).isoformat(),
            'src': {'ip': src, 'port': 50000}, 'dst': {'ip': dst, 'port': port}}


def warm_profiles(tmp_path, roles=None):
    p = tmp_path / 'roles.json'
    if roles:
        p.write_text(json.dumps(roles))
    hp = HostProfiles(str(p))
    base = [flow('192.168.1.20', '10.0.0.5', pt, i) for i, pt in enumerate([443, 80, 25, 53] * 50)]
    hp.learn_from(base)
    return hp


def test_service_class():
    assert service_class(3306) == 'db' and service_class(445) == 'file' and service_class(12345) == 'other'


def test_new_service_db_after_baseline(tmp_path):
    hp = warm_profiles(tmp_path)
    assert hp.observe(flow('192.168.1.20', '10.0.0.9', 443, 1000)) == []
    a = hp.observe(flow('192.168.1.20', '192.168.1.50', 3306, 1001))
    kinds = {x['kind'] for x in a}
    assert 'new-service' in kinds
    ns = next(x for x in a if x['kind'] == 'new-service')
    assert ns['severity'] == 'high' and ns['service'] == 'db' and ns['id'].startswith('ins-')
    assert ns['mitre'] and ns['actions'] and ns['flowId'] == 'f1001'


def test_dedupe_and_new_internal_peer(tmp_path):
    hp = warm_profiles(tmp_path)
    assert hp.observe(flow('192.168.1.20', '192.168.1.50', 3306, 1000))
    assert hp.observe(flow('192.168.1.20', '192.168.1.50', 3306, 1100)) == []
    # after 10 minutes the same alert may fire again
    assert hp.observe(flow('192.168.1.20', '192.168.1.50', 3306, 1000 + 601)) == []  # seen already -> no new-service
    hp2 = warm_profiles(tmp_path)
    a = hp2.observe(flow('192.168.1.20', '192.168.1.60', 445, 1000))
    assert any(x['kind'] in ('new-service',) for x in a)


def test_role_violation(tmp_path):
    hp = warm_profiles(tmp_path, {'roles': {'mail-user': {'allow': ['mail', 'web', 'dns']}},
                                  'hosts': {'192.168.1.20': 'mail-user'}})
    assert hp.observe(flow('192.168.1.20', '10.0.0.5', 25, 1000)) == []
    a = hp.observe(flow('192.168.1.20', '10.0.0.5', 22, 1001))
    assert a and a[0]['kind'] == 'role-violation' and a[0]['severity'] == 'high'


def test_fan_out(tmp_path):
    hp = warm_profiles(tmp_path)
    out = []
    for i in range(25):
        out += hp.observe(flow('192.168.1.20', f'192.168.1.{100 + i}', 443, 2000 + i * 0.5))
    assert any(x['kind'] == 'fan-out' for x in out)
    assert len([x for x in out if x['kind'] == 'fan-out']) == 1  # deduped


def test_warming_up_suppresses(tmp_path):
    hp = HostProfiles(str(tmp_path / 'none.json'))
    out = []
    for i, port in enumerate([443, 443, 3306, 22]):
        out += hp.observe(flow('192.168.1.7', '192.168.1.50', port, i * 30))
    assert out == []
    # after the 10 minute warm-up a brand-new class alerts
    a = hp.observe(flow('192.168.1.7', '192.168.1.50', 5900 if False else 445, 700))
    assert a and a[0]['kind'] == 'new-service'


def test_external_source_ignored(tmp_path):
    hp = warm_profiles(tmp_path)
    assert hp.observe(flow('8.8.8.8', '192.168.1.5', 3306, 1000)) == []


# ---------------------------------------------------------------- pipeline (real engine)
@pytest.fixture(scope='module')
def engine():
    from engine import MavisEngine
    if not (ENGINE_DIR / 'engine.joblib').exists():
        pytest.skip('no trained engine')
    return MavisEngine.load(ENGINE_DIR)


TUESDAY = ROOT / 'dataset' / 'Tuesday-WorkingHours.pcap_ISCX.csv'


def make_rows(n, offset=0, skip=0):
    from data.cic import FEATURES
    if not TUESDAY.exists():
        pytest.skip('needs dataset/Tuesday-WorkingHours.pcap_ISCX.csv')
    df = pd.read_csv(TUESDAY, encoding='latin-1',
                     skiprows=range(1, skip + 1), nrows=n)
    df.columns = [c.strip() for c in df.columns]
    rows = []
    for i, (_, r) in enumerate(df.iterrows()):
        d = {f: (None if pd.isna(r[f]) or r[f] in (float('inf'), float('-inf')) else float(r[f]))
             for f in FEATURES if f in r}
        d.update({'Src IP': f'192.168.1.{10 + i % 5}', 'Dst IP': f'10.0.0.{1 + i % 7}', 'Src Port': 40000 + i,
                  'Dst Port': int(r['Destination Port']), 'Destination Port': int(r['Destination Port']),
                  'Protocol': 6, 'Timestamp': (T0 + timedelta(seconds=offset + i)).isoformat()})
        rows.append(d)
    return rows


@needs_engine
def test_pipeline_ingest_snapshot(engine, tmp_path):
    from live.pipeline import LivePipeline
    lp = LivePipeline(engine, profiles=HostProfiles(str(tmp_path / 'r.json')))
    assert lp.snapshot()['sensor']['connected'] is False
    t = time.time()
    res = lp.ingest({'sensor': {'id': 's1', 'iface': 'en0', 'mode': 'pcap'}, 'flows': make_rows(200)})
    elapsed = time.time() - t
    print('200-flow batch seconds:', round(elapsed, 3))
    assert elapsed < 3 and res['accepted'] == 200 and res['seq'] == 200
    lp.ingest({'sensor': {'id': 's1'}, 'flows': make_rows(50, 300, skip=200)})
    snap = lp.snapshot(0)
    assert snap['seq'] == 250 and snap['sensor']['connected'] and snap['sensor']['id'] == 's1'
    seqs = [f['seq'] for f in snap['flows']]
    assert seqs == list(range(1, 251)) and snap['flows'][0]['id'] == 'live:1'
    f0 = snap['flows'][0]
    assert f0['src']['ip'].startswith('192.168.1.') and f0['day'] == 'live' and f0['file'] == 's1'
    assert f0['proto'] == 'TCP' and f0['ts'].startswith('2026-10-19')
    assert [f['seq'] for f in lp.snapshot(240)['flows']] == list(range(241, 251))
    assert lp.snapshot(250)['flows'] == []
    st = snap['stats']
    assert st['flows'] == 250 and sum(st['byVerdict'].values()) == 250 and st['timeline']
    assert snap['hosts'] and all('maxRisk' in h for h in snap['hosts'])
    lp._last_seen -= 10
    assert lp.snapshot()['sensor']['connected'] is False
    lp.ingest({'sensor': {'id': 's1'}, 'flows': []})  # heartbeat
    assert lp.snapshot()['sensor']['connected'] is True and lp.snapshot()['seq'] == 250
    lp.reset()
    assert lp.snapshot()['flows'] == [] and lp.snapshot()['stats']['flows'] == 0
    lp.ingest({'sensor': {'id': 's1'}, 'flows': make_rows(5)})
    assert lp.snapshot()['seq'] == 255  # seq keeps increasing


@needs_engine
def test_learning_calls_recalibrate(engine, tmp_path, monkeypatch):
    from live.pipeline import LivePipeline
    calls = []
    monkeypatch.setattr(engine, 'recalibrate', lambda X, raw=None, **k: calls.append((len(X), sorted(raw))))
    lp = LivePipeline(engine, profiles=HostProfiles(str(tmp_path / 'r.json')))
    with pytest.raises(ValueError):
        lp.learn('apply')
    lp.learn('start', 120)
    lp.ingest({'sensor': {'id': 's'}, 'flows': make_rows(100)})
    assert lp.snapshot()['learning']['flows'] == 100 and lp.snapshot()['learning']['active']
    lp.ingest({'sensor': {'id': 's'}, 'flows': make_rows(100, 200)})
    L = lp.snapshot()['learning']
    assert L['flows'] == 120 and not L['active']
    lp.learn('apply')
    assert calls and calls[0][0] == 120
    L = lp.snapshot()['learning']
    assert L['calibrated'] and L['calibratedAt'] and lp.profiles.learned


# ---------------------------------------------------------------- HTTP smoke
@needs_engine
def test_http_smoke(engine, tmp_path):
    import serve
    serve.init_live(engine)
    srv = ThreadingHTTPServer(('127.0.0.1', 0), serve.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=None):
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=60)
        c.request(method, path, body=json.dumps(body) if body is not None else None,
                  headers={'Content-Type': 'application/json'})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    try:
        st, h = call('GET', '/api/health')
        assert st == 200 and h['live'] is True and 'response' in h
        st, r = call('POST', '/api/ingest', {'sensor': {'id': 'smoke', 'mode': 'pcap'}, 'flows': make_rows(50)})
        assert st == 200 and r['accepted'] == 50
        st, live = call('GET', '/api/live?since=0')
        assert st == 200 and len(live['flows']) == 50 and live['sensor']['connected']
        st, live2 = call('GET', f"/api/live?since={live['seq']}")
        assert live2['flows'] == []
        assert call('GET', '/api/live?since=x')[0] == 400
        assert call('POST', '/api/ingest', {'flows': 'nope'})[0] == 400
        st, _ = call('POST', '/api/live/learn', {'action': 'bogus'})
        assert st == 400
        st, _ = call('POST', '/api/live/reset')
        assert st == 200 and call('GET', '/api/live')[1]['flows'] == []
        st, b = call('GET', '/api/blocks')
        assert st in (200, 503)
    finally:
        srv.shutdown()


def test_flood_from_one_source(tmp_path):
    hp = warm_profiles(tmp_path)
    quiet = []
    for i in range(60):  # 60 flows in 10 s: busy, not a flood
        quiet += hp.observe(flow('192.168.1.20', '10.0.0.9', 8000, 3000 + i * 0.15))
    assert not any(x['kind'] == 'flood' for x in quiet)
    out = []
    for i in range(150):  # 150 flows in ~7 s to one dst:port
        out += hp.observe(flow('192.168.1.20', '10.0.0.9', 8000, 4000 + i * 0.05))
    floods = [x for x in out if x['kind'] == 'flood']
    assert len(floods) == 1 and floods[0]['severity'] == 'high'  # fires once, then deduped


def test_learned_peak_raises_flood_threshold(tmp_path):
    hp = HostProfiles(str(tmp_path / 'roles.json'))
    busy = [flow('192.168.1.30', '10.0.0.9', 8000, i * 0.05) for i in range(120)]  # normal for this host
    hp.learn_from(busy)
    out = []
    for i in range(150):
        out += hp.observe(flow('192.168.1.30', '10.0.0.9', 8000, 1000 + i * 0.05))
    assert not any(x['kind'] == 'flood' for x in out)  # limit is 4 x 120 = 480


def test_distributed_flood_from_external_sources(tmp_path):
    hp = warm_profiles(tmp_path)
    out = []
    for i in range(250):  # 25 internet sources, 10 flows each, within ~5 s
        out += hp.observe(flow(f'203.0.113.{i % 25 + 1}', '192.168.1.80', 443, 5000 + i * 0.02))
    ddos = [x for x in out if x['kind'] == 'ddos']
    assert len(ddos) == 1 and ddos[0]['severity'] == 'critical'
    assert not any(x['kind'] == 'flood' for x in out)  # no single source is flooding
