"""Live pipeline: sensor flow batches in, console-ready state out (docs/LIVE_SPEC.md s2)."""
import threading
import time
from collections import deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from engine.frontend import flow_records
from engine.report import normalise_flows

from .episodes import EpisodeTracker
from .profiles import HostProfiles, service_class

RING = 5000
INSIDER_KEEP = 200
PAGE = 500
TIMELINE_SECONDS = 300
MAX_EXPLAIN = 25
# Load shedding: during a flood the sensor can send tens of thousands of flows per second.
# At most this many per batch get full ML scoring; the rest only feed the cheap volume rules
# (flood / DDoS / fan-out) and the counters, so the server keeps up and floods are still caught.
MAX_SCORED = 500
CONNECTED_S = 5.0


def _iso(t=None):
    return datetime.fromtimestamp(t if t is not None else time.time(), timezone.utc).isoformat()


class LivePipeline:
    def __init__(self, engine, response=None, profiles=None):
        self.engine = engine
        self.response = response
        self.profiles = profiles if profiles is not None else HostProfiles()
        self.lock = threading.RLock()
        # Scoring runs under its own lock so /api/live polls are never blocked by a big batch.
        # Lock order is always score_lock -> lock.
        self.score_lock = threading.Lock()
        self.calibrated = False
        self.calibrated_at = None
        self.learning = self._fresh_learning()
        self._buf_X, self._buf_raw, self._buf_flows = [], [], []
        self.sensor = {'connected': False, 'id': None, 'iface': None, 'lastSeen': None, 'mode': None}
        self._last_seen = 0.0
        self.sensors = {}  # id -> {id, iface, mode, lastTs, flows}
        self.episodes = EpisodeTracker(response)
        self.reset()

    @staticmethod
    def _fresh_learning(target=3000):
        return {'active': False, 'startedAt': None, 'flows': 0, 'target': target,
                'calibrated': False, 'calibratedAt': None}

    # ------------------------------------------------------------------ state
    def reset(self):
        with self.lock:
            self.seq = getattr(self, 'seq', 0)  # seq stays monotonic so pollers never go backwards
            self.epoch = getattr(self, 'epoch', -1) + 1  # tells pollers to drop flows they cached before the reset
            self.flows = deque(maxlen=RING)
            self.insider = deque(maxlen=INSIDER_KEEP)
            self.hosts = {}
            self.total = {'flows': 0, 'alerts': 0}
            self.by_sev, self.by_family, self.by_verdict = {}, {}, {}
            self.timeline = {}
            self.episodes.reset()

    def _bump(self, d, k, n=1):
        d[k] = d.get(k, 0) + n

    # ------------------------------------------------------------------ ingest
    def ingest(self, payload):
        sensor = payload.get('sensor') or {}
        rows = payload.get('flows') or []
        with self.lock:
            now = time.time()
            sid = sensor.get('id') or 'sensor'
            s = self.sensors.setdefault(sid, {'id': sid, 'iface': None, 'mode': None, 'lastTs': 0.0, 'flows': 0})
            s.update({k: sensor.get(k) for k in ('iface', 'mode') if sensor.get(k) is not None})
            s['lastTs'] = now
            s['flows'] += len(rows)
            if not self._is_sim(s) or not any(not self._is_sim(x) for x in self.sensors.values()):
                # top-level sensor: the latest real sensor, or the simulator when it is the only one
                self._last_seen = now
                self.sensor.update({k: sensor.get(k) for k in ('id', 'iface', 'mode') if sensor.get(k) is not None})
                self.sensor['lastSeen'] = _iso(now)
            if not rows:
                return {'accepted': 0, 'alerts': 0, 'seq': self.seq}
            file = self.sensor.get('id') or 'sensor'
        shed = []
        if len(rows) > MAX_SCORED:
            keep = set(np.random.default_rng(len(rows)).choice(len(rows), MAX_SCORED, replace=False).tolist())
            shed = [r for i, r in enumerate(rows) if i not in keep]
            rows = [r for i, r in enumerate(rows) if i in keep]
        df = pd.DataFrame(rows)
        if 'Destination Port' not in df.columns:
            for alt in ('Dst Port', 'Dest Port'):
                if alt in df.columns:
                    df['Destination Port'] = df[alt]
                    break
        with self.score_lock:
            recs, X, raw = self._score(df, file)
            with self.lock:
                if self.learning['active']:
                    self._learn_collect(X, raw)
                alerts = 0
                for rec in recs:
                    alerts += self._record(rec, now)
                if shed:
                    self._observe_shed(shed, now)
                done = self.learning.pop('_ready', False)
                result = {'accepted': len(recs) + len(shed), 'scored': len(recs), 'shed': len(shed),
                          'alerts': alerts, 'seq': self.seq}
        self.episodes.flush()
        if done:  # learning reached its target: apply it straight away
            try:
                self.learn('apply')
            except ValueError as exc:
                with self.lock:
                    self.learning['error'] = str(exc)
        return result

    @staticmethod
    def _is_sim(s):
        return s.get('id') == 'simulator' or s.get('mode') == 'sim'

    def _episode_alert(self, a):
        """Feed an insider/volume alert into the episode tracker."""
        kind = a.get('kind')
        family = {'ddos': 'DDoS', 'flood': 'DoS'}.get(kind, 'Insider')
        target = a['src'] if kind == 'fan-out' else a['dst']
        self.episodes.add(family, a['title'] if family == 'Insider' else (
            'Distributed denial of service' if family == 'DDoS' else 'Denial of service'),
            a['severity'], target, a['src'], a.get('mitre'), rule=True)

    def _observe_shed(self, rows, now):
        """Flows not scored by the models: count them and run the volume rules on them."""
        def pick(r, *keys):
            for k in keys:
                if r.get(k) is not None:
                    return r[k]
            return None
        self.total['flows'] += len(rows)
        self.total['shed'] = self.total.get('shed', 0) + len(rows)
        t = self.timeline.setdefault(int(now), [0, 0])
        t[0] += len(rows)
        for r in rows:
            f = {'id': None, 'ts': pick(r, 'Timestamp'),
                 'src': {'ip': pick(r, 'Src IP', 'Source IP'), 'port': pick(r, 'Src Port', 'Source Port')},
                 'dst': {'ip': pick(r, 'Dst IP', 'Destination IP'), 'port': pick(r, 'Dst Port', 'Destination Port')}}
            for a in self.profiles.observe(f):
                self.insider.append(a)
                self._episode_alert(a)

    def _score(self, df, file):
        eng = self.engine
        feats, context, _, _ = normalise_flows(df)
        X = eng.preprocessor.transform(feats)[eng.features]
        raw = eng.model_scores(X)
        scored = eng.score(X, raw=raw)
        internals = {'X': X, 'raw_scores': raw, 'features': feats, 'context': context}
        alert_rows = np.flatnonzero((scored['verdict'] != 'normal').to_numpy())
        order = scored['risk_score'].to_numpy()[alert_rows].argsort()[::-1] if len(alert_rows) else []
        top = [int(r) for r in alert_rows[order][:MAX_EXPLAIN]] if len(alert_rows) else []
        top_set = set(top)
        rest = [r for r in range(len(scored)) if r not in top_set]
        by_row = {}
        for rows, explain in ((top, True), (rest, False)):
            if rows:
                for rec, r in zip(flow_records(eng, scored, internals, rows, 'live:', day='live', file=file,
                                               explain=explain), rows):
                    by_row[r] = rec
        return [by_row[r] for r in range(len(scored))], X, raw

    def _record(self, rec, now):
        self.seq += 1
        rec['seq'] = self.seq
        rec['id'] = f'live:{self.seq}'
        rec['day'] = 'live'
        rec['insider'] = []
        rec['response'] = None
        is_alert = rec['verdict'] != 'normal'
        for a in self.profiles.observe(rec):
            self.insider.append(a)
            rec['insider'].append(a['id'])
            self._episode_alert(a)
        if is_alert and self.response is not None:
            try:
                rec['response'] = self.response.evaluate(rec)
            except Exception as exc:
                rec['response'] = {'action': 'none', 'reason': f'response error: {exc}'}
        if is_alert:
            self.episodes.add(rec['family'] or 'Anomaly', rec['familyTitle'] or 'Anomalous traffic',
                              rec['severity'], rec['dst']['ip'], rec['src']['ip'], rec.get('mitre'))
        self.flows.append(rec)
        if self.learning['active'] and len(self._buf_flows) < self.learning['target']:
            self._buf_flows.append({'src': rec['src'], 'dst': rec['dst'], 'ts': rec['ts']})
        # stats
        self.total['flows'] += 1
        self._bump(self.by_verdict, rec['verdict'])
        sec = int(now)
        t = self.timeline.setdefault(sec, [0, 0])
        t[0] += 1
        if is_alert:
            self.total['alerts'] += 1
            self._bump(self.by_sev, rec['severity'])
            self._bump(self.by_family, rec['family'] or 'Unknown')
            t[1] += 1
        for k in [s for s in self.timeline if s < sec - TIMELINE_SECONDS]:
            del self.timeline[k]
        self._host(rec, is_alert)
        return int(is_alert)

    def _host(self, rec, is_alert):
        ip = rec['src']['ip']
        if not ip:
            return
        ts = rec['ts'] or _iso()
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = {'ip': ip, 'flows': 0, 'alerts': 0, 'maxRisk': 0, 'services': {},
                                  'peers': set(), 'firstSeen': ts, 'lastSeen': ts}
        h['flows'] += 1
        h['alerts'] += int(is_alert)
        h['maxRisk'] = max(h['maxRisk'], rec['risk'] or 0) if is_alert else h['maxRisk']
        self._bump(h['services'], service_class(rec['dst']['port']))
        if rec['dst']['ip'] and len(h['peers']) < 5000:
            h['peers'].add(rec['dst']['ip'])
        h['lastSeen'] = ts

    # ------------------------------------------------------------------ learning
    def _learn_collect(self, X, raw):
        room = self.learning['target'] - sum(len(x) for x in self._buf_X)
        if room <= 0:
            self.learning['active'] = False
            return
        take = X.iloc[:room]
        self._buf_X.append(take.reset_index(drop=True))
        self._buf_raw.append({k: np.asarray(v)[:len(take)] for k, v in raw.items()})
        self.learning['flows'] = sum(len(x) for x in self._buf_X)
        if self.learning['flows'] >= self.learning['target']:
            self.learning['active'] = False
            self.learning['_ready'] = True

    def learn(self, action, target=None):
        with self.score_lock, self.lock:
            if action == 'start':
                t = int(target or 3000)
                self.learning.update(self._fresh_learning(max(1, t)))
                self.learning.update(active=True, startedAt=_iso(), calibrated=self.calibrated,
                                     calibratedAt=self.calibrated_at)
                self._buf_X, self._buf_raw, self._buf_flows = [], [], []
            elif action == 'stop':
                self.learning['active'] = False
            elif action == 'apply':
                self.learning['active'] = False
                if not self._buf_X:
                    raise ValueError('no learning data collected: start learning first')
                X = pd.concat(self._buf_X, ignore_index=True)
                raw = {k: np.concatenate([r[k] for r in self._buf_raw]) for k in self._buf_raw[0]}
                self.engine.recalibrate(X, raw, log=lambda *_: None)
                self.profiles.learn_from(self._buf_flows)
                self.calibrated = True
                self.calibrated_at = _iso()
                self.learning.update(calibrated=True, calibratedAt=self.calibrated_at, error=None)
            else:
                raise ValueError(f'unknown action: {action!r}')
            return dict(self.learning)

    # ------------------------------------------------------------------ snapshot
    def snapshot(self, since=0):
        with self.lock:
            now = time.time()
            connected = self._last_seen > 0 and now - self._last_seen < CONNECTED_S
            sensors = [{'id': x['id'], 'iface': x['iface'], 'mode': x['mode'],
                        'connected': now - x['lastTs'] < CONNECTED_S, 'lastSeen': _iso(x['lastTs']),
                        'flows': x['flows']} for x in sorted(self.sensors.values(), key=lambda x: -x['lastTs'])]
            ep = self.episodes.snapshot()
            flows = []
            if self.flows:
                first = self.flows[0]['seq']
                start = max(0, int(since) + 1 - first)
                flows = [self.flows[i] for i in range(start, min(len(self.flows), start + PAGE))]
            blocks, rcfg, blocked = [], None, set()
            if self.response is not None:
                try:
                    blocks = self.response.blocks()
                    blocked = {b['ip'] for b in blocks}
                    rcfg = self.response.config()
                except Exception:
                    pass
            info = self.profiles.hosts_info()
            hosts = [{**{k: v for k, v in h.items() if k != 'peers'}, 'peers': len(h['peers']),
                      'role': info.get(h['ip'], {}).get('role') or self.profiles.role_of(h['ip']),
                      'blocked': h['ip'] in blocked} for h in self.hosts.values()]
            return {
                'seq': self.seq,
                'epoch': self.epoch,
                'sensor': {**self.sensor, 'connected': connected},
                'sensors': sensors,
                'status': ep['status'], 'episodes': ep['episodes'],
                'learning': dict(self.learning),
                'stats': {'flows': self.total['flows'], 'alerts': self.total['alerts'], 'shed': self.total.get('shed', 0),
                          'bySeverity': dict(self.by_sev), 'byFamily': dict(self.by_family),
                          'byVerdict': dict(self.by_verdict),
                          'timeline': [{'t': _iso(s), 'flows': v[0], 'alerts': v[1]}
                                       for s, v in sorted(self.timeline.items())]},
                'flows': flows, 'hosts': hosts, 'insider': list(self.insider),
                'blocks': blocks, 'response': rcfg,
            }
