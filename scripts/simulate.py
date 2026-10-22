#!/usr/bin/env python
"""MAVIS attack simulator: posts synthetic flow records to the LOCAL MAVIS API. Nothing else.

It never opens a socket to the target IPs and never sends packets anywhere. Attacker addresses come
from documentation ranges (198.51.100.0/24, 203.0.113.0/24) and 10.66.0.0/16. Feature values are
real CIC-IDS2017 rows from data/sim_library.parquet (build it with scripts/build_sim_library.py).

  .venv/bin/python scripts/simulate.py office --minutes 5
  .venv/bin/python scripts/simulate.py ddos --target 192.168.1.10 --intensity high --seconds 60
  .venv/bin/python scripts/simulate.py portscan|bruteforce|webattack|dos|botnet --target <ip>
  .venv/bin/python scripts/simulate.py insider --host 192.168.1.20 --db 192.168.1.50
  .venv/bin/python scripts/simulate.py story        # scripted ~3 minute demo
"""
import argparse
import http.client
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

SENSOR = {'id': 'simulator', 'iface': 'sim', 'mode': 'sim'}
FALLBACK_IP = '192.168.1.10'
LOCAL_HOSTS = ('127.0.0.1', 'localhost', '::1')
# flows per second, per intensity: low / medium / high
RATES = {'office': (10, 25, 60), 'ddos': (40, 200, 800), 'dos': (15, 50, 150), 'portscan': (30, 80, 200),
         'bruteforce': (5, 15, 40), 'webattack': (5, 15, 40), 'botnet': (1, 2, 4), 'insider': (2, 4, 8)}
DDOS_SOURCES = (60, 300, 1000)
FAMILY = {'office': 'Benign', 'insider': 'Benign', 'ddos': 'DDoS', 'dos': 'DoS', 'portscan': 'PortScan',
          'bruteforce': 'BruteForce', 'webattack': 'WebAttack', 'botnet': 'Bot'}
LEVEL = {'low': 0, 'medium': 1, 'high': 2}
OFFICE_PORTS = np.array([443, 443, 443, 80, 80, 53, 53, 465, 465, 123])  # ports with real benign rows in the library
BASELINE_AGE = timedelta(minutes=15)   # insider baseline is back-dated past the profile warm-up


def local_ip():
    """The Mac's primary IPv4, read from local config only (no packets are sent)."""
    try:
        out = subprocess.run(['ipconfig', 'getifaddr', 'en0'], capture_output=True, text=True, timeout=3).stdout.strip()
        if out:
            return out
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith('127.'):
            return ip
    except Exception:
        pass
    return FALLBACK_IP


def load_library(path=None):
    path = Path(path or ROOT / 'data' / 'sim_library.parquet')
    if not path.exists():
        sys.exit(f'{path} missing: run scripts/build_sim_library.py')
    lib = pd.read_parquet(path)
    return {fam: g.drop(columns='family').reset_index(drop=True) for fam, g in lib.groupby('family')}


def _attacker_ips(n, rng):
    """n distinct attacker IPs from the documentation ranges (then 10.66.0.0/16 if more are needed)."""
    pool = [f'198.51.100.{i}' for i in range(1, 255)] + [f'203.0.113.{i}' for i in range(1, 255)]
    if n > len(pool):
        pool += [f'10.66.{i // 250}.{i % 250 + 1}' for i in range(n - len(pool))]
    idx = rng.permutation(len(pool))[:n]
    return [pool[i] for i in idx]


class Simulator:
    def __init__(self, library, target, host='192.168.1.20', db='192.168.1.50', seed=42):
        self.lib, self.target, self.host, self.db = library, target, host, db
        self.rng = np.random.default_rng(seed)
        self.office_hosts = [f'192.168.1.{i}' for i in range(101, 113)]
        self.sources = {}          # scenario -> attacker ips (stable during one run)
        self.scan_port = 0
        self.baseline_sent = False

    def _rows(self, family, n):
        g = self.lib[family]
        return g.iloc[self.rng.integers(0, len(g), n)].reset_index(drop=True)

    def _benign_rows(self, dport):
        """Benign library rows that really used the requested port. Stamping another port onto a benign
        flow changes a model feature and made calm traffic raise false alerts. When no row used that
        port (e.g. the insider's database port 5432), the port is kept: the scenario needs it."""
        g = self.lib['Benign']
        if not hasattr(self, '_by_port'):
            self._by_port = g.groupby(g['Destination Port'].astype(int)).indices
        idx, ports = [], []
        for p in dport:
            rows = self._by_port.get(int(p))
            if rows is not None and len(rows):
                idx.append(int(self.rng.choice(rows)))
            else:
                idx.append(int(self.rng.integers(0, len(g))))
            ports.append(int(p))
        return g.iloc[idx].reset_index(drop=True), ports

    def _flows(self, family, src, dst, sport, dport, ts):
        n = len(src)
        if family == 'Benign':
            df, dport = self._benign_rows(dport)
        else:
            df = self._rows(family, n)
        df['Destination Port'] = np.asarray(dport, dtype=np.float32)
        recs = df.to_dict('records')
        ts = ts if isinstance(ts, list) else [ts] * n
        for r, s, d, sp, dp, t in zip(recs, src, dst, sport, dport, ts):
            r.update({'Src IP': s, 'Dst IP': d, 'Src Port': int(sp), 'Dst Port': int(dp), 'Protocol': 6,
                      'Timestamp': t})
        return recs

    def _srcs(self, key, n):
        if key not in self.sources:
            self.sources[key] = _attacker_ips(n, self.rng)
        return self.sources[key]

    def batch(self, scenario, intensity='medium', n=None):
        """One second of flow records for a scenario (pure: no network)."""
        lvl = LEVEL[intensity]
        n = n if n is not None else RATES[scenario][lvl]
        now = datetime.now(timezone.utc).isoformat()
        rng, t = self.rng, self.target
        eph = lambda k: rng.integers(32768, 61000, k)  # noqa: E731
        fam = FAMILY[scenario]
        if scenario == 'office':
            src = rng.choice(self.office_hosts, n)
            port = rng.choice(OFFICE_PORTS, n)
            dst = ['192.168.1.5' if p == 53 else '192.168.1.6' if p in (25, 587, 993)
                   else f'198.51.100.{rng.integers(100, 140)}' for p in port]
            return self._flows(fam, list(src), dst, eph(n), port, now)
        if scenario == 'ddos':
            srcs = self._srcs(('ddos', intensity), DDOS_SOURCES[lvl])
            return self._flows(fam, list(rng.choice(srcs, n)), [t] * n, eph(n), rng.choice([80, 443], n), now)
        if scenario == 'dos':
            srcs = self._srcs('dos', int(rng.integers(1, 4)))
            return self._flows(fam, list(rng.choice(srcs, n)), [t] * n, eph(n), rng.choice([80, 443], n), now)
        if scenario == 'portscan':
            src = self._srcs('portscan', 1)[0]
            ports = (self.scan_port + np.arange(n)) % 1024 + 1
            self.scan_port = int((self.scan_port + n) % 1024)
            return self._flows(fam, [src] * n, [t] * n, [40000] * n, ports, now)
        if scenario == 'bruteforce':
            srcs = self._srcs('bruteforce', int(rng.integers(1, 4)))
            return self._flows(fam, list(rng.choice(srcs, n)), [t] * n, eph(n), [rng.choice([22, 22, 21]) for _ in range(n)], now)
        if scenario == 'webattack':
            srcs = self._srcs('webattack', int(rng.integers(1, 3)))
            return self._flows(fam, list(rng.choice(srcs, n)), [t] * n, eph(n), rng.choice([80, 443], n), now)
        if scenario == 'botnet':
            return self._flows(fam, [self.office_hosts[3]] * n, ['203.0.113.50'] * n, eph(n), [8080] * n, now)
        if scenario == 'insider':
            out = []
            if not self.baseline_sent:   # normal web + mail history for the host, back-dated past warm-up
                self.baseline_sent = True
                base = datetime.now(timezone.utc) - BASELINE_AGE
                m = 40
                ts = [(base + timedelta(seconds=float(s))).isoformat() for s in np.sort(rng.uniform(0, 240, m))]
                port = rng.choice([443, 443, 80, 25, 587], m)
                dst = ['198.51.100.120' if p in (443, 80) else '192.168.1.6' for p in port]
                out += self._flows('Benign', [self.host] * m, dst, eph(m), port, ts)
            out += self._flows(fam, [self.host] * n, [self.db] * n, eph(n), [5432] * n, now)
            return out
        raise ValueError(f'unknown scenario: {scenario}')


class Poster:
    def __init__(self, api):
        u = urlparse(api if '//' in api else 'http://' + api)
        if u.hostname not in LOCAL_HOSTS:
            sys.exit(f'refusing --api {api}: the simulator only posts to the local MAVIS API (127.0.0.1)')
        self.host, self.port = u.hostname, u.port or 80
        self.conn = None

    def post(self, flows):
        body = json.dumps({'sensor': SENSOR, 'flows': flows}, default=float)
        for attempt in (0, 1):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
                self.conn.request('POST', '/api/ingest', body, {'Content-Type': 'application/json'})
                r = self.conn.getresponse()
                data = r.read()
                if r.status >= 300:
                    raise OSError(f'MAVIS API answered HTTP {r.status}: {data[:200]!r}')
                return json.loads(data)
            except (OSError, http.client.HTTPException):
                self.conn = None
                if attempt:
                    raise


def run_phase(sim, poster, scenario, seconds, intensity, label=None, background=0, quiet=False):
    """Send one batch per second for `seconds`. Returns the number of flows sent."""
    sent, t0 = 0, time.time()
    for i in range(int(seconds)):
        flows = sim.batch(scenario, intensity)
        if background and scenario != 'office':
            flows += sim.batch('office', n=background)
        res = poster.post(flows) if poster else {}
        sent += len(flows)
        if not quiet:
            print(f'[{i + 1:>3}s] {label or scenario:<10} sent={len(flows):<5} accepted={res.get("accepted", "-")} '
                  f'alerts={res.get("alerts", "-")}', flush=True)
        wait = t0 + i + 1 - time.time()
        if wait > 0:
            time.sleep(wait)
    return sent


STORY = [
    ('office', 30, 'medium', 'Calm: normal office traffic.'),
    ('portscan', 20, 'medium', 'A scanner at 198.51.100.x is probing ports on the target.'),
    ('bruteforce', 20, 'medium', 'Someone is guessing SSH passwords against the target.'),
    ('office', 15, 'medium', 'Calm again: normal office traffic.'),
    ('ddos', 40, 'high', 'A distributed flood is hitting the web service from about 1,000 sources.'),
    ('office', 20, 'medium', 'Calm: the flood stopped; watch the incident move to contained and resolved.'),
    ('insider', 15, 'medium', 'An internal workstation reaches a database it never used before.'),
]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('scenario', choices=sorted(RATES) + ['story'])
    p.add_argument('--target', default=None, help='victim IP (default: this Mac primary IPv4)')
    p.add_argument('--host', default='192.168.1.20', help='insider: the internal workstation')
    p.add_argument('--db', default='192.168.1.50', help='insider: the database server')
    p.add_argument('--intensity', choices=list(LEVEL), default='medium')
    p.add_argument('--seconds', type=int, default=None)
    p.add_argument('--minutes', type=float, default=None)
    p.add_argument('--api', default='http://127.0.0.1:8000')
    a = p.parse_args()
    target = a.target or local_ip()
    poster = Poster(a.api)
    sim = Simulator(load_library(), target, a.host, a.db)
    print(f'simulator -> {a.api} (flow records only, no packets)  target={target}', flush=True)
    try:
        if a.scenario == 'story':
            for scenario, secs, inten, text in STORY:
                print(f'\n== {text} ({secs}s)', flush=True)
                run_phase(sim, poster, scenario, secs, inten, background=5)
            print('\nstory finished', flush=True)
            return
        secs = a.seconds or (int(a.minutes * 60) if a.minutes else (300 if a.scenario == 'office' else 30))
        run_phase(sim, poster, a.scenario, secs, a.intensity)
    except KeyboardInterrupt:
        print('\nstopped')
    except OSError as exc:
        sys.exit(f'cannot reach the MAVIS API at {a.api}: {exc}. Start it with scripts/serve.py')


if __name__ == '__main__':
    main()
