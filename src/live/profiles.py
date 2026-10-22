"""Host profiles: per-host service baselines for insider / lateral-movement alerts (docs/LIVE_SPEC.md s3)."""
import ipaddress
import json
import threading
from functools import lru_cache
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

SERVICE_PORTS = {
    'web': (80, 443, 8080, 8443), 'dns': (53,), 'mail': (25, 465, 587, 110, 143, 993, 995),
    'db': (1433, 1521, 3306, 5432, 6379, 9200, 27017), 'admin': (22, 23, 3389, 5900, 5985, 5986),
    'file': (21, 139, 445, 2049), 'directory': (88, 389, 636, 3268),
}
PORT_CLASS = {p: s for s, ps in SERVICE_PORTS.items() for p in ps}
SENSITIVE = ('db', 'admin', 'file', 'directory')
LABEL = {'db': 'a database service', 'admin': 'a remote-administration service', 'file': 'a file-sharing service',
         'directory': 'a directory service', 'web': 'web services', 'mail': 'mail services',
         'dns': 'DNS', 'other': 'an uncommon service'}
MITRE = {
    'new-service': [{'tactic': 'TA0008 Lateral Movement', 'technique': 'T1021 Remote Services'}],
    'role-violation': [{'tactic': 'TA0008 Lateral Movement', 'technique': 'T1021 Remote Services'},
                       {'tactic': 'TA0004 Privilege Escalation', 'technique': 'T1078 Valid Accounts'}],
    'new-internal-peer': [{'tactic': 'TA0007 Discovery', 'technique': 'T1018 Remote System Discovery'}],
    'fan-out': [{'tactic': 'TA0007 Discovery', 'technique': 'T1046 Network Service Discovery'},
                {'tactic': 'TA0008 Lateral Movement', 'technique': 'T1021 Remote Services'}],
    'flood': [{'tactic': 'TA0040 Impact', 'technique': 'T1499 Endpoint Denial of Service'}],
    'ddos': [{'tactic': 'TA0040 Impact', 'technique': 'T1498 Network Denial of Service'}],
}
ACTIONS = {
    'new-service': ['Confirm with the host owner that this access is expected.',
                    'Review the account and process behind the connection.',
                    'Restrict the service to the hosts that need it if unexpected.'],
    'role-violation': ['Verify the host is not compromised or misused.',
                       'Check the connection against the host role policy.',
                       'Block or isolate the host if the access is not approved.'],
    'new-internal-peer': ['Check why this host contacted a sensitive internal system.',
                          'Review authentication logs on the destination.'],
    'fan-out': ['Isolate the host and investigate for scanning or lateral movement.',
                'Review recent logins and processes on the host.',
                'Reset credentials that were used from it.'],
    'flood': ['Rate-limit or block the source at the firewall / load balancer.',
              'Check the target service for exhausted connections or workers.',
              'If the source is internal, check it for malware or a misbehaving script.'],
    'ddos': ['Enable upstream protection for the target (ISP scrubbing, Cloudflare Under Attack mode).',
             'Rate-limit the targeted service by request pattern rather than by single IP.',
             'Watch the target service health and inform the team.'],
}
WARMUP = timedelta(minutes=10)
# Volume rules: per-flow models judge each connection alone, so a flood of ordinary-looking
# requests passes them. These count flows per short window instead.
RATE_WINDOW = timedelta(seconds=10)
FLOOD_MIN = 100          # one source -> one dst:port, flows per 10 s (raised to 4x the learned peak)
DDOS_SOURCES = 20        # distinct sources hitting one dst:port within 10 s ...
DDOS_FLOWS = 200         # ... with at least this many flows in total
FAN_WINDOW = timedelta(seconds=60)
DEDUPE = timedelta(minutes=10)


def service_class(port):
    try:
        return PORT_CLASS.get(int(port), 'other')
    except (TypeError, ValueError):
        return 'other'


_NETS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8')]


@lru_cache(maxsize=65536)
def is_internal(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in _NETS) or a.is_loopback


def parse_ts(v):
    if v is None:
        return datetime.now(timezone.utc)
    try:
        d = datetime.fromisoformat(str(v).replace('Z', '+00:00').replace(' ', 'T', 1))
    except ValueError:
        return datetime.now(timezone.utc)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class _Host:
    def __init__(self, ts):
        self.first = ts
        self.services = {}      # baseline class -> flow count
        self.peers = set()      # baseline internal sensitive peers
        self.seen = {}          # all observed class -> count (warm period + after)
        self.flows = 0
        self.learned = False
        self.recent = deque()   # (ts, dst, port, dst_is_internal) for fan-out
        self.peer_count = {}    # internal dst -> flows in the fan-out window
        self.port_count = {}    # dst port -> flows in the fan-out window
        self.peak_rate = 0      # learned: most flows to one dst:port in any 10 s window


class HostProfiles:
    def __init__(self, roles_path='config/roles.json'):
        self.roles_path = Path(roles_path)
        self.lock = threading.RLock()
        self.hosts = {}
        self.counter = 0
        self.last_alert = {}
        self.learned = False
        self.roles = {'roles': {}, 'hosts': {}}
        self.pair_recent = {}   # (src, dst, port) -> deque[ts]   for floods
        self.dst_recent = {}    # (dst, port) -> deque[(ts, src)] for distributed floods
        self._pruned = 0
        self.load_roles()

    def load_roles(self):
        try:
            data = json.loads(self.roles_path.read_text())
            self.roles = {'roles': data.get('roles', {}), 'hosts': data.get('hosts', {})}
        except Exception:
            self.roles = {'roles': {}, 'hosts': {}}

    def role_of(self, ip):
        return self.roles['hosts'].get(ip)

    def _host(self, ip, ts):
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = _Host(ts)
        return h

    def reset_observed(self):
        """Forget what was observed since the baseline (first-time service use, scan/flood windows,
        alert de-duplication), keeping learned baselines. Lets a demo or test be replayed."""
        with self.lock:
            self.hosts = {ip: h for ip, h in self.hosts.items() if h.learned}
            for h in self.hosts.values():
                h.seen = {}
                h.recent.clear()
                h.peer_count.clear()
                h.port_count.clear()
            self.last_alert = {}
            self.pair_recent = {}
            self.dst_recent = {}

    def learn_from(self, flows):
        """Build baselines from flows (console flow objects or dicts with src/dst/ts)."""
        with self.lock:
            self.hosts = {}
            self.last_alert = {}
            for f in flows:
                src, dst = f['src']['ip'], f['dst']['ip']
                if not src:
                    continue
                h = self._host(src, parse_ts(f.get('ts')))
                c = service_class(f['dst'].get('port'))
                h.services[c] = h.services.get(c, 0) + 1
                h.flows += 1
                if c in SENSITIVE and is_internal(dst):
                    h.peers.add(dst)
            # learned peak rate per host, so busy-but-normal hosts don't trip the flood rule
            windows = {}
            for f in flows:
                if f['src']['ip']:
                    key = (f['src']['ip'], f['dst']['ip'], f['dst'].get('port'))
                    windows.setdefault(key, []).append(parse_ts(f.get('ts')))
            for (src, _, _), times in windows.items():
                times.sort()
                lo, best = 0, 0
                for hi, t in enumerate(times):
                    while t - times[lo] > RATE_WINDOW:
                        lo += 1
                    best = max(best, hi - lo + 1)
                h = self.hosts.get(src)
                if h is not None:
                    h.peak_rate = max(h.peak_rate, best)
            for h in self.hosts.values():
                h.learned = True
            self.learned = True

    def _alert(self, f, h, kind, service, severity, risk, title, detail, key=None):
        src, dst, port = f['src']['ip'], f['dst']['ip'], f['dst'].get('port')
        ts = parse_ts(f.get('ts'))
        key = key or (src, kind, service if kind != 'new-internal-peer' else dst)
        prev = self.last_alert.get(key)
        if prev and ts - prev < DEDUPE:
            return None
        self.last_alert[key] = ts
        self.counter += 1
        return {'id': f'ins-{self.counter}', 'ts': ts.isoformat(), 'src': src, 'dst': dst, 'dstPort': port,
                'kind': kind, 'service': service, 'severity': severity, 'risk': risk, 'title': title,
                'detail': detail, 'mitre': MITRE[kind], 'actions': ACTIONS[kind], 'flowId': f.get('id')}

    def _rate_alerts(self, f, src, dst, port, ts):
        """Flood (one source) and distributed flood (many sources) on one dst:port."""
        out = []
        pk = (src, dst, port)
        q = self.pair_recent.setdefault(pk, deque())
        q.append(ts)
        while q and ts - q[0] > RATE_WINDOW:
            q.popleft()
        h = self.hosts.get(src)
        limit = max(FLOOD_MIN, 4 * (h.peak_rate if h else 0))
        if len(q) >= limit:
            a = self._alert(f, h, 'flood', service_class(port), 'high', 80,
                            f'{src} sent {len(q)} connections to {dst}:{port} in 10 s',
                            f'Flood threshold for this source: {limit} flows per 10 s'
                            + (f' (4x its learned peak of {h.peak_rate}).' if h and h.peak_rate else '.'))
            if a:
                out.append(a)
        dk = (dst, port)
        dq = self.dst_recent.setdefault(dk, deque())
        dq.append((ts, src))
        while dq and ts - dq[0][0] > RATE_WINDOW:
            dq.popleft()
        if len(dq) >= DDOS_FLOWS:
            sources = {s for _, s in dq}
            if len(sources) >= DDOS_SOURCES:
                a = self._alert(f, h, 'ddos', service_class(port), 'critical', 92,
                                f'{dst}:{port} received {len(dq)} connections from {len(sources)} sources in 10 s',
                                'Many sources at once: a distributed flood. Blocking single IPs will not stop it.',
                                key=(dst, 'ddos', port))
                if a:
                    out.append(a)
        self._pruned += 1
        if self._pruned >= 5000:  # drop idle windows so memory stays bounded on long runs
            self._pruned = 0
            for d in (self.pair_recent, self.dst_recent):
                for k in [k for k, v in d.items() if not v or ts - (v[-1] if d is self.pair_recent else v[-1][0]) > RATE_WINDOW]:
                    del d[k]
        return out

    def observe(self, f):
        """Update the profile with one flow; return the insider alerts it triggers."""
        src, dst, port = f['src']['ip'], f['dst']['ip'], f['dst'].get('port')
        if not src:
            return []
        if not is_internal(src):
            with self.lock:
                return self._rate_alerts(f, src, dst, port, parse_ts(f.get('ts')))
        with self.lock:
            ts = parse_ts(f.get('ts'))
            h = self._host(src, ts)
            h.flows += 1
            c = service_class(port)
            out = []
            warming = not h.learned and ts - h.first < WARMUP
            out += self._rate_alerts(f, src, dst, port, ts)
            base = ', '.join(sorted(h.services, key=h.services.get, reverse=True)[:5]) or 'none'
            nbase = sum(h.services.values())
            detail_base = f'Baseline for this host: {base} ({nbase} flows).'

            # fan-out sliding window: never subject to warm-up. A host that is new to us and
            # immediately touches dozens of ports or hosts is exactly what a scanner looks like.
            # Counters are updated incrementally (O(1) per flow). Recomputing the distinct sets
            # over the whole window for every flow was O(n^2) and froze the server under a flood.
            internal_dst = is_internal(dst)
            h.recent.append((ts, dst, port, internal_dst))
            if internal_dst:
                h.peer_count[dst] = h.peer_count.get(dst, 0) + 1
            h.port_count[port] = h.port_count.get(port, 0) + 1
            while h.recent and ts - h.recent[0][0] > FAN_WINDOW:
                _, d0, p0, i0 = h.recent.popleft()
                if i0:
                    h.peer_count[d0] -= 1
                    if not h.peer_count[d0]:
                        del h.peer_count[d0]
                h.port_count[p0] -= 1
                if not h.port_count[p0]:
                    del h.port_count[p0]
            if h.recent:
                peers, ports = h.peer_count, h.port_count
                if len(peers) >= 20 or len(ports) >= 50:
                    a = self._alert(f, h, 'fan-out', 'other', 'high', 85,
                                    f'{src} contacted {len(peers)} internal hosts and {len(ports)} ports in 60 s',
                                    'Wide fan-out in a short window is typical of scanning or lateral movement.')
                    if a:
                        out.append(a)

            role = self.role_of(src)
            allowed = self.roles['roles'].get(role, {}).get('allow') if role else None
            role_hit = allowed is not None and c not in allowed
            if role_hit and not warming:
                a = self._alert(f, h, 'role-violation', c, 'high', 82,
                                f'{src} ({role}) used {LABEL[c]}, which its role does not allow',
                                f'Role {role} allows: {", ".join(allowed)}.')
                if a:
                    out.append(a)
            elif not warming and h.services and c not in h.services and c not in h.seen:
                sev = 'high' if c in SENSITIVE else 'medium'
                a = self._alert(f, h, 'new-service', c, sev, 78 if sev == 'high' else 50,
                                f'{src} used {LABEL[c]} for the first time', detail_base)
                if a:
                    out.append(a)
            if (not warming and c in ('db', 'admin', 'file') and is_internal(dst) and dst not in h.peers
                    and (h.services or h.learned) and not (out and out[-1]['kind'] in ('new-service', 'role-violation'))):
                a = self._alert(f, h, 'new-internal-peer', c, 'medium', 55,
                                f'{src} contacted internal host {dst} on {LABEL[c]} for the first time', detail_base)
                if a:
                    out.append(a)
            h.seen[c] = h.seen.get(c, 0) + 1
            if not h.learned and warming:
                h.services[c] = h.services.get(c, 0) + 1
            if c in SENSITIVE and is_internal(dst):
                h.peers.add(dst)
            return out

    def hosts_info(self):
        with self.lock:
            return {ip: {'role': self.role_of(ip), 'services': dict(h.seen), 'peers': len(h.peers)}
                    for ip, h in self.hosts.items()}
