"""Attack episodes: alerts grouped by (family, target) with a response lifecycle (docs/DEMO_SPEC.md s2).

active -> contained -> resolved. Cheap per alert (dict lookups, per-second counters); the clock is
injectable for tests. Auto-response goes through ResponseManager (dry-run backend by default).
"""
import heapq
import threading
import time
from collections import deque
from datetime import datetime, timezone

SEV = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
ACTIVE_S = 15.0       # an alert in the last 15 s keeps an episode active
RESOLVE_S = 30.0      # no alert for 30 s -> resolved
CONTAIN_RATIO = 0.2   # contained when the alert rate fell below 20 % of its peak
RATE_S = 10           # window for flowsPerSec and peak
STATUS_S = 5          # window for alertsPerSec in the threat status
ALERT_STATUS_RATE = 20
KEEP_RESOLVED = 50
MIN_ALERTS = 3        # an ML flow alert alone is not an episode: needs 3 (rule alerts count at once)
MAX_SOURCES = 5000
MAX_BLOCK = 10
UPSTREAM_SOURCES = 20


def _iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


class _Episode:
    def __init__(self, eid, key, family, title, severity, target, mitre, now):
        self.id, self.key, self.family, self.title = eid, key, family, title
        self.severity, self.target, self.mitre = severity, target, mitre or []
        self.state = 'active'
        self.first = self.last = self.since = now
        self.flows = 0
        self.src = {}                 # ip -> alert count (capped)
        self.per_sec = {}             # int(second) -> alerts
        self.peak = 0                 # max alerts in any RATE_S window seen
        self.actions = []
        self.blocked = set()
        self.responded_sev = 0
        self.responded_sources = 0
        self.upstream = False
        self.isolated = False
        self.by = None
        self.dirty = True
        self.rule = False

    def rate(self, now, window=RATE_S):
        t = int(now)
        return sum(v for s, v in self.per_sec.items() if t - window < s <= t)


class EpisodeTracker:
    def __init__(self, response=None, clock=time.time):
        self.response = response
        self.clock = clock
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.counter = getattr(self, 'counter', 0)
            self.open = {}          # key -> episode (active or contained)
            self.done = deque(maxlen=KEEP_RESOLVED)
            self.all = {}           # id -> episode (open + kept resolved)
            self.alert_sec = {}     # int(second) -> alerts, for the threat status
            self.level, self.level_since = 'calm', self.clock()

    # ------------------------------------------------------------------ input
    def add(self, family, title, severity, target, source, mitre=None, n=1, rule=False):
        """Record n alerts of one family against a target. Returns the episode.

        rule=True marks a volume / host-profile rule alert (confirmed at once); model alerts need MIN_ALERTS."""
        family = family or 'Anomaly'
        sev = severity if severity in SEV else 'low'
        key = (family, target)
        with self.lock:
            now = self.clock()
            sec = int(now)
            self.alert_sec[sec] = self.alert_sec.get(sec, 0) + n
            ep = self.open.get(key)
            if ep is None:
                self.counter += 1
                ep = _Episode(f'ep-{self.counter}', key, family, title, sev, target, mitre, now)
                self.open[key] = ep
                self.all[ep.id] = ep
            ep.last = now
            ep.rule = ep.rule or rule
            ep.flows += n
            ep.per_sec[sec] = ep.per_sec.get(sec, 0) + n
            if source and (source in ep.src or len(ep.src) < MAX_SOURCES):
                ep.src[source] = ep.src.get(source, 0) + n
            if SEV[sev] > SEV[ep.severity]:
                ep.severity = sev
            if len(ep.per_sec) > RATE_S + 2:
                for s in [s for s in ep.per_sec if s <= sec - RATE_S - 1]:
                    del ep.per_sec[s]
            ep.peak = max(ep.peak, ep.rate(now))
            ep.dirty = True
            self._update(ep, now)
            return ep

    # ------------------------------------------------------------------ response
    def _mode(self):
        try:
            return self.response.config().get('mode', 'suggest')
        except Exception:
            return 'suggest'

    def _act(self, ep, now, kind, detail, status='executed', backend=None, ips=None):
        a = {'ts': _iso(now), 'kind': kind, 'detail': detail, 'status': status, 'backend': backend}
        if ips:
            a['ips'] = ips
            a['ip'] = ips[0]
        ep.actions.append(a)

    @staticmethod
    def _confirmed(ep):
        return ep.rule or ep.flows >= MIN_ALERTS

    def _respond(self, ep, now):
        """Respond when an episode opens, escalates, or has gathered many more sources."""
        if not self._confirmed(ep):
            ep.dirty = True
            return
        sev = SEV[ep.severity]
        nsrc = len(ep.src)
        new_sev = sev > ep.responded_sev
        more_src = sev >= SEV['high'] and nsrc >= max(2, 2 * ep.responded_sources) and nsrc > ep.responded_sources
        upstream_due = (ep.family in ('DDoS', 'DoS') and sev >= SEV['critical'] and nsrc > UPSTREAM_SOURCES
                        and not ep.upstream)
        if not (new_sev or more_src or upstream_due):
            return
        ep.responded_sev = max(ep.responded_sev, sev)
        ep.responded_sources = max(ep.responded_sources, nsrc)
        auto = self._mode() == 'auto'
        status = 'executed' if auto else 'recommended'
        label = ep.title or ep.family
        backend = None
        cfg = {}
        if self.response is not None:
            try:
                cfg = self.response.config()
                backend = cfg.get('backend')
            except Exception:
                pass
        if new_sev:
            if sev <= SEV['low']:
                self._act(ep, now, 'logged', f'{label} on {ep.target} written to the incident log', 'executed')
            elif sev == SEV['medium']:
                hook = (cfg.get('notify') or {}).get('slackWebhook')
                if hook and auto and self.response is not None:
                    try:
                        self.response._tell(f'MAVIS: {label} on {ep.target} (medium)')
                        self._act(ep, now, 'notified', 'Slack notification sent', 'executed')
                    except Exception:
                        self._act(ep, now, 'notified', 'Slack notification failed; recorded in console', 'executed')
                else:
                    self._act(ep, now, 'notified', 'Analyst notified in the console'
                              + (' (Slack would be used if configured)' if not hook else ''), 'executed')
        if sev >= SEV['high'] and (new_sev or more_src):
            self._block(ep, now, auto, status, backend)
        if sev >= SEV['critical']:
            if upstream_due:
                ep.upstream = True
                self._act(ep, now, 'upstream-protection',
                          f'Simulated: Cloudflare Under Attack mode would be enabled for {ep.target} '
                          f'({nsrc} sources)', 'recommended' if not auto else 'simulated', backend)
            elif ep.family in ('Insider', 'Infiltration') and not ep.isolated:
                ep.isolated = True
                host = next(iter(ep.src), ep.target)
                self._act(ep, now, 'isolated', f'Simulated: host {host} quarantined from the network',
                          'recommended' if not auto else 'simulated', backend, [host] if host else None)

    def _block(self, ep, now, auto, status, backend):
        top = [ip for ip, _ in heapq.nlargest(MAX_BLOCK * 2, ep.src.items(), key=lambda kv: kv[1])
               if ip not in ep.blocked][:max(0, MAX_BLOCK - len(ep.blocked))]
        if not top:
            return
        done, refused = [], 0
        for ip in top:
            if not auto or self.response is None:
                done.append(ip)
                continue
            try:
                b = self.response.block(ip, f'{ep.family} episode {ep.id} on {ep.target}', source='episode')
            except Exception:
                refused += 1
                continue
            if b.get('status') == 'active':
                done.append(ip)
            else:
                refused += 1
        if done:
            if auto:
                ep.blocked.update(done)
            verb = 'Blocked' if auto else 'Recommended: block'
            extra = f' ({refused} refused by safety rules)' if refused else ''
            self._act(ep, now, 'blocked', f'{verb} {len(done)} source{"s" if len(done) != 1 else ""}{extra}',
                      status, backend, done)
        elif refused:
            last = ep.actions[-1] if ep.actions else None
            if last and last['status'] == 'refused' and last['kind'] == 'blocked':
                last['ts'] = _iso(now)  # one line, not one per retry
            else:
                self._act(ep, now, 'blocked', 'No source blocked: refused by safety rules or the block rate limit',
                          'refused', backend)

    # ------------------------------------------------------------------ lifecycle
    def _update(self, ep, now):
        if ep.state == 'resolved':
            return
        quiet = now - ep.last
        if quiet >= RESOLVE_S:
            new = 'resolved'
        else:
            peak = max(ep.peak, 1)
            rate = ep.rate(now)
            all_blocked = now - ep.first >= 3 and bool(ep.src) and len(ep.blocked) >= min(len(ep.src), MAX_BLOCK) and \
                len(ep.src) <= MAX_BLOCK and all(ip in ep.blocked for ip in ep.src)
            fell = bool(ep.actions) and quiet >= 3 and rate < CONTAIN_RATIO * peak
            if all_blocked or fell or (quiet >= ACTIVE_S and ep.actions):
                new = 'contained'
            else:
                new = 'active'
        if new != ep.state:
            ep.state, ep.since = new, now
            if new == 'resolved':
                self.open.pop(ep.key, None)
                self.done.append(ep)
                if len(self.all) > KEEP_RESOLVED * 2:
                    keep = {e.id for e in self.done} | {e.id for e in self.open.values()}
                    self.all = {k: v for k, v in self.all.items() if k in keep}

    def flush(self):
        """Run the automatic response for episodes that changed (once per batch, so it sees all new sources)."""
        with self.lock:
            now = self.clock()
            for ep in self.open.values():
                if ep.dirty:
                    ep.dirty = False
                    self._respond(ep, now)

    def tick(self):
        self.flush()
        with self.lock:
            now = self.clock()
            for ep in list(self.open.values()):
                self._update(ep, now)
            for s in [s for s in self.alert_sec if s < int(now) - 60]:
                del self.alert_sec[s]

    def resolve(self, eid):
        with self.lock:
            ep = self.all.get(eid)
            if ep is None:
                raise KeyError(f'unknown episode: {eid}')
            if ep.state != 'resolved':
                now = self.clock()
                ep.state, ep.since, ep.by = 'resolved', now, 'analyst'
                self.open.pop(ep.key, None)
                self.done.append(ep)
                self._act(ep, now, 'resolved', 'Marked resolved by the analyst', 'executed')
            return self._view(ep, self.clock())

    # ------------------------------------------------------------------ output
    def _view(self, ep, now):
        top = [ip for ip, _ in heapq.nlargest(10, ep.src.items(), key=lambda kv: kv[1])]
        return {'id': ep.id, 'family': ep.family, 'title': ep.title, 'severity': ep.severity, 'state': ep.state,
                'target': ep.target, 'sources': len(ep.src), 'topSources': top, 'flows': ep.flows,
                'flowsPerSec': round(ep.rate(now) / RATE_S, 1), 'firstSeen': _iso(ep.first),
                'lastSeen': _iso(ep.last), 'stateSince': _iso(ep.since), 'mitre': ep.mitre,
                'actions': list(ep.actions), 'blocked': sorted(ep.blocked), 'resolvedBy': ep.by}

    def status(self):
        with self.lock:
            now = self.clock()
            t = int(now)
            aps = sum(v for s, v in self.alert_sec.items() if t - STATUS_S < s <= t) / STATUS_S
            active = [e for e in self.open.values() if e.state == 'active' and self._confirmed(e)]
            crit = [e for e in active if e.severity == 'critical']
            hi = [e for e in active if SEV[e.severity] >= SEV['medium']]
            if crit or aps >= ALERT_STATUS_RATE:
                level = 'under-attack'
            elif hi:
                level = 'elevated'
            else:
                level = 'calm'
            if level != self.level:
                self.level, self.level_since = level, now
            pool = crit or hi or active
            lead = max(pool, key=lambda e: (SEV[e.severity], e.flows)) if pool else None
            if level == 'calm' or lead is None:
                headline = 'No active threats' if level == 'calm' else f'{aps:.0f} alerts per second'
            else:
                headline = f'{lead.title or lead.family} on {lead.target}'
                if len(lead.src) > 1:
                    headline += f' from {len(lead.src)} sources'
                headline += f', {lead.rate(now) / RATE_S:.0f} flows/s'
            return {'level': level, 'since': _iso(self.level_since), 'headline': headline,
                    'activeEpisodes': len(active), 'alertsPerSec': round(aps, 1)}

    def snapshot(self):
        with self.lock:
            self.tick()
            now = self.clock()
            order = {'active': 0, 'contained': 1, 'resolved': 2}
            eps = [e for e in self.open.values() if self._confirmed(e)] + list(self.done)
            eps.sort(key=lambda e: (order[e.state], -e.last))
            return {'status': self.status(), 'episodes': [self._view(e, now) for e in eps]}
