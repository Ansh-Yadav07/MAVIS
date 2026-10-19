"""CICFlowMeter-compatible bidirectional flow meter (pure python, scapy for parsing only).

Semantics follow CICFlowMeter (CIC-IDS2017) with these approximations:
- Header lengths are the transport header only (TCP data offset, 8 for UDP/ICMP), which is what
  the CIC CSVs show (e.g. 2 plain fwd TCP packets -> 40).
- Std/variance are sample statistics (n-1), like CIC's commons-math; 0 when n < 2.
- Rates with zero duration are output as 0 instead of inf.
- Bulk features are 0; Subflow features equal the flow totals (one subflow).
- A flow cut by the active timeout is continued by a new flow whose "forward" side is the
  direction of the next packet.
- FIN: the flow is finished once both directions sent FIN (plus a 1 s grace for the last ACK).
"""
import math
import time
from datetime import datetime, timezone

try:
    from data.cic import FEATURES
except ImportError:  # imported as src.sensor
    from src.data.cic import FEATURES

ACTIVITY_THRESHOLD_US = 5_000_000
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
CLOSE_GRACE = 1.0


def parse_packet(pkt):
    """scapy packet (or dict already in this shape) -> dict, or None if not TCP/UDP/ICMP."""
    if isinstance(pkt, dict):
        return pkt
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:   # raw-IP pcaps (LL type 228/229) come back as Raw
        raw = bytes(pkt)
        if not raw or raw[0] >> 4 not in (4, 6):
            return None
        t = pkt.time
        pkt = (IP if raw[0] >> 4 == 4 else IPv6)(raw)
        pkt.time = t
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    d = {'time': float(pkt.time), 'src': ip.src, 'dst': ip.dst, 'flags': 0, 'win': -1}
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        d.update(proto=6, sport=t.sport, dport=t.dport, flags=int(t.flags), win=t.window,
                 hdr=(t.dataofs or 5) * 4, payload=len(t.payload))
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        d.update(proto=17, sport=u.sport, dport=u.dport, hdr=8, payload=len(u.payload))
    elif pkt.haslayer(ICMP):
        d.update(proto=1, sport=0, dport=0, hdr=8, payload=len(pkt[ICMP].payload))
    else:
        return None
    return d


def _stats(v):
    """(mean, std, max, min) with sample std; zeros for empty input."""
    n = len(v)
    if not n:
        return 0.0, 0.0, 0.0, 0.0
    m = sum(v) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in v) / (n - 1)) if n > 1 else 0.0
    return m, sd, max(v), min(v)


class _Flow:
    def __init__(self, p):
        self.src, self.dst, self.sport, self.dport, self.proto = p['src'], p['dst'], p['sport'], p['dport'], p['proto']
        self.start = self.last = p['time']
        self.ts = [[], []]      # packet times per direction (0 fwd, 1 bwd)
        self.lens = [[], []]    # payload lengths
        self.hdr = [0, 0]
        self.min_fwd_hdr = None
        self.psh, self.urg = [0, 0], [0, 0]
        self.flags = {k: 0 for k in (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)}
        self.win = [-1, -1]
        self.fin_dir = set()
        self.closing = False
        self.rst = False
        self.act_data = 0
        self.all_ts = []
        self.active, self.idle = [], []
        self.act_start = p['time']

    def add(self, p, d):
        t = p['time']
        if self.all_ts:
            gap = (t - self.all_ts[-1]) * 1e6
            if gap > ACTIVITY_THRESHOLD_US:
                self.active.append((self.all_ts[-1] - self.act_start) * 1e6)
                self.idle.append(gap)
                self.act_start = t
        self.all_ts.append(t)
        self.last = max(self.last, t)
        self.ts[d].append(t)
        self.lens[d].append(p['payload'])
        self.hdr[d] += p['hdr']
        if d == 0:
            self.min_fwd_hdr = p['hdr'] if self.min_fwd_hdr is None else min(self.min_fwd_hdr, p['hdr'])
            if p['payload'] > 0:
                self.act_data += 1
        f = p['flags']
        for k in self.flags:
            if f & k:
                self.flags[k] += 1
        if f & PSH:
            self.psh[d] += 1
        if f & URG:
            self.urg[d] += 1
        if p['proto'] == 6 and self.win[d] == -1 and len(self.ts[d]) == 1:
            self.win[d] = p['win']
        if f & FIN:
            self.fin_dir.add(d)
            if len(self.fin_dir) == 2:
                self.closing = True
        if f & RST:
            self.rst = True

    def to_dict(self):
        fl, bl = self.lens
        allen = fl + bl
        dur = max((self.last - self.start) * 1e6, 0.0)
        sec = dur / 1e6
        rate = lambda x: x / sec if sec > 0 else 0.0
        iat = lambda ts: [(b - a) * 1e6 for a, b in zip(ts, ts[1:])]
        times = sorted(self.all_ts)
        flow_iat = iat(times)
        fi, bi = iat(self.ts[0]), iat(self.ts[1])
        active = self.active + [(self.last - self.act_start) * 1e6]
        fm, fs, fx, fn = _stats(fl)
        bm, bs, bx, bn = _stats(bl)
        am, asd, ax, an = _stats(allen)
        im, isd, ix, i_n = _stats(flow_iat)
        fim, fis, fix_, fin_ = _stats(fi)
        bim, bis, bix, bin_ = _stats(bi)
        acm, acs, acx, acn = _stats(active)
        idm, ids, idx, idn = _stats(self.idle)
        nf, nb = len(fl), len(bl)
        tf, tb = sum(fl), sum(bl)
        f = self.flags
        row = {
            'Destination Port': self.dport, 'Flow Duration': dur,
            'Total Fwd Packets': nf, 'Total Backward Packets': nb,
            'Total Length of Fwd Packets': tf, 'Total Length of Bwd Packets': tb,
            'Fwd Packet Length Max': fx, 'Fwd Packet Length Min': fn, 'Fwd Packet Length Mean': fm, 'Fwd Packet Length Std': fs,
            'Bwd Packet Length Max': bx, 'Bwd Packet Length Min': bn, 'Bwd Packet Length Mean': bm, 'Bwd Packet Length Std': bs,
            'Flow Bytes/s': rate(tf + tb), 'Flow Packets/s': rate(nf + nb),
            'Flow IAT Mean': im, 'Flow IAT Std': isd, 'Flow IAT Max': ix, 'Flow IAT Min': i_n,
            'Fwd IAT Total': sum(fi), 'Fwd IAT Mean': fim, 'Fwd IAT Std': fis, 'Fwd IAT Max': fix_, 'Fwd IAT Min': fin_,
            'Bwd IAT Total': sum(bi), 'Bwd IAT Mean': bim, 'Bwd IAT Std': bis, 'Bwd IAT Max': bix, 'Bwd IAT Min': bin_,
            'Fwd PSH Flags': self.psh[0], 'Bwd PSH Flags': self.psh[1],
            'Fwd URG Flags': self.urg[0], 'Bwd URG Flags': self.urg[1],
            'Fwd Header Length': self.hdr[0], 'Bwd Header Length': self.hdr[1],
            'Fwd Packets/s': rate(nf), 'Bwd Packets/s': rate(nb),
            'Min Packet Length': an, 'Max Packet Length': ax, 'Packet Length Mean': am,
            'Packet Length Std': asd, 'Packet Length Variance': asd ** 2,
            'FIN Flag Count': f[FIN], 'SYN Flag Count': f[SYN], 'RST Flag Count': f[RST], 'PSH Flag Count': f[PSH],
            'ACK Flag Count': f[ACK], 'URG Flag Count': f[URG], 'CWE Flag Count': f[CWR], 'ECE Flag Count': f[ECE],
            'Down/Up Ratio': int(nb / nf) if nf else 0,
            'Average Packet Size': (tf + tb) / (nf + nb) if nf + nb else 0.0,
            'Avg Fwd Segment Size': fm, 'Avg Bwd Segment Size': bm,
            'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': nf, 'Subflow Fwd Bytes': tf, 'Subflow Bwd Packets': nb, 'Subflow Bwd Bytes': tb,
            'Init_Win_bytes_forward': self.win[0], 'Init_Win_bytes_backward': self.win[1],
            'act_data_pkt_fwd': self.act_data, 'min_seg_size_forward': self.min_fwd_hdr or 0,
            'Active Mean': acm, 'Active Std': acs, 'Active Max': acx, 'Active Min': acn,
            'Idle Mean': idm, 'Idle Std': ids, 'Idle Max': idx, 'Idle Min': idn,
        }
        row = {k: row[k] for k in FEATURES}
        row.update({
            'Src IP': self.src, 'Dst IP': self.dst, 'Src Port': self.sport, 'Dst Port': self.dport,
            'Protocol': self.proto,
            'Timestamp': datetime.fromtimestamp(self.start, timezone.utc).isoformat(timespec='milliseconds'),
        })
        return row


class FlowMeter:
    def __init__(self, idle_timeout=5, active_timeout=30):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.flows = {}
        self.done = []
        self.packets = 0
        self._sweep_at = 0.0

    @staticmethod
    def _key(p):
        a, b = (p['src'], p['sport']), (p['dst'], p['dport'])
        return (a, b, p['proto']) if a <= b else (b, a, p['proto'])

    def _finish(self, key):
        self.done.append(self.flows.pop(key).to_dict())

    def add_packet(self, pkt):
        p = parse_packet(pkt)
        if p is None:
            return
        self.packets += 1
        t = p['time']
        key = self._key(p)
        fl = self.flows.get(key)
        if fl is not None:
            syn_only = (p['flags'] & (SYN | ACK)) == SYN
            if (fl.closing and syn_only) or t - fl.last > self.idle_timeout \
                    or t - fl.start >= self.active_timeout:
                self._finish(key)
                fl = None
        if fl is None:
            fl = self.flows[key] = _Flow(p)
        d = 0 if (p['src'], p['sport']) == (fl.src, fl.sport) else 1
        fl.add(p, d)
        if fl.rst:
            self._finish(key)
        if t - self._sweep_at >= 1.0:   # packet-time sweep so offline pcaps stream out
            self._sweep_at = t
            self._sweep(t)

    def _sweep(self, now):
        for key, fl in list(self.flows.items()):
            if now - fl.last > self.idle_timeout or now - fl.start >= self.active_timeout \
                    or (fl.closing and now - fl.last >= CLOSE_GRACE):
                self._finish(key)

    def collect_expired(self, now=None):
        self._sweep(time.time() if now is None else now)
        out, self.done = self.done, []
        return out

    def flush(self):
        for key in list(self.flows):
            self._finish(key)
        out, self.done = self.done, []
        return out
