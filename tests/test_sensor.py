import math
import subprocess
import sys
from pathlib import Path

import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, wrpcap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data.cic import FEATURES  # noqa: E402
from engine.report import normalise_flows  # noqa: E402
from sensor.flowmeter import FlowMeter  # noqa: E402

C, S = '10.0.0.1', '10.0.0.2'


def tcp(t, src, dst, sp, dp, flags, payload=b'', win=8192):
    p = IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, window=win)
    if payload:
        p = p / Raw(payload)
    p.time = t
    return p


def session(t0=1000.0):
    return [
        tcp(t0, C, S, 40000, 80, 'S', win=1000),
        tcp(t0 + .001, S, C, 80, 40000, 'SA', win=2000),
        tcp(t0 + .002, C, S, 40000, 80, 'A'),
        tcp(t0 + .003, C, S, 40000, 80, 'PA', b'GET / HTTP/1.1\r\n'),   # 16 bytes
        tcp(t0 + .004, S, C, 80, 40000, 'PA', b'x' * 100),
        tcp(t0 + .005, C, S, 40000, 80, 'FA'),
        tcp(t0 + .006, S, C, 80, 40000, 'FA'),
        tcp(t0 + .007, C, S, 40000, 80, 'A'),
    ]


def run(pkts):
    m = FlowMeter()
    for p in pkts:
        m.add_packet(p)
    return m.flush()


def check_row(r):
    for k in FEATURES + ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp']:
        assert k in r, k
    assert all(math.isfinite(r[k]) for k in FEATURES)


def test_tcp_session():
    (r,) = run(session())
    check_row(r)
    assert r['Total Fwd Packets'] == 5 and r['Total Backward Packets'] == 3
    assert r['Total Length of Fwd Packets'] == 16 and r['Total Length of Bwd Packets'] == 100
    assert abs(r['Flow Duration'] - 7000) < 1
    assert r['SYN Flag Count'] == 2 and r['FIN Flag Count'] == 2 and r['PSH Flag Count'] == 2
    assert r['Fwd PSH Flags'] == 1 and r['Bwd PSH Flags'] == 1
    assert r['Destination Port'] == 80 and r['Dst Port'] == 80 and r['Src IP'] == C
    assert r['Init_Win_bytes_forward'] == 1000 and r['Init_Win_bytes_backward'] == 2000
    assert r['act_data_pkt_fwd'] == 1 and r['min_seg_size_forward'] == 20
    assert r['Fwd Header Length'] == 100 and r['Protocol'] == 6
    assert r['Timestamp'].startswith('1970-01-01T00:16:40')


def test_udp_pair():
    a = IP(src=C, dst=S) / UDP(sport=5000, dport=53) / Raw(b'q' * 30)
    b = IP(src=S, dst=C) / UDP(sport=53, dport=5000) / Raw(b'r' * 60)
    a.time, b.time = 50.0, 50.002
    (r,) = run([a, b])
    check_row(r)
    assert r['Protocol'] == 17 and r['Destination Port'] == 53
    assert r['Total Length of Fwd Packets'] == 30 and r['Total Length of Bwd Packets'] == 60
    assert r['Init_Win_bytes_forward'] == -1 and abs(r['Flow Duration'] - 2000) < 1
    assert r['Fwd Header Length'] == 8


def test_rst_scan_flow():
    pkts = [tcp(10.0, C, S, 41000, 22, 'S'), tcp(10.0005, S, C, 22, 41000, 'RA')]
    m = FlowMeter()
    for p in pkts:
        m.add_packet(p)
    out = m.collect_expired(10.001)      # RST ends the flow immediately
    assert len(out) == 1
    r = out[0]
    check_row(r)
    assert r['RST Flag Count'] == 1 and r['Total Fwd Packets'] == 1 and r['Total Backward Packets'] == 1


def test_idle_timeout_and_zero_duration():
    m = FlowMeter(idle_timeout=5)
    m.add_packet(tcp(100.0, C, S, 42000, 3306, 'S'))
    assert m.collect_expired(102.0) == []
    out = m.collect_expired(106.0)
    assert len(out) == 1 and out[0]['Flow Duration'] == 0 and out[0]['Flow Packets/s'] == 0
    check_row(out[0])
    assert m.flush() == []


def test_active_timeout_cuts_flow():
    m = FlowMeter(idle_timeout=5, active_timeout=30)
    for i in range(0, 70, 2):
        m.add_packet(tcp(200.0 + i, C, S, 43000, 80, 'A', b'd'))
    out = m.collect_expired(270.0) + m.flush()
    assert len(out) >= 2 and sum(r['Total Fwd Packets'] for r in out) == 35


def test_normalise_accepts_output():
    rows = run(session() + [tcp(5.0, C, S, 41000, 22, 'S')])
    _, _, _, quality = normalise_flows(pd.DataFrame(rows))
    assert quality['missing_feature_columns'] == []


def test_offline_cli(tmp_path):
    pcap, out = tmp_path / 't.pcap', tmp_path / 'o.csv'
    wrpcap(str(pcap), session())
    r = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'sensor.py'), '--pcap', str(pcap),
                        '--csv', str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    df = pd.read_csv(out)
    assert len(df) == 1 and df.loc[0, 'Total Fwd Packets'] == 5 and set(FEATURES) <= set(df.columns)
