#!/usr/bin/env python
"""MAVIS live flow sensor: sniff packets, build CIC-style flows, post them to the MAVIS server.

  sudo .venv/bin/python scripts/sensor.py --iface en0
  sudo .venv/bin/python scripts/sensor.py --iface lo0 --bpf "tcp"
  .venv/bin/python scripts/sensor.py --pcap capture.pcap --csv out.csv
"""
import argparse
import csv
import http.client
import json
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from data.cic import FEATURES  # noqa: E402
from sensor.flowmeter import FlowMeter  # noqa: E402

CONTEXT = ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp']
BUFFER_CAP = 50_000
BATCH = 2000


class Poster:
    """Keep-alive JSON poster; remembers its own client endpoint so its traffic is not reported."""

    def __init__(self, api, meta):
        u = urlparse(api if '//' in api else 'http://' + api)
        self.host, self.port = u.hostname, u.port or 80
        self.meta = meta
        self.conn = None
        self.own = set()          # (ip, port) client endpoints used by this sensor
        self.buffer = []
        self.sent = 0
        self.warned = False

    def _post(self, flows):
        if self.conn is None:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
            self.conn.connect()
            ip, port = self.conn.sock.getsockname()[:2]
            self.own.add((ip, port))
            if ip == '::1' or ip.startswith('127.'):
                self.own.add(('127.0.0.1', port))
        body = json.dumps({'sensor': self.meta, 'flows': flows}, default=float)
        self.conn.request('POST', '/api/ingest', body, {'Content-Type': 'application/json'})
        r = self.conn.getresponse()
        r.read()
        if r.status >= 300:
            raise OSError(f'server answered HTTP {r.status}')

    def is_own(self, f):
        return (f['Src IP'], f['Src Port']) in self.own or (f['Dst IP'], f['Dst Port']) in self.own

    def push(self, flows):
        self.buffer.extend(f for f in flows if not self.is_own(f))
        del self.buffer[:-BUFFER_CAP]
        try:
            while True:
                chunk = self.buffer[:BATCH]
                self._post(chunk)
                del self.buffer[:len(chunk)]
                self.sent += len(chunk)
                if not self.buffer:
                    break
            if self.warned:
                print('[sensor] server reachable again')
                self.warned = False
        except (OSError, http.client.HTTPException) as e:
            if self.conn is not None:
                self.conn.close()
            self.conn = None
            if not self.warned:
                print(f'[sensor] warning: cannot reach http://{self.host}:{self.port} ({e}); '
                      f'buffering up to {BUFFER_CAP} flows and retrying')
                self.warned = True


def write_csv(path, flows, state):
    if not flows:
        return
    with open(path, 'a', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=FEATURES + CONTEXT, extrasaction='ignore')
        if not state['header']:
            w.writeheader()
            state['header'] = True
        w.writerows(flows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--iface')
    src.add_argument('--pcap')
    ap.add_argument('--api', default='http://127.0.0.1:8000')
    ap.add_argument('--csv')
    ap.add_argument('--bpf', default=None)
    ap.add_argument('--idle-timeout', type=float, default=5)
    ap.add_argument('--active-timeout', type=float, default=30)
    ap.add_argument('--id')
    ap.add_argument('--no-post', action='store_true', help='do not post to the server')
    ap.add_argument('--post', action='store_true', help='with --pcap and --csv, also post to the server')
    a = ap.parse_args()

    live = a.iface is not None
    sid = a.id or f"{socket.gethostname()}-{a.iface or 'pcap'}"
    meta = {'id': sid, 'iface': a.iface or Path(a.pcap).name, 'mode': 'live' if live else 'pcap',
            'started': datetime.now(timezone.utc).isoformat(timespec='seconds')}
    post = not a.no_post and (live or a.post or not a.csv)
    poster = Poster(a.api, meta)
    meter = FlowMeter(a.idle_timeout, a.active_timeout)
    csv_state = {'header': False}
    if a.csv:
        Path(a.csv).write_text('')

    def emit(flows):
        if a.csv:
            write_csv(a.csv, [f for f in flows if not poster.is_own(f)], csv_state)
        if post:
            poster.push(flows)

    if not live:
        from scapy.utils import PcapReader
        n = 0
        with PcapReader(a.pcap) as rd:
            for pkt in rd:
                meter.add_packet(pkt)
                n += 1
                if len(meter.done) >= 1000:
                    emit(meter.collect_expired(0))
        emit(meter.flush())
        print(f'[sensor] {a.pcap}: {n} packets, {meter.packets} parsed; '
              f'{poster.sent} flows posted' + (f'; csv -> {a.csv}' if a.csv else ''))
        return 0

    from scapy.all import sniff
    lock, stop, err = threading.Lock(), threading.Event(), []

    def on_packet(pkt):
        with lock:
            meter.add_packet(pkt)

    def sniffer():
        try:
            sniff(iface=a.iface, filter=a.bpf, prn=on_packet, store=False,
                  stop_filter=lambda _: stop.is_set())
        except Exception as e:  # noqa: BLE001
            err.append(e)

    t = threading.Thread(target=sniffer, daemon=True)
    t.start()
    print(f'[sensor] id={sid} iface={a.iface} bpf={a.bpf!r} -> {a.api}  (Ctrl+C to stop)')
    last_status = time.time()
    try:
        while not err:
            time.sleep(1)
            with lock:
                flows = meter.collect_expired()
            emit(flows)
            if post and not flows and not poster.buffer:
                poster.push([])     # heartbeat
            if time.time() - last_status >= 5:
                last_status = time.time()
                print(f'[sensor] packets={meter.packets} active_flows={len(meter.flows)} '
                      f'flows_sent={poster.sent} buffered={len(poster.buffer)}')
    except KeyboardInterrupt:
        print('\n[sensor] stopping, flushing flows...')
    stop.set()
    if err:
        e = err[0]
        denied = isinstance(e, PermissionError) or 'ermission' in str(e) or 'bpf' in str(e).lower()
        print(f'[sensor] capture failed: {e}', file=sys.stderr)
        if denied:
            print('[sensor] packet capture needs root: re-run with  sudo .venv/bin/python scripts/sensor.py ...',
                  file=sys.stderr)
        return 1
    with lock:
        flows = meter.flush()
    emit(flows)
    print(f'[sensor] done: packets={meter.packets} flows_sent={poster.sent}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
