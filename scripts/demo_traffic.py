#!/usr/bin/env python
"""Safe demo traffic for MAVIS. Touches ONLY localhost (127.0.0.1 / ::1). No root needed.

  .venv/bin/python scripts/demo_traffic.py normal|portscan|bruteforce|flood|db-access
"""
import argparse
import socket
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

LOCAL = {'127.0.0.1', '::1', 'localhost'}


def check_local(host):
    if host not in LOCAL:
        sys.exit(f'refusing to target {host!r}: demo traffic is restricted to 127.0.0.1 / ::1')


def get(url, timeout=3):
    check_local(urlparse(url).hostname)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            r.read()
        return True
    except Exception:  # noqa: BLE001
        return False


def listener(port, reply=b''):
    """Local TCP server on 127.0.0.1:port that reads and (optionally) answers."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(128)

    def handle(c):
        try:
            c.settimeout(2)
            c.recv(1024)
            if reply:
                c.sendall(reply)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def normal(a):
    paths = ['/', '/', '/index.html', '/favicon.ico', '/api/health', '/']
    end, i = time.time() + a.seconds, 0
    while time.time() < end:
        url = a.base + paths[i % len(paths)]
        print(f'GET {url} ->', 'ok' if get(url) else 'failed')
        i += 1
        time.sleep(0.2 + (i % 3) * 0.2)  # brisk browsing: enough flows to finish learning in ~2 min


def portscan(a):
    check_local('127.0.0.1')
    print('TCP connect scan of 127.0.0.1 ports 1-1024')

    def probe(p):
        s = socket.socket()
        s.settimeout(0.3)
        try:
            return p if s.connect_ex(('127.0.0.1', p)) == 0 else None
        finally:
            s.close()

    with ThreadPoolExecutor(8) as ex:
        openp = [p for p in ex.map(probe, range(1, 1025)) if p]
    print('open ports:', openp or 'none')


def bruteforce(a):
    srv = listener(a.port, b'SSH-2.0-fake\r\n')
    print(f'fake SSH listener on 127.0.0.1:{a.port}; ~5 logins/s for {a.seconds}s')
    end, n = time.time() + a.seconds, 0
    while time.time() < end:
        try:
            with socket.create_connection(('127.0.0.1', a.port), timeout=2) as c:
                c.sendall(f'USER root\r\nPASS guess{n}\r\n'.encode())
                c.recv(64)
        except OSError:
            pass
        n += 1
        time.sleep(0.2)
    srv.close()
    print(f'{n} attempts done')


def flood(a):
    url = a.base + '/'
    check_local(urlparse(url).hostname)
    print(f'flooding {url} for {a.seconds}s, {a.concurrency} workers, max {a.rate} req/s (localhost only)')
    end, count = time.time() + a.seconds, [0]

    # Capped at --rate requests/s in total (default 300): enough to trip MAVIS's flood rule
    # (100 flows / 10 s) many times over, without melting the laptop. Failed requests back off.
    gap = a.concurrency / max(1, a.rate)

    def worker():
        while time.time() < end:
            t0 = time.time()
            ok = get(url, 2)
            count[0] += 1
            time.sleep(max(0.0, gap - (time.time() - t0)) + (0 if ok else 0.5))

    ts = [threading.Thread(target=worker) for _ in range(a.concurrency)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    print(f'{count[0]} requests sent')


def db_access(a):
    srv = listener(5432, b'N')
    print('fake database listener on 127.0.0.1:5432; opening 6 connections')
    for i in range(6):
        try:
            with socket.create_connection(('127.0.0.1', 5432), timeout=2) as c:
                c.sendall(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
                c.recv(16)
                time.sleep(1)
        except OSError as e:
            print('connect failed:', e)
    srv.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', nargs='?', default='normal',
                    choices=['normal', 'portscan', 'bruteforce', 'flood', 'db-access'])
    ap.add_argument('--base', default='http://127.0.0.1:8000')
    ap.add_argument('--seconds', type=float)
    ap.add_argument('--port', type=int, default=2222)
    ap.add_argument('--concurrency', type=int, default=50)
    ap.add_argument('--rate', type=int, default=300, help='flood: max requests per second in total')
    a = ap.parse_args()
    check_local(urlparse(a.base).hostname)
    a.seconds = a.seconds or {'normal': 60, 'bruteforce': 30, 'flood': 20}.get(a.mode, 0)
    print(f'[demo] {a.mode}: this only generates traffic to localhost (127.0.0.1 / ::1).')
    {'normal': normal, 'portscan': portscan, 'bruteforce': bruteforce,
     'flood': flood, 'db-access': db_access}[a.mode](a)


if __name__ == '__main__':
    main()
