"""Run the MAVIS console with the live engine behind it.

    python scripts/serve.py            # http://localhost:8000
    python scripts/serve.py --port 9000 --no-browser

Serves frontend/ and a small JSON API used by the console's "Analyze a capture" button:

    GET  /api/health             -> {"ok": true, ...}
    POST /api/analyze?name=x.csv  body: a CICFlowMeter CSV -> the same payload shape as one
                                  capture in data/mavis.json

Standard library only (no web framework). Meant for local use, not for exposing to the internet.
"""
import argparse
import io
import json
import sys
import threading
import time
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from engine import MavisEngine  # noqa: E402
from engine.frontend import build_payload  # noqa: E402

MAX_BYTES = 300 * 1024 * 1024
MAX_ROWS = 1_000_000
ENGINE = None
LOCK = threading.Lock()  # torch / sklearn scoring is not worth running concurrently on a laptop
COUNTER = {'n': 0}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'frontend'), **kwargs)

    def log_message(self, fmt, *args):
        if '/api/' in (self.path or ''):
            super().log_message(fmt, *args)

    def _json(self, code, obj):
        body = json.dumps(obj, default=str, separators=(',', ':')).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path == '/api/health':
            return self._json(200, {'ok': True, 'engine': {'alertBudgetFpr': ENGINE.target_fpr,
                                                           'features': len(ENGINE.features)},
                                    'maxRows': MAX_ROWS, 'maxBytes': MAX_BYTES})
        return super().do_GET()

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != '/api/analyze':
            return self._json(404, {'error': 'unknown endpoint'})
        size = int(self.headers.get('Content-Length') or 0)
        if size <= 0:
            return self._json(400, {'error': 'empty upload: send a CICFlowMeter CSV as the request body'})
        if size > MAX_BYTES:
            return self._json(413, {'error': f'file larger than {MAX_BYTES // 2**20} MB'})
        name = parse_qs(url.query).get('name', ['upload.csv'])[0]
        try:
            df = pd.read_csv(io.BytesIO(self.rfile.read(size)), encoding='latin-1', low_memory=False, nrows=MAX_ROWS)
        except Exception as exc:  # malformed CSV
            return self._json(400, {'error': f'could not read CSV: {exc}'})
        if df.empty:
            return self._json(400, {'error': 'the CSV has no rows'})
        t0 = time.time()
        try:
            with LOCK:
                COUNTER['n'] += 1
                payload = build_payload(ENGINE, df, day='upload', file=name, id_prefix=f"up{COUNTER['n']}:")
        except Exception as exc:
            return self._json(422, {'error': f'analysis failed: {exc}'})
        payload['elapsed_s'] = round(time.time() - t0, 2)
        payload['truncated'] = len(df) >= MAX_ROWS
        return self._json(200, payload)


def main():
    global ENGINE
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--port', type=int, default=8000)
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--engine', type=Path, default=ROOT / 'results' / 'engine')
    p.add_argument('--no-browser', action='store_true')
    a = p.parse_args()
    if not (a.engine / 'engine.joblib').exists():
        sys.exit(f"no engine at {a.engine}: run scripts/train_evaluate.py then scripts/build_engine.py")
    print('loading engine...')
    ENGINE = MavisEngine.load(a.engine)
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    url = f'http://{"localhost" if a.host in ("127.0.0.1", "0.0.0.0") else a.host}:{a.port}'
    print(f'MAVIS console: {url}  (Ctrl+C to stop)')
    if not a.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
