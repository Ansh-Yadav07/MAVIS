"""Run the MAVIS console with the live engine behind it.

    python scripts/serve.py            # http://localhost:8000
    python scripts/serve.py --port 9000 --no-browser

Serves frontend/ and a small JSON API used by the console's "Analyze a capture" button:

    Live mode: POST /api/ingest, GET /api/live, POST /api/live/learn|reset, /api/blocks*, /api/response/*
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
from urllib.parse import parse_qs, unquote, urlparse

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from engine import MavisEngine  # noqa: E402
from engine.frontend import build_payload  # noqa: E402
from live.pipeline import LivePipeline  # noqa: E402

MAX_INGEST_BYTES = 20 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
LIVE = None
RESPONSE = None
RESPONSE_ERR = 'response module not available (src/response missing)'

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

    def _body_json(self, limit=MAX_JSON_BYTES, required=True):
        """Parse the JSON request body; sends the error response and returns None on failure."""
        size = int(self.headers.get('Content-Length') or 0)
        if size > limit:
            self._json(413, {'error': f'body larger than {limit // 1024} KB'})
            return None
        if size <= 0:
            if required:
                self._json(400, {'error': 'empty body: send JSON'})
                return None
            return {}
        try:
            obj = json.loads(self.rfile.read(size))
        except ValueError as exc:
            self._json(400, {'error': f'invalid JSON: {exc}'})
            return None
        if not isinstance(obj, dict):
            self._json(400, {'error': 'JSON body must be an object'})
            return None
        return obj

    def _need_response(self):
        if RESPONSE is None:
            self._json(503, {'error': RESPONSE_ERR})
            return False
        return True

    def _respond_call(self, fn):
        try:
            return self._json(200, fn())
        except (ValueError, KeyError, TypeError) as exc:
            return self._json(400, {'error': str(exc)})
        except Exception as exc:
            return self._json(500, {'error': f'response error: {exc}'})

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        if path == '/api/health':
            return self._json(200, {'ok': True, 'engine': {'alertBudgetFpr': ENGINE.target_fpr,
                                                           'features': len(ENGINE.features)},
                                    'maxRows': MAX_ROWS, 'maxBytes': MAX_BYTES,
                                    'live': True, 'response': RESPONSE is not None})
        if path == '/api/live':
            try:
                since = int(parse_qs(url.query).get('since', ['0'])[0])
            except ValueError:
                return self._json(400, {'error': 'since must be an integer'})
            return self._json(200, LIVE.snapshot(since))
        if path.startswith('/api/blocks') or path.startswith('/api/response/'):
            if not self._need_response():
                return
            if path == '/api/blocks':
                return self._respond_call(lambda: {'blocks': RESPONSE.blocks(), 'pending': RESPONSE.pending()})
            if path == '/api/response/config':
                return self._respond_call(RESPONSE.config)
            if path == '/api/response/audit':
                return self._respond_call(lambda: {'audit': RESPONSE.audit(200)})
            return self._json(404, {'error': 'unknown endpoint'})
        return super().do_GET()

    def do_DELETE(self):
        parts = urlparse(self.path).path.strip('/').split('/')
        if len(parts) == 3 and parts[:2] == ['api', 'blocks']:
            if not self._need_response():
                return
            return self._respond_call(lambda: {'unblocked': RESPONSE.unblock(unquote(parts[2]))})
        return self._json(404, {'error': 'unknown endpoint'})

    def _live_post(self, path):
        if path == '/api/ingest':
            if self.client_address[0] not in ('127.0.0.1', '::1', '::ffff:127.0.0.1'):
                return self._json(403, {'error': 'ingest is accepted from localhost only'})
            obj = self._body_json(MAX_INGEST_BYTES)
            if obj is None:
                return
            if not isinstance(obj.get('flows', []), list):
                return self._json(400, {'error': "'flows' must be a list"})
            try:
                with LOCK:
                    return self._json(200, LIVE.ingest(obj))
            except Exception as exc:
                return self._json(422, {'error': f'ingest failed: {exc}'})
        obj = self._body_json(required=False)
        if obj is None:
            return
        if path == '/api/live/reset':
            LIVE.reset()
            return self._json(200, {'ok': True})
        if path == '/api/live/learn':
            try:
                with LOCK:
                    return self._json(200, {'learning': LIVE.learn(obj.get('action'), obj.get('target'))})
            except (ValueError, TypeError) as exc:
                return self._json(400, {'error': str(exc)})
            except Exception as exc:
                return self._json(500, {'error': f'learning failed: {exc}'})
        return self._json(404, {'error': 'unknown endpoint'})

    def _response_post(self, path):
        if not self._need_response():
            return
        parts = path.strip('/').split('/')
        if path == '/api/response/config':
            obj = self._body_json()
            return None if obj is None else self._respond_call(lambda: RESPONSE.update_config(obj))
        if path == '/api/blocks':
            obj = self._body_json()
            if obj is None:
                return
            if not obj.get('ip'):
                return self._json(400, {'error': "'ip' is required"})
            return self._respond_call(lambda: RESPONSE.block(
                obj['ip'], obj.get('reason') or 'analyst block', ttl_minutes=obj.get('ttlMinutes'),
                source='analyst', alert_id=obj.get('alertId')))
        if len(parts) == 4 and parts[:2] == ['api', 'blocks'] and parts[3] in ('approve', 'reject'):
            fn = RESPONSE.approve if parts[3] == 'approve' else RESPONSE.reject
            return self._respond_call(lambda: fn(unquote(parts[2])))
        return self._json(404, {'error': 'unknown endpoint'})

    def do_POST(self):
        url = urlparse(self.path)
        if url.path.startswith('/api/live') or url.path == '/api/ingest':
            return self._live_post(url.path)
        if url.path.startswith('/api/blocks') or url.path.startswith('/api/response/'):
            return self._response_post(url.path)
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


def load_response():
    """ResponseManager is optional: serve 503 on its routes when the module is missing."""
    global RESPONSE, RESPONSE_ERR
    try:
        from response import ResponseManager
        RESPONSE = ResponseManager(str(ROOT / 'config' / 'response.json'),
                                   str(ROOT / 'results' / 'response' / 'audit.jsonl'))
    except ImportError:
        RESPONSE = None
    except Exception as exc:
        RESPONSE, RESPONSE_ERR = None, f'response module failed to start: {exc}'


def init_live(engine):
    global ENGINE, LIVE
    ENGINE = engine
    load_response()
    from live.profiles import HostProfiles
    LIVE = LivePipeline(engine, response=RESPONSE, profiles=HostProfiles(str(ROOT / 'config' / 'roles.json')))


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
    init_live(MavisEngine.load(a.engine))
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
