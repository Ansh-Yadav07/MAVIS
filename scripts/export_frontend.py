"""Run the MAVIS engine over every capture day and write the console snapshot.

    python scripts/export_frontend.py                    # full files -> frontend/data/mavis.json
    python scripts/export_frontend.py --max-rows 50000   # quicker, first rows of each file

The snapshot holds real engine output (verdicts, scores, explanations, incidents, drift) for a
readable sample of flows per day, the full-day aggregates, and the evaluation reports, so the
static site on Netlify shows real results without a backend. Run after build_engine.py.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data.cic import find_flow_csvs  # noqa: E402
from engine import MavisEngine  # noqa: E402
from engine.frontend import build_payload, engine_meta  # noqa: E402

DAYS = {'Monday': ('mon', 'Mon 3 Jul', '2017-07-03'), 'Tuesday': ('tue', 'Tue 4 Jul', '2017-07-04'),
        'Wednesday': ('wed', 'Wed 5 Jul', '2017-07-05'), 'Thursday': ('thu', 'Thu 6 Jul', '2017-07-06'),
        'Friday': ('fri', 'Fri 7 Jul', '2017-07-07')}


def read_json(path):
    return json.loads(path.read_text()) if path.exists() else None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--raw-dir', type=Path, default=ROOT / 'dataset')
    p.add_argument('--engine', type=Path, default=ROOT / 'results' / 'engine')
    p.add_argument('--out', type=Path, default=ROOT / 'frontend' / 'data' / 'mavis.json')
    p.add_argument('--max-rows', type=int, default=None)
    p.add_argument('--per-family', type=int, default=60, help='exported alerts per threat family per file')
    p.add_argument('--normals', type=int, default=80, help='exported normal flows per file')
    a = p.parse_args()

    engine = MavisEngine.load(a.engine)
    captures = []
    for path in find_flow_csvs(a.raw_dir, exclude=a.raw_dir / 'processed'):
        day = next((v for k, v in DAYS.items() if path.name.lower().startswith(k.lower())), None)
        if day is None:
            continue
        t0 = time.time()
        raw = pd.read_csv(path, encoding='latin-1', low_memory=False, nrows=a.max_rows)
        slug = path.name.split('.')[0]
        payload = build_payload(engine, raw, day=day[0], file=path.name, id_prefix=f'{slug}:',
                                sample={'per_family': a.per_family, 'normals': a.normals, 'misses': 15, 'false_pos': 25, 'top': 25})
        s = payload['summary']
        print(f"{path.name}: {s['flows']:,} flows, {s['alerts']:,} alerts, {len(payload['flows'])} exported "
              f"({time.time() - t0:.0f}s)")
        captures.append(payload)

    order = [d[0] for d in DAYS.values()]
    captures.sort(key=lambda c: (order.index(c['day']), c['file']))
    snapshot = {
        'generated': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'source': 'CIC-IDS2017 MachineLearningCSV (no IP addresses or timestamps in these files)',
        'days': [{'id': i, 'label': l, 'date': d} for i, l, d in DAYS.values()],
        'engine': engine_meta(engine),
        'evaluation': {
            'engine': read_json(ROOT / 'reports' / 'engine_evaluation.json'),
            'anomaly': read_json(ROOT / 'reports' / 'evaluation_anomaly.json'),
            'preprocess': read_json(ROOT / 'reports' / 'preprocess_report_anomaly.json'),
        },
        'captures': captures,
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(snapshot, separators=(',', ':'), default=str))
    print(f"wrote {a.out} ({a.out.stat().st_size / 1e6:.1f} MB, "
          f"{sum(len(c['flows']) for c in captures):,} flows)")


if __name__ == '__main__':
    main()
