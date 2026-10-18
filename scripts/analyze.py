"""Analyse CICFlowMeter flow CSVs with the MAVIS engine.

    python scripts/analyze.py flows.csv                       # report -> reports/analysis_<name>.json
    python scripts/analyze.py dataset/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --max-rows 50000
    python scripts/analyze.py flows.csv --flows-out alerts.csv  # also write per-flow verdicts

Works on unlabelled live captures (`cicflowmeter -f capture.pcap -c flows.csv`) and on labelled
datasets; with a Label column the report also scores itself against the ground truth.
"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from engine import MavisEngine, analyze  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('csv', type=Path, nargs='+')
    p.add_argument('--engine', type=Path, default=ROOT / 'results' / 'engine')
    p.add_argument('--max-rows', type=int, default=None, help='read at most this many rows per file')
    p.add_argument('--report', type=Path, default=None)
    p.add_argument('--flows-out', type=Path, default=None, help='write per-flow verdicts (.csv or .parquet)')
    p.add_argument('--explain', type=int, default=200, help='explain the top N alerts')
    a = p.parse_args()

    engine = MavisEngine.load(a.engine)
    raw = pd.concat([pd.read_csv(f, encoding='latin-1', low_memory=False, nrows=a.max_rows) for f in a.csv],
                    ignore_index=True)
    report, flows = analyze(engine, raw, max_explanations=a.explain)
    report['inputs'] = [str(f) for f in a.csv]

    s = report['summary']
    print(f"{s['flows']:,} flows, {s.get('alerts', 0):,} alerts  {s.get('verdicts', {})}")
    print(f"severity: {s.get('severity', {})}")
    for inc in report['incidents'][:5]:
        print(f"  [{inc['severity']}] {inc['title']}: {inc['flows']:,} flows, max risk {inc['max_risk']}")
    for tip in report['insights']:
        print(f"  * {tip}")
    print(f"drift: {report['drift']['status']}")
    if 'ground_truth' in report:
        g = report['ground_truth']
        print(f"vs labels: precision {g['precision']:.3f} recall {g['recall']:.3f} FPR {g['fpr']:.4f}")

    out = a.report or ROOT / 'reports' / f"analysis_{a.csv[0].stem.split('.')[0]}.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f"report: {out}")
    if a.flows_out:
        (flows.to_parquet if a.flows_out.suffix == '.parquet' else flows.to_csv)(a.flows_out, index=False)
        print(f"flows: {a.flows_out}")


if __name__ == '__main__':
    main()
