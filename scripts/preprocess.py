"""Clean, split and scale the CIC flow CSVs.

Run from the repo root:

    python scripts/preprocess.py                      # anomaly split, dataset/ -> dataset/processed/
    python scripts/preprocess.py --mode supervised --out-dir dataset/processed_supervised
    python scripts/preprocess.py --max-rows-per-file 20000   # quick run on a low-RAM laptop
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data.preprocess import run  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--raw-dir', default=None, type=Path,
                   help='folder with the CICFlowMeter CSVs, searched recursively (default: dataset/ or datasets/ in the repo)')
    p.add_argument('--out-dir', default=ROOT / 'dataset' / 'processed', type=Path)
    p.add_argument('--mode', choices=['anomaly', 'supervised'], default='anomaly')
    p.add_argument('--benign-source', default='Monday', help="anomaly mode: train on benign rows of files whose name contains this")
    p.add_argument('--val-frac', type=float, default=0.15)
    p.add_argument('--test-frac', type=float, default=0.15, help='supervised mode only')
    p.add_argument('--drop-port', action='store_true', help="drop 'Destination Port' so models can't just memorise ports")
    p.add_argument('--max-rows-per-file', type=int, default=None)
    p.add_argument('--seed', type=int, default=42)
    p.add_argument('--report', type=Path, default=None, help='also copy the report here (default: reports/preprocess_report_<mode>.json)')
    a = p.parse_args()
    if a.raw_dir is None:
        a.raw_dir = next((d for d in (ROOT / 'dataset', ROOT / 'datasets') if d.is_dir()), None)
        if a.raw_dir is None:
            p.error(f"no dataset/ or datasets/ folder in {ROOT}; pass --raw-dir /path/to/csvs")
    print(f"reading CSVs from {a.raw_dir}")

    report = run(a.raw_dir, a.out_dir, mode=a.mode, benign_source=a.benign_source, val_frac=a.val_frac,
                 test_frac=a.test_frac, drop_port=a.drop_port, max_rows_per_file=a.max_rows_per_file, seed=a.seed)

    dest = a.report or ROOT / 'reports' / f'preprocess_report_{a.mode}.json'
    shutil.copyfile(a.out_dir / 'preprocess_report.json', dest)
    print(f"features kept: {len(report['features'])}, dropped: {report['dropped_columns']}")
    print(json.dumps({k: v['categories'] for k, v in report['splits'].items()}, indent=2))
    print(f"report: {dest}")


if __name__ == '__main__':
    main()
