"""Build data/sim_library.parquet: a small sample of CIC-IDS2017 flows per family for scripts/simulate.py.

    .venv/bin/python scripts/build_sim_library.py

Keeps raw (unscaled) float32 feature rows, ~1,500 benign and up to 400 per attack family.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data.cic import FEATURES, find_flow_csvs, load_flow_csv  # noqa: E402

FAMILIES = {'Benign': 1500, 'DoS': 400, 'DDoS': 400, 'PortScan': 400, 'BruteForce': 400,
            'WebAttack': 400, 'Bot': 400, 'Infiltration': 400}


def keep_consistent(lib):
    """With a trained engine available, keep benign rows the engine calls normal and attack rows it
    alerts on, so a demo's calm phase stays calm (about 1 % of benign CIC rows are false positives
    at the engine's budget) and each injected attack is actually seen."""
    engine_dir = ROOT / 'results' / 'engine'
    if not (engine_dir / 'engine.joblib').exists():
        print('no trained engine: library left unfiltered')
        return lib
    from engine import MavisEngine
    from engine.report import normalise_flows
    eng = MavisEngine.load(engine_dir)
    feats, _, _, _ = normalise_flows(lib.drop(columns=['family']))
    verdict = eng.score(eng.preprocessor.transform(feats)[eng.features])['verdict'].to_numpy()
    benign = (lib['family'] == 'Benign').to_numpy()
    keep = (benign & (verdict == 'normal')) | (~benign & (verdict != 'normal'))
    print(f'engine filter kept {int(keep.sum())} of {len(lib)} rows')
    return lib[keep].reset_index(drop=True)


def main():
    rng_seed = 42
    pools = {f: [] for f in FAMILIES}
    raw = ROOT / 'dataset'
    for path in find_flow_csvs(raw, exclude=raw / 'processed'):
        if path.parent != raw and 'processed' in str(path):
            continue
        try:
            df = load_flow_csv(path)
        except Exception as exc:  # non-CIC csv
            print(f'skip {path.name}: {exc}')
            continue
        df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
        for fam, g in df.groupby('category'):
            if fam in pools:
                n = FAMILIES[fam]
                pools[fam].append(g.sample(min(len(g), n * 2), random_state=rng_seed))  # oversample per file, trim below
        print(f'{path.name}: {len(df):,} rows')
    parts = []
    for fam, n in FAMILIES.items():
        if not pools[fam]:
            print(f'warning: no rows for {fam}')
            continue
        g = pd.concat(pools[fam], ignore_index=True)
        g = g.sample(min(len(g), n), random_state=rng_seed)
        out = g[FEATURES].astype(np.float32).reset_index(drop=True)
        out['family'] = fam
        parts.append(out)
        print(f'{fam}: {len(out)}')
    lib = pd.concat(parts, ignore_index=True)
    lib = keep_consistent(lib)
    out_path = ROOT / 'data' / 'sim_library.parquet'
    out_path.parent.mkdir(exist_ok=True)
    lib.to_parquet(out_path, index=False)
    print(f'wrote {out_path} ({out_path.stat().st_size / 1e6:.2f} MB, {len(lib)} rows)')


if __name__ == '__main__':
    main()
