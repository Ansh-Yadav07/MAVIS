"""Build and evaluate the MAVIS risk engine.

Run from the repo root after `python scripts/train_evaluate.py` (which trains the three anomaly
models into results/models/ and caches their scores in results/scores/):

    python scripts/build_engine.py                              # build, evaluate, save results/engine/
    python scripts/build_engine.py --holdout-families Bot PortScan WebAttack   # + zero-day test
    python scripts/build_engine.py --no-augment                 # without synthetic rare-class rows

The Tuesday-Friday test split is cut (stratified by attack family) into
  35 % classifier training, 15 % calibration (percentile maps + alert threshold), 50 % evaluation.
All reported numbers come from the evaluation half, which nothing was fitted on.

--holdout-families runs a zero-day experiment per family: the classifier is retrained without
that family, so the engine has never seen it labelled, and we measure whether the anomaly side
still raises it (as a `novel` alert).
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data import FlowPreprocessor, load_split  # noqa: E402
from engine import MavisEngine, evaluate  # noqa: E402
from engine.engine import MODEL_NAMES  # noqa: E402
from models import MavisAutoencoder, MavisIsolationForest, MavisLOF  # noqa: E402

LOADERS = {'iforest': (MavisIsolationForest, 'iforest.joblib'), 'lof': (MavisLOF, 'lof.joblib'),
           'ae': (MavisAutoencoder, 'ae.pt')}


def summarise(name, flows, cats):
    ev = evaluate(flows, cats)
    y = cats != 'Benign'
    ev['roc_auc'] = round(float(roc_auc_score(y, flows['risk_score'])), 4)
    ev['pr_auc'] = round(float(average_precision_score(y, flows['risk_score'])), 4)
    ev['verdicts'] = flows['verdict'].value_counts().to_dict()
    print(f"\n[{name}] ROC-AUC {ev['roc_auc']:.3f} | precision {ev['precision']:.3f} | recall {ev['recall']:.3f} "
          f"| F1 {ev['f1']:.3f} | FPR {ev['fpr']:.4f}")
    print(f"{'family':<14}{'n':>9}{'alerted':>9}{'named':>8}{'novel':>8}")
    for cat, e in sorted(ev['per_category'].items(), key=lambda kv: (kv[0] != 'Benign', kv[0])):
        print(f"{cat:<14}{e['n']:>9,}{e['alerted']:>9.1%}"
              f"{('' if cat == 'Benign' else format(e['named_correctly'], '.1%')):>8}"
              f"{('' if cat == 'Benign' else format(e['flagged_novel'], '.1%')):>8}")
    return ev


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--data-dir', type=Path, default=ROOT / 'dataset' / 'processed')
    p.add_argument('--model-dir', type=Path, default=ROOT / 'results' / 'models')
    p.add_argument('--score-dir', type=Path, default=ROOT / 'results' / 'scores')
    p.add_argument('--out', type=Path, default=ROOT / 'results' / 'engine')
    p.add_argument('--report', type=Path, default=ROOT / 'reports' / 'engine_evaluation.json')
    p.add_argument('--fpr', type=float, default=0.01, help='alert budget: target false-positive rate')
    p.add_argument('--no-augment', action='store_true', help='skip synthetic oversampling of rare families')
    p.add_argument('--holdout-families', nargs='*', default=[], help='zero-day experiment per family')
    p.add_argument('--max-benign', type=int, default=300_000, help='cap benign rows for the classifier')
    p.add_argument('--seed', type=int, default=42)
    a = p.parse_args()

    X, meta = load_split(a.data_dir, 'test')
    cats = meta['category'].to_numpy().astype(object)
    raw = {}
    for n in MODEL_NAMES:
        f = a.score_dir / f'{n}_test.npy'
        if not f.exists():
            sys.exit(f"missing {f}: run scripts/train_evaluate.py first")
        raw[n] = np.load(f)
        if len(raw[n]) != len(X):
            sys.exit(f"{f} has {len(raw[n])} rows, test has {len(X)}: re-run scripts/train_evaluate.py")
    models = {n: cls.load(a.model_dir / fname) for n, (cls, fname) in LOADERS.items()}

    idx = np.arange(len(X))
    fit_idx, eval_idx = train_test_split(idx, test_size=0.5, stratify=cats, random_state=a.seed)
    tr_idx, cal_idx = train_test_split(fit_idx, test_size=0.3, stratify=cats[fit_idx], random_state=a.seed)
    part = lambda ix: (X.iloc[ix], cats[ix], {n: raw[n][ix] for n in MODEL_NAMES})  # noqa: E731
    X_tr, y_tr, r_tr = part(tr_idx)
    X_cal, y_cal, r_cal = part(cal_idx)
    X_ev, y_ev, r_ev = part(eval_idx)
    print(f"classifier train {len(tr_idx):,} | calibration {len(cal_idx):,} | evaluation {len(eval_idx):,}")

    pre = FlowPreprocessor.load(a.data_dir / 'preprocessor.joblib')
    t0 = time.time()
    engine = MavisEngine(models, pre).fit(X_tr, y_tr, r_tr, X_cal, y_cal, r_cal, target_fpr=a.fpr,
                                          augment=not a.no_augment, max_benign=a.max_benign, seed=a.seed)
    print(f"engine fitted in {time.time() - t0:.0f}s")
    flows = engine.score(X_ev, raw=r_ev)
    report = {'alert_budget_fpr': a.fpr, 'alert_threshold': engine.alert_threshold,
              'synthetic_rows': engine.meta['synthetic_rows'],
              'engine': summarise('MAVIS engine', flows, y_ev)}

    # Baseline: anomaly ensemble alone at the same alert budget, for comparison.
    ens = flows['anomaly_percentile'].to_numpy()
    cal_ens = engine.score(X_cal, raw=r_cal)['anomaly_percentile'].to_numpy()
    thr = np.quantile(cal_ens[y_cal == 'Benign'], 1 - a.fpr)
    base = flows.copy()
    base['threat_family'] = ''
    base['verdict'] = np.where(ens >= thr, 'suspicious', 'normal')
    base['risk_score'] = ens
    base['detection_mode'] = np.where(ens >= thr, 'novel', '')
    report['anomaly_only'] = summarise('anomaly ensemble only', base, y_ev)

    report['zero_day'] = {}
    for fam in a.holdout_families:
        print(f"\n== zero-day test: classifier never sees {fam} ==")
        eng_h = MavisEngine(models, pre).fit(X_tr, y_tr, r_tr, X_cal, y_cal, r_cal, target_fpr=a.fpr,
                                             augment=not a.no_augment, exclude_categories=[fam],
                                             max_benign=a.max_benign, seed=a.seed, log=lambda *_: None)
        fl = eng_h.score(X_ev, raw=r_ev)
        m = y_ev == fam
        alerted = fl['verdict'].to_numpy()[m] != 'normal'
        res = {'n': int(m.sum()), 'alerted': round(float(alerted.mean()), 4),
               'as_novel': round(float((fl['detection_mode'].to_numpy()[m] == 'novel').mean()), 4),
               'anomaly_path_fired': round(float(fl['detection_mode'].isin(['novel', 'known+novel']).to_numpy()[m].mean()), 4),
               'misnamed_as': fl.loc[m & (fl['verdict'] == 'malicious').to_numpy(), 'threat_family']
               .value_counts().head(3).to_dict(),
               'benign_fpr': round(float((fl['verdict'].to_numpy()[y_ev == 'Benign'] != 'normal').mean()), 4)}
        report['zero_day'][fam] = res
        print(f"{fam}: alerted {res['alerted']:.1%} (anomaly path fired {res['anomaly_path_fired']:.1%}, "
              f"pure novel {res['as_novel']:.1%}), benign FPR {res['benign_fpr']:.2%}, "
              f"recognised as other family: {res['misnamed_as']}")

    engine.save(a.out)
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nengine: {a.out}\nreport: {a.report}")


if __name__ == '__main__':
    main()
