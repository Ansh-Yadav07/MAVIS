"""Train the anomaly models on benign flows and evaluate them per attack category.

Run from the repo root after `python scripts/preprocess.py` (anomaly mode):

    python scripts/train_evaluate.py                          # all models, full test set
    python scripts/train_evaluate.py --models iforest ae      # skip LOF (slowest to score)
    python scripts/train_evaluate.py --max-test-benign 200000 # quicker: subsample benign test flows

    python scripts/train_evaluate.py --reuse-scores           # re-run the comparison from cached scores

Each model is trained on train.parquet (benign Monday flows only). Scores are
mapped to their percentile among benign val flows so models are comparable.

The test split (Tuesday-Friday) is cut into a stratified calibration slice
(--calib-frac, default 10 %) and the evaluation set. The calibration slice is
used to set each alert threshold at the target false-positive rate on
Tuesday-Friday benign traffic (the Monday-only val threshold under-estimates it)
and to fit the stacked ensemble. Every number in the table is measured on the
evaluation set only.

Ensembles (versions of the MAVIS risk engine):
  ens_mean   mean of all model percentiles
  ens_best2  mean of the LOF and autoencoder percentiles
  ens_max    max of all model percentiles (alert if any model is confident)
  ens_stack  logistic regression on the percentiles, fitted on the calibration slice
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data import load_split  # noqa: E402
from models import MavisAutoencoder, MavisIsolationForest, MavisLOF  # noqa: E402

MODEL_NAMES = ['iforest', 'lof', 'ae']


def build(name, n_features, a):
    # Parameters follow results/hpo/final_hpo_report.json where the wrapper exposes them.
    if name == 'iforest':
        return MavisIsolationForest(n_estimators=300, max_samples=0.75, max_features=0.5, random_state=a.seed)
    if name == 'lof':
        return MavisLOF(n_neighbors=50, metric='euclidean', leaf_size=40, max_train_samples=a.lof_train_samples)
    device = 'mps' if a.device == 'auto' and _mps_available() else ('cpu' if a.device == 'auto' else a.device)
    return MavisAutoencoder(n_features, learning_rate=3e-4, device=device, dropout=0.1, seed=a.seed)


def _mps_available():
    import torch
    return torch.backends.mps.is_available()


def fit(name, model, X, a, X_val=None):
    if name == 'ae':
        model.fit(X, X_val=X_val, epochs=a.ae_epochs, batch_size=128, patience=3)
    else:
        model.fit(X)


def score(model, X, chunk=100_000):
    """Score in chunks so LOF and the autoencoder stay within memory on the 2M-row test set."""
    out = []
    for i in range(0, len(X), chunk):
        out.append(model.predict_anomaly_score(X.iloc[i:i + chunk]))
        if len(X) > chunk:
            print(f"  scored {min(i + chunk, len(X)):,}/{len(X):,}", end='\r', flush=True)
    if len(X) > chunk:
        print()
    return np.concatenate(out).astype(np.float64)


def evaluate(scores, threshold, meta):
    y = meta['is_attack'].to_numpy().astype(bool)
    alert = scores > threshold
    tp, fp = int((alert & y).sum()), int((alert & ~y).sum())
    fn, tn = int((~alert & y).sum()), int((~alert & ~y).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    per_category = {}
    for cat, idx in meta.groupby('category').indices.items():
        per_category[cat] = {'n': len(idx), 'flagged': float(alert[idx].mean())}
    return {
        'roc_auc': float(roc_auc_score(y, scores)),
        'pr_auc': float(average_precision_score(y, scores)),
        'threshold': float(threshold),
        'precision': precision,
        'recall': recall,
        'f1': 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        'fpr': fp / (fp + tn) if fp + tn else 0.0,
        'confusion': {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn},
        'per_category': per_category,
    }


def percentile_of(val_scores, scores):
    """Map scores to their percentile among benign val scores (0..1), comparable across models."""
    ref = np.sort(val_scores)
    return np.searchsorted(ref, scores, side='right') / len(ref)


def print_table(results, categories):
    names = list(results)
    title = 'detected (eval set)'
    w = max(len(c) for c in categories + [title, 'FPR (Monday threshold)']) + 2
    print('\n' + title.ljust(w) + ''.join(n.rjust(10) for n in names))
    for cat in categories:
        row = [results[n]['per_category'].get(cat, {}).get('flagged') for n in names]
        print(cat.ljust(w) + ''.join(('-' if v is None else f'{v:.1%}').rjust(10) for v in row))
    print('-' * (w + 10 * len(names)))
    for key, label in [('roc_auc', 'ROC-AUC'), ('pr_auc', 'PR-AUC'), ('precision', 'Precision'),
                       ('recall', 'Recall'), ('f1', 'F1'), ('fpr', 'FPR'),
                       ('fpr_monday_threshold', 'FPR (Monday threshold)')]:
        print(label.ljust(w) + ''.join(('-' if results[n].get(key) is None else f'{results[n][key]:.3f}').rjust(10)
                                       for n in names))


def train_and_score(name, X_train, X_val, X_test, a):
    """Return (val_scores, test_scores, timings), from the cache when --reuse-scores allows it."""
    cache = {split: a.score_dir / f'{name}_{split}.npy' for split in ('val', 'test')}
    if a.reuse_scores and all(f.exists() for f in cache.values()):
        val_scores, test_scores = np.load(cache['val']), np.load(cache['test'])
        if len(val_scores) == len(X_val) and len(test_scores) == len(X_test):
            print(f"loaded cached scores from {a.score_dir}")
            return val_scores, test_scores, None
        print("cached scores don't match this data, retraining")

    model = build(name, X_train.shape[1], a)
    t0 = time.time()
    fit(name, model, X_train, a, X_val=X_val)
    t1 = time.time()
    val_scores, test_scores = score(model, X_val), score(model, X_test)
    timings = {'train_s': round(t1 - t0, 1), 'score_s': round(time.time() - t1, 1)}
    if hasattr(model, 'save'):
        model.save(a.model_dir / f"{name}.{'pt' if name == 'ae' else 'joblib'}")
    if not a.max_test_benign:
        np.save(cache['val'], val_scores)
        np.save(cache['test'], test_scores)
    return val_scores, test_scores, timings


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--data-dir', type=Path, default=ROOT / 'dataset' / 'processed')
    p.add_argument('--models', nargs='+', choices=MODEL_NAMES, default=MODEL_NAMES)
    p.add_argument('--fpr', type=float, default=0.01, help='target false-positive rate for every threshold')
    p.add_argument('--calib-frac', type=float, default=0.10, help='share of test held out to set thresholds and fit ens_stack')
    p.add_argument('--max-train', type=int, default=None, help='subsample the benign training flows')
    p.add_argument('--max-test-benign', type=int, default=None, help='subsample benign test flows (all attacks are kept)')
    p.add_argument('--lof-train-samples', type=int, default=30_000)
    p.add_argument('--ae-epochs', type=int, default=20)
    p.add_argument('--device', default='auto', help="autoencoder device: auto, cpu or mps")
    p.add_argument('--model-dir', type=Path, default=ROOT / 'results' / 'models')
    p.add_argument('--score-dir', type=Path, default=ROOT / 'results' / 'scores')
    p.add_argument('--reuse-scores', action='store_true', help='skip training when cached scores for this data exist')
    p.add_argument('--report', type=Path, default=ROOT / 'reports' / 'evaluation_anomaly.json')
    p.add_argument('--seed', type=int, default=42)
    a = p.parse_args()

    X_train, _ = load_split(a.data_dir, 'train')
    X_val, _ = load_split(a.data_dir, 'val')
    X_test, meta_test = load_split(a.data_dir, 'test')
    if a.max_train and len(X_train) > a.max_train:
        X_train = X_train.sample(n=a.max_train, random_state=a.seed)
    if a.max_test_benign:
        is_benign = ~meta_test['is_attack'].astype(bool).to_numpy()
        if is_benign.sum() > a.max_test_benign:
            rng = np.random.default_rng(a.seed)
            keep = ~is_benign
            keep[rng.choice(np.flatnonzero(is_benign), size=a.max_test_benign, replace=False)] = True
            X_test, meta_test = X_test[keep].reset_index(drop=True), meta_test[keep].reset_index(drop=True)
    calib_idx, eval_idx = train_test_split(np.arange(len(X_test)), test_size=1 - a.calib_frac,
                                           stratify=meta_test['category'], random_state=a.seed)
    meta_calib, meta_eval = meta_test.iloc[calib_idx], meta_test.iloc[eval_idx]
    calib_benign = ~meta_calib['is_attack'].astype(bool).to_numpy()
    print(f"train {len(X_train):,} | val {len(X_val):,} | calib {len(calib_idx):,} | eval {len(eval_idx):,} "
          f"({int(meta_eval['is_attack'].sum()):,} attacks) | {X_train.shape[1]} features")

    a.model_dir.mkdir(parents=True, exist_ok=True)
    a.score_dir.mkdir(parents=True, exist_ok=True)
    results, val_pct, test_pct, timings = {}, {}, {}, {}

    def add_result(name, val_s, test_s):
        """Threshold on calibration-slice benign flows, evaluate on the eval set."""
        threshold = np.quantile(test_s[calib_idx][calib_benign], 1 - a.fpr)
        results[name] = evaluate(test_s[eval_idx], threshold, meta_eval)
        if val_s is not None:
            monday = evaluate(test_s[eval_idx], np.quantile(val_s, 1 - a.fpr), meta_eval)
            results[name]['fpr_monday_threshold'] = monday['fpr']

    for name in a.models:
        print(f"\n== {name} ==")
        val_scores, test_scores, t = train_and_score(name, X_train, X_val, X_test, a)
        if t:
            timings[name] = t
        val_pct[name], test_pct[name] = percentile_of(val_scores, val_scores), percentile_of(val_scores, test_scores)
        add_result(name, val_scores, test_scores)
        print(f"ROC-AUC {results[name]['roc_auc']:.3f}")

    if len(a.models) > 1:
        V = np.column_stack([val_pct[n] for n in a.models])
        T = np.column_stack([test_pct[n] for n in a.models])
        add_result('ens_mean', V.mean(axis=1), T.mean(axis=1))
        add_result('ens_max', V.max(axis=1), T.max(axis=1))
        best2 = [i for i, n in enumerate(a.models) if n in ('lof', 'ae')]
        if len(best2) == 2:
            add_result('ens_best2', V[:, best2].mean(axis=1), T[:, best2].mean(axis=1))
        # Logit of the percentile spreads out the top of the range, where attacks sit.
        logit = lambda P: np.log(np.clip(P, 1e-6, 1 - 1e-6) / (1 - np.clip(P, 1e-6, 1 - 1e-6)))
        stack = LogisticRegression(class_weight='balanced', max_iter=1000)
        stack.fit(logit(T[calib_idx]), meta_calib['is_attack'].astype(int))
        add_result('ens_stack', None, stack.decision_function(logit(T)))
        results['ens_stack']['weights'] = dict(zip(a.models, stack.coef_[0].round(3).tolist()))
        print(f"\nens_stack weights: {results['ens_stack']['weights']}")

    categories = sorted(meta_eval['category'].unique(), key=lambda c: (c != 'Benign', c))
    print_table(results, categories)

    report = {
        'data_dir': str(a.data_dir), 'target_fpr': a.fpr, 'calib_frac': a.calib_frac,
        'n_train': len(X_train), 'n_val': len(X_val), 'n_calib': len(calib_idx), 'n_eval': len(eval_idx),
        'thresholds': 'quantile (1 - target_fpr) of calibration-slice benign scores',
        'timings': timings, 'results': results,
    }
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2))
    print(f"\nreport: {a.report}\nmodels: {a.model_dir}")


if __name__ == '__main__':
    main()
