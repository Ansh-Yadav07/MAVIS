"""Train the anomaly models on benign flows and evaluate them per attack category.

Run from the repo root after `python scripts/preprocess.py` (anomaly mode):

    python scripts/train_evaluate.py                          # all models, full test set
    python scripts/train_evaluate.py --models iforest ae      # skip LOF (slowest to score)
    python scripts/train_evaluate.py --max-test-benign 200000 # quicker: subsample benign test flows

Each model is trained on train.parquet (benign only). Its alert threshold is the
(1 - fpr) quantile of its scores on val.parquet, which is also benign, so no
attack labels are used to pick it. Test results are reported overall and as the
detection rate for each attack category. An `ensemble` row averages the models'
val-percentile scores, a first version of the MAVIS risk engine.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from data import load_split  # noqa: E402
from models import MavisAutoencoder, MavisIsolationForest, MavisLOF  # noqa: E402

MODEL_NAMES = ['iforest', 'lof', 'ae']


def build(name, n_features, a):
    # Parameters follow results/hpo/final_hpo_report.json where the wrapper exposes them.
    if name == 'iforest':
        return MavisIsolationForest(n_estimators=300, random_state=a.seed)
    if name == 'lof':
        return MavisLOF(n_neighbors=50, metric='euclidean', leaf_size=40, max_train_samples=a.lof_train_samples)
    device = 'mps' if a.device == 'auto' and _mps_available() else ('cpu' if a.device == 'auto' else a.device)
    return MavisAutoencoder(n_features, learning_rate=3e-4, device=device)


def _mps_available():
    import torch
    return torch.backends.mps.is_available()


def fit(name, model, X, a):
    if name == 'ae':
        model.fit(X, epochs=a.ae_epochs, batch_size=128)
    else:
        model.train(X)


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
    w = max(len(c) for c in categories + ['detected @ val threshold']) + 2
    print('\n' + 'detected @ val threshold'.ljust(w) + ''.join(n.rjust(10) for n in names))
    for cat in categories:
        row = [results[n]['per_category'].get(cat, {}).get('flagged') for n in names]
        print(cat.ljust(w) + ''.join(('-' if v is None else f'{v:.1%}').rjust(10) for v in row))
    print('-' * (w + 10 * len(names)))
    for key, label in [('roc_auc', 'ROC-AUC'), ('pr_auc', 'PR-AUC'), ('precision', 'Precision'),
                       ('recall', 'Recall'), ('f1', 'F1'), ('fpr', 'FPR')]:
        print(label.ljust(w) + ''.join(f'{results[n][key]:.3f}'.rjust(10) for n in names))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--data-dir', type=Path, default=ROOT / 'dataset' / 'processed')
    p.add_argument('--models', nargs='+', choices=MODEL_NAMES, default=MODEL_NAMES)
    p.add_argument('--fpr', type=float, default=0.01, help='target false-positive rate used to set each threshold on val')
    p.add_argument('--max-train', type=int, default=None, help='subsample the benign training flows')
    p.add_argument('--max-test-benign', type=int, default=None, help='subsample benign test flows (all attacks are kept)')
    p.add_argument('--lof-train-samples', type=int, default=30_000)
    p.add_argument('--ae-epochs', type=int, default=20)
    p.add_argument('--device', default='auto', help="autoencoder device: auto, cpu or mps")
    p.add_argument('--model-dir', type=Path, default=ROOT / 'results' / 'models')
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
    print(f"train {len(X_train):,} | val {len(X_val):,} | test {len(X_test):,} "
          f"({int(meta_test['is_attack'].sum()):,} attacks) | {X_train.shape[1]} features")

    a.model_dir.mkdir(parents=True, exist_ok=True)
    results, val_pct, test_pct, timings = {}, {}, {}, {}
    for name in a.models:
        print(f"\n== {name} ==")
        model = build(name, X_train.shape[1], a)
        t0 = time.time()
        fit(name, model, X_train, a)
        t1 = time.time()
        val_scores = score(model, X_val)
        test_scores = score(model, X_test)
        t2 = time.time()
        timings[name] = {'train_s': round(t1 - t0, 1), 'score_s': round(t2 - t1, 1)}
        threshold = np.quantile(val_scores, 1 - a.fpr)
        results[name] = evaluate(test_scores, threshold, meta_test)
        val_pct[name], test_pct[name] = percentile_of(val_scores, val_scores), percentile_of(val_scores, test_scores)
        if hasattr(model, 'save'):
            model.save(a.model_dir / f"{name}.{'pt' if name == 'ae' else 'joblib'}")
        print(f"train {timings[name]['train_s']}s, score {timings[name]['score_s']}s, "
              f"ROC-AUC {results[name]['roc_auc']:.3f}")

    if len(a.models) > 1:
        ens_val = np.mean([val_pct[n] for n in a.models], axis=0)
        ens_test = np.mean([test_pct[n] for n in a.models], axis=0)
        results['ensemble'] = evaluate(ens_test, np.quantile(ens_val, 1 - a.fpr), meta_test)

    categories = sorted(meta_test['category'].unique(), key=lambda c: (c != 'Benign', c))
    print_table(results, categories)

    report = {
        'data_dir': str(a.data_dir), 'target_fpr': a.fpr,
        'n_train': len(X_train), 'n_val': len(X_val), 'n_test': len(X_test),
        'timings': timings, 'results': results,
    }
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2))
    print(f"\nreport: {a.report}\nmodels: {a.model_dir}")


if __name__ == '__main__':
    main()
