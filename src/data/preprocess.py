"""Cleaning, splitting and scaling of CICFlowMeter flows.

Two split modes:

- 'anomaly' (for IF / LOF / Autoencoder): train only on benign flows from the
  benign capture (Monday in CIC-IDS2017). A held-out slice of those benign
  flows is the validation set, used later to pick score thresholds without
  touching attack labels. Every other file is the test set.
- 'supervised' (for a classifier that names the attack family): stratified
  train / val / test split over all files, by attack category.

The FlowPreprocessor is fitted on the training split only and saved, so the
exact same transform can be applied to test data and, later, to live flows.
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .cic import FEATURES, LABEL, find_flow_csvs, load_flow_csv

META_COLUMNS = [LABEL, 'category', 'is_attack', 'source']


def clean(df, report):
    """Drop rows with NaN/inf features and exact duplicate rows. Records counts in report."""
    report['rows_loaded'] = len(df)

    bad = np.zeros(len(df), dtype=bool)
    for c in FEATURES:
        bad |= ~np.isfinite(df[c].to_numpy())
    report['rows_dropped_nan_or_inf'] = int(bad.sum())
    df = df[~bad]

    row_hash = pd.util.hash_pandas_object(df[FEATURES], index=False)
    # Identical flow features under different labels: a known CIC-IDS2017 labelling issue.
    labels_per_flow = df[LABEL].groupby(row_hash.values).nunique()
    report['flows_with_conflicting_labels'] = int((labels_per_flow > 1).sum())

    dup = pd.DataFrame({'h': row_hash.values, 'y': df[LABEL].values}).duplicated().to_numpy()
    report['rows_dropped_duplicate'] = int(dup.sum())
    df = df[~dup]

    report['rows_clean'] = len(df)
    return df.reset_index(drop=True)


def constant_columns(df):
    """Features with a single value across the whole cleaned corpus (carry no information)."""
    return [c for c in FEATURES if df[c].nunique(dropna=False) <= 1]


def signed_log(x):
    """sign(x) * log(1 + |x|): tames heavy-tailed byte/packet/time counts, keeps -1 sentinels distinct."""
    return np.sign(x) * np.log1p(np.abs(x))


class FlowPreprocessor:
    """signed-log transform + standard scaling, fitted on training rows only."""

    def __init__(self, drop_columns=()):
        self.drop_columns = list(drop_columns)

    def fit(self, df):
        self.features_ = [c for c in FEATURES if c not in self.drop_columns]
        logged = signed_log(df[self.features_].astype(np.float64))
        self.medians_ = logged.median()
        self.scaler_ = StandardScaler().fit(logged)
        return self

    def transform(self, df):
        """Scale flows. NaN/inf (e.g. Flow Bytes/s of a zero-length flow) get the training median."""
        x = df[self.features_].astype(np.float64).replace([np.inf, -np.inf], np.nan)
        logged = signed_log(x).fillna(self.medians_)
        scaled = self.scaler_.transform(logged).astype(np.float32)
        return pd.DataFrame(scaled, columns=self.features_, index=df.index)

    def save(self, path):
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        return joblib.load(path)


def split_anomaly(df, benign_source, val_frac, seed):
    from_benign_file = df['source'].str.contains(benign_source, case=False, regex=False)
    if not from_benign_file.any():
        raise ValueError(f"no file name contains {benign_source!r}; pass --benign-source")
    pool = df[from_benign_file & (df['is_attack'] == 0)]
    train, val = train_test_split(pool, test_size=val_frac, random_state=seed)
    test = df[~from_benign_file]
    return {'train': train, 'val': val, 'test': test}


def split_supervised(df, val_frac, test_frac, seed):
    counts = df['category'].value_counts()
    too_small = counts[counts < 3]
    if len(too_small):
        raise ValueError(f"categories with < 3 rows can't be stratified into 3 splits: {too_small.to_dict()}")
    train, rest = train_test_split(
        df, test_size=val_frac + test_frac, stratify=df['category'], random_state=seed)
    val, test = train_test_split(
        rest, test_size=test_frac / (val_frac + test_frac), stratify=rest['category'], random_state=seed)
    return {'train': train, 'val': val, 'test': test}


def run(raw_dir, out_dir, mode='anomaly', benign_source='Monday', val_frac=0.15, test_frac=0.15,
        drop_port=False, max_rows_per_file=None, seed=42, log=print):
    """Load every CSV under raw_dir, clean, split, scale and write the splits to out_dir."""
    raw_dir, out_dir = Path(raw_dir), Path(out_dir)
    files = find_flow_csvs(raw_dir, exclude=out_dir)
    if not files:
        raise FileNotFoundError(f"no CSV files found under {raw_dir}")

    report = {'mode': mode, 'seed': seed, 'files': []}
    frames = []
    for path in files:
        part = load_flow_csv(path, max_rows=max_rows_per_file)
        log(f"loaded {path.name}: {len(part):,} rows")
        report['files'].append({'source': path.name, 'rows': len(part)})
        frames.append(part)
    df = clean(pd.concat(frames, ignore_index=True), report)
    log(f"clean: {report['rows_clean']:,} rows "
        f"(-{report['rows_dropped_nan_or_inf']:,} NaN/inf, -{report['rows_dropped_duplicate']:,} duplicates)")

    drop = constant_columns(df)
    if drop_port:
        drop.append('Destination Port')
    report['dropped_columns'] = drop

    if mode == 'anomaly':
        splits = split_anomaly(df, benign_source, val_frac, seed)
        report['benign_source'] = benign_source
    elif mode == 'supervised':
        splits = split_supervised(df, val_frac, test_frac, seed)
    else:
        raise ValueError(f"unknown mode {mode!r}")

    pre = FlowPreprocessor(drop_columns=drop).fit(splits['train'])
    report['features'] = pre.features_

    out_dir.mkdir(parents=True, exist_ok=True)
    report['splits'] = {}
    for name, part in splits.items():
        scaled = pre.transform(part)
        scaled[META_COLUMNS] = part[META_COLUMNS]
        scaled.reset_index(drop=True).to_parquet(out_dir / f'{name}.parquet', index=False)
        report['splits'][name] = {
            'rows': len(part),
            'categories': {k: int(v) for k, v in part['category'].value_counts().items()},
            'labels': {k: int(v) for k, v in part[LABEL].value_counts().items()},
        }
        log(f"wrote {name}.parquet: {len(part):,} rows")
    pre.save(out_dir / 'preprocessor.joblib')

    with open(out_dir / 'preprocess_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    return report


def load_split(out_dir, name):
    """Read a split written by run(): returns (X features, meta columns)."""
    df = pd.read_parquet(Path(out_dir) / f'{name}.parquet')
    return df.drop(columns=META_COLUMNS), df[META_COLUMNS]
