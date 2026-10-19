import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from data.cic import FEATURES  # noqa: E402
from data.preprocess import FlowPreprocessor  # noqa: E402
from engine import MavisEngine, PercentileMap, analyze, oversample_rare, severity_for  # noqa: E402
from engine.engine import MODEL_NAMES  # noqa: E402


class NormModel:
    """Stand-in anomaly model: distance from the origin of a few feature columns."""

    def __init__(self, cols):
        self.cols = cols

    def predict_anomaly_score(self, X):
        return np.sqrt((np.asarray(X, dtype=np.float64)[:, self.cols] ** 2).sum(axis=1))


def _raw_flows(n, family, rng):
    """Raw (unscaled) flows; attacks inflate one block of features."""
    data = rng.lognormal(3, 1, size=(n, len(FEATURES)))
    shift = {'DoS': slice(0, 10), 'PortScan': slice(20, 30), 'Bot': slice(40, 50)}.get(family)
    if shift:
        data[:, shift] *= 60
    df = pd.DataFrame(data, columns=FEATURES)
    df['Label'] = 'BENIGN' if family == 'Benign' else family
    return df


@pytest.fixture(scope='module')
def fitted():
    rng = np.random.default_rng(0)
    parts = [_raw_flows(4000, 'Benign', rng)] + [_raw_flows(400, f, rng) for f in ('DoS', 'PortScan', 'Bot')]
    raw = pd.concat(parts, ignore_index=True)
    pre = FlowPreprocessor().fit(raw[raw['Label'] == 'BENIGN'])
    X = pre.transform(raw)
    y = raw['Label'].replace({'BENIGN': 'Benign'}).to_numpy().astype(object)
    models = {n: NormModel(list(range(lo, hi))) for n, (lo, hi) in zip(MODEL_NAMES, [(0, 69), (0, 50), (20, 69), (10, 60)])}
    eng = MavisEngine(models, pre)
    idx = rng.permutation(len(X))
    tr, cal, ev = idx[:2000], idx[2000:3500], idx[3500:]
    scores = eng.model_scores(X)
    part = lambda ix: (X.iloc[ix], y[ix], {n: s[ix] for n, s in scores.items()})  # noqa: E731
    eng.fit(*part(tr), *part(cal), target_fpr=0.02, log=lambda *_: None)
    return eng, X, y, ev, raw, models, pre, part, tr, cal


def test_percentile_map_monotone_and_bounded():
    pm = PercentileMap(np.r_[np.zeros(50), np.arange(100.0)])
    p = pm(np.array([-5, 0, 50, 99, 1e9]))
    assert p[0] == 0 and p[-1] == 1 and np.all(np.diff(p) >= 0)


def test_severity_bands():
    assert severity_for(10, 20) == 'None'
    assert severity_for(25, 20) == 'Low'
    assert severity_for(90, 20) == 'Critical'


def test_oversample_only_rare_classes():
    X = np.random.default_rng(1).normal(size=(130, 4)).astype(np.float32)
    y = np.array(['Benign'] * 100 + ['Bot'] * 30, dtype=object)
    Xa, ya, added = oversample_rare(X, y, min_count=50)
    assert added == {'Bot': 20} and len(Xa) == 150 and (ya == 'Bot').sum() == 50
    bot = X[100:]
    assert Xa[130:].min() >= bot.min() - 1e-6 and Xa[130:].max() <= bot.max() + 1e-6  # interpolations


def test_engine_detects_and_names_attacks(fitted):
    eng, X, y, ev, *_ = fitted
    flows = eng.score(X.iloc[ev])
    yy = y[ev]
    alert = flows['verdict'] != 'normal'
    assert alert[yy != 'Benign'].mean() > 0.9
    assert alert[yy == 'Benign'].mean() < 0.08
    named = flows['threat_family'][(yy == 'DoS') & alert]
    assert (named == 'DoS').mean() > 0.9
    assert set(flows['severity']) <= {'None', 'Low', 'Medium', 'High', 'Critical'}
    assert flows['risk_score'].between(0, 100).all()


def test_unseen_family_flagged_as_novel(fitted):
    eng, X, y, ev, raw, models, pre, part, tr, cal = fitted
    eng2 = MavisEngine(models, pre).fit(*part(tr), *part(cal), target_fpr=0.02,
                                        exclude_categories=['Bot'], log=lambda *_: None)
    flows = eng2.score(X.iloc[ev])
    bot = y[ev] == 'Bot'
    assert (flows['verdict'][bot] != 'normal').mean() > 0.8
    # the anomaly path must fire on the unseen family, whatever name the classifier guesses
    assert flows['detection_mode'][bot].isin(['novel', 'known+novel']).mean() > 0.5


def test_analyze_handles_messy_input(fitted):
    eng, *_ , raw, models, pre, part, tr, cal = fitted
    messy = raw.sample(500, random_state=0).drop(columns=['Flow IAT Min'])
    messy = messy.rename(columns={'Destination Port': ' Dst Port', 'Flow Duration': 'flow_duration'})
    messy.iloc[0, 3] = np.inf
    messy['Src IP'] = np.where(messy['Label'] == 'BENIGN', '10.0.0.5', '172.16.0.1')
    report, flows = analyze(eng, messy, max_explanations=20)
    assert report['summary']['flows'] == 500 and len(flows) == 500
    assert report['data_quality']['missing_feature_columns'] == ['Flow IAT Min']
    assert report['data_quality']['rows_with_missing_or_infinite_values'] >= 1
    assert report['incidents'] and 'src_ip' in report['incidents'][0]
    assert report['top_alerts'][0]['why'] and report['top_alerts'][0]['actions']
    assert 'ground_truth' in report and report['insights']


def test_analyze_empty_and_unlabelled(fitted):
    eng, *_, raw, models, pre, part, tr, cal = fitted
    report, flows = analyze(eng, raw.iloc[:0])
    assert report['summary']['flows'] == 0
    report, _ = analyze(eng, raw.drop(columns=['Label']).head(50))
    assert 'ground_truth' not in report


def test_drift_detects_shifted_traffic(fitted):
    eng, X, y, *_ = fitted
    benign = X[y == 'Benign']
    assert eng.drift(benign, np.ones(len(benign), bool), min_rows=500)['status'] == 'stable'
    shifted = benign + 3.0
    assert eng.drift(shifted, np.ones(len(benign), bool), min_rows=500)['status'] == 'retrain-recommended'
