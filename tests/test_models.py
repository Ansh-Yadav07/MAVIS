import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from models import MavisAutoencoder, MavisECOD, MavisIsolationForest, MavisLOF  # noqa: E402

D = 12


@pytest.fixture(scope='module')
def data():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(400, D)).astype(np.float32)
    Xv = rng.normal(size=(100, D)).astype(np.float32)
    out = (rng.normal(size=(20, D)) * 0.5 + 8).astype(np.float32)
    return pd.DataFrame(X), pd.DataFrame(Xv), pd.DataFrame(out)


def make(name):
    if name == 'iforest':
        return MavisIsolationForest(n_estimators=30)
    if name == 'lof':
        return MavisLOF(n_neighbors=10)
    if name == 'ecod':
        return MavisECOD()
    return MavisAutoencoder(D, learning_rate=1e-2, dropout=0.0)


def fit(name, m, X, Xv):
    if name == 'ae':
        m.fit(X, X_val=Xv, epochs=15, batch_size=64, patience=3)
    else:
        m.fit(X)
    return m


@pytest.fixture(scope='module', params=['iforest', 'lof', 'ae', 'ecod'])
def trained(request, data):
    X, Xv, _ = data
    return request.param, fit(request.param, make(request.param), X, Xv)


def test_scores_shape_and_outliers(trained, data):
    _, m = trained
    X, _, out = data
    s = m.predict_anomaly_score(X)
    assert isinstance(s, np.ndarray) and s.shape == (len(X),) and s.ndim == 1
    assert np.isfinite(s).all()
    assert m.predict_anomaly_score(out).mean() > s.mean()
    # numpy input gives the same result as a DataFrame
    np.testing.assert_allclose(m.predict_anomaly_score(X.to_numpy()), s, rtol=1e-5, atol=1e-6)


def test_save_load_roundtrip(trained, data, tmp_path):
    _, m = trained
    X, _, out = data
    path = tmp_path / 'model.bin'
    m.save(path)
    m2 = type(m).load(path)
    both = pd.concat([X, out])
    np.testing.assert_allclose(m2.predict_anomaly_score(both), m.predict_anomaly_score(both), rtol=1e-5, atol=1e-6)


def test_train_alias(data):
    X, _, _ = data
    m = MavisIsolationForest(n_estimators=5)
    m.train(X)
    assert m.is_trained


def test_autoencoder_feature_errors(data, tmp_path):
    X, Xv, out = data
    m = fit('ae', make('ae'), X, Xv)
    fe = m.feature_errors(out)
    assert fe.shape == (len(out), D) and (fe >= 0).all()
    np.testing.assert_allclose(fe.mean(axis=1), m.predict_anomaly_score(out), rtol=1e-4, atol=1e-6)
    m.save(tmp_path / 'ae.pt')
    m2 = MavisAutoencoder.load(tmp_path / 'ae.pt')
    assert m2.input_dim == D
    np.testing.assert_allclose(m2.feature_errors(out), fe, rtol=1e-5, atol=1e-6)


def test_untrained_raises():
    with pytest.raises(ValueError):
        MavisIsolationForest().predict_anomaly_score(np.zeros((2, D)))


def test_ecod_feature_scores_and_ties(data):
    X, _, out = data
    m = MavisECOD().fit(X)
    fs = m.feature_scores(out)
    assert fs.shape == (len(out), D) and np.isfinite(fs).all() and (fs >= 0).all()
    assert fs.mean() > m.feature_scores(X).mean()
    # constant feature in training data: same value typical, different value maximally unusual
    Xc = X.copy()
    Xc[0] = 1.0
    mc = MavisECOD().fit(Xc)
    probe = np.zeros((2, D), dtype=np.float32)
    probe[1, 0] = 5.0
    s = mc.predict_anomaly_score(np.where(np.arange(D) == 0, probe, 0.0))
    assert s[1] > s[0]
