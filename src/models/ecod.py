"""ECOD: empirical-cumulative-distribution outlier detection (Li et al., 2022), implemented from scratch.

Per feature it estimates the left and right tail probabilities of a value from benign training data;
the anomaly score is the sum over features of -log(tail probability), using the tail the data are
skewed towards ("auto") and the max of left-only, right-only and auto sums. Parameter-free, very
fast, and the per-feature tail scores explain *which* features make a flow unusual.

The training ECDF is stored as a compact quantile grid per feature (dense in the tails), not the raw rows.
"""
import joblib
import numpy as np

from ._util import batched, to_numpy

_BODY = np.linspace(0.001, 0.999, 999)
_TAIL = np.logspace(-6, -3, 40)
_GRID = np.unique(np.concatenate([[0.0], _TAIL, _BODY, 1 - _TAIL, [1.0]]))


class MavisECOD:
    def __init__(self):
        self.params = {}
        self.is_trained = False
        self.n_train = 0

    def fit(self, X, y=None):
        """Fit the per-feature ECDFs on (mostly) benign traffic."""
        print("Fitting ECOD...")
        A = to_numpy(X, np.float64)
        self.n_train = len(A)
        qs = np.quantile(A, _GRID, axis=0)                      # (grid, d)
        self.skew = self._skew(A)
        self._build(qs)
        self.is_trained = True
        print("ECOD fitted.")
        return self

    @staticmethod
    def _skew(A):
        m, s = A.mean(axis=0), A.std(axis=0)
        return np.where(s > 0, ((A - m) ** 3).mean(axis=0) / np.maximum(s, 1e-12) ** 3, 0.0)

    def _build(self, qs):
        """Per feature: distinct quantile values with P(X<=v) (hi) and P(X<v) (lo)."""
        self.knots = []
        for j in range(qs.shape[1]):
            q = qs[:, j]
            u, first = np.unique(q, return_index=True)
            last = np.append(first[1:], len(q)) - 1
            self.knots.append((u, _GRID[last], _GRID[first]))   # values, hi, lo

    def train(self, X_train):
        """Backward-compatible alias for fit()."""
        return self.fit(X_train)

    def _tails(self, A):
        n, d = A.shape
        eps = 0.5 / max(self.n_train, 1)
        left, right = np.empty((n, d)), np.empty((n, d))
        for j, (u, hi, lo) in enumerate(self.knots):
            x = A[:, j]
            if len(u) == 1:   # constant feature: anything equal is typical, anything else maximally unusual
                same = x == u[0]
                fl = np.where(same, 1.0, np.where(x < u[0], 0.0, 1.0))
                fr = np.where(same, 1.0, np.where(x > u[0], 0.0, 1.0))
            else:
                fl = np.interp(x, u, hi)              # P(X <= x)
                fr = 1 - np.interp(x, u, lo)          # P(X >= x)
            left[:, j], right[:, j] = fl, fr
        return -np.log(np.clip(left, eps, 1)), -np.log(np.clip(right, eps, 1))

    def feature_scores(self, X):
        """(n, d) per-feature tail scores (the skew-chosen tail), for explanations."""
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        ol, orr = self._tails(to_numpy(X, np.float64))
        return np.where(self.skew < 0, ol, orr)

    def _score_batch(self, A):
        ol, orr = self._tails(A)
        auto = np.where(self.skew < 0, ol, orr)
        return np.maximum(np.maximum(ol.sum(axis=1), orr.sum(axis=1)), auto.sum(axis=1))

    def predict_anomaly_score(self, X, batch_size=100_000):
        """1-D float array; higher = more anomalous."""
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        return batched(lambda b: self._score_batch(b.astype(np.float64)), X, batch_size)

    def save(self, filepath):
        joblib.dump({'knots': self.knots, 'skew': self.skew, 'n_train': self.n_train}, filepath)

    @classmethod
    def load(cls, filepath):
        obj = joblib.load(filepath)
        inst = cls()
        inst.knots, inst.skew, inst.n_train = obj['knots'], obj['skew'], obj['n_train']
        inst.is_trained = True
        return inst
