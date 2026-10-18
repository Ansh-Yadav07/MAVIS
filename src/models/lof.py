from sklearn.neighbors import LocalOutlierFactor
import numpy as np
import joblib
import logging

from ._util import batched, to_numpy

logger = logging.getLogger(__name__)

# LOF scoring cost grows with the stored training set; see scripts/train_evaluate.py.
DEFAULT_MAX_TRAIN_SAMPLES = 30000


class MavisLOF:
    def __init__(self, n_neighbors=20, contamination='auto', metric='minkowski', leaf_size=30,
                 max_train_samples=DEFAULT_MAX_TRAIN_SAMPLES, random_state=42):
        """Local Outlier Factor (novelty=True) fitted on benign data.

        If the training set exceeds max_train_samples it is randomly subsampled.
        """
        self.params = dict(n_neighbors=n_neighbors, contamination=contamination, metric=metric,
                           leaf_size=leaf_size, max_train_samples=max_train_samples,
                           random_state=random_state)
        self.model = self._make_model()
        self.max_train_samples = max_train_samples
        self.random_state = random_state
        self.is_trained = False

    def _make_model(self):
        p = self.params
        return LocalOutlierFactor(n_neighbors=p['n_neighbors'], contamination=p['contamination'],
                                  novelty=True, metric=p['metric'], leaf_size=p['leaf_size'], n_jobs=-1)

    def fit(self, X, y=None):
        X = to_numpy(X)
        n = len(X)
        if n > self.max_train_samples:
            logger.warning(f"LOF: subsampling {n} -> {self.max_train_samples} rows")
            idx = np.random.RandomState(self.random_state).choice(n, self.max_train_samples, replace=False)
            X = X[idx]
        print(f"Training Local Outlier Factor on {len(X)} samples...")
        self.model.fit(X)
        self.is_trained = True
        print("Training complete.")
        return self

    def train(self, X_train):
        """Backward-compatible alias for fit()."""
        return self.fit(X_train)

    def predict_anomaly_score(self, X, batch_size=50_000):
        """1-D float array; higher = more anomalous (negated sklearn decision_function)."""
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        return batched(lambda b: -self.model.decision_function(b), X, batch_size)

    def save(self, filepath):
        joblib.dump({'params': self.params, 'model': self.model}, filepath)

    @classmethod
    def load(cls, filepath):
        obj = joblib.load(filepath)
        inst = cls(**obj['params'])
        inst.model = obj['model']
        inst.is_trained = True
        return inst
