from sklearn.ensemble import IsolationForest
import joblib

from ._util import batched, to_numpy


class MavisIsolationForest:
    def __init__(self, n_estimators=300, max_samples=0.75, max_features=0.5, bootstrap=False,
                 contamination='auto', random_state=42):
        """Isolation Forest for semi-supervised anomaly detection (train on benign only).

        contamination='auto' is appropriate for 100% benign training data.
        """
        self.params = dict(n_estimators=n_estimators, max_samples=max_samples, max_features=max_features,
                           bootstrap=bootstrap, contamination=contamination, random_state=random_state)
        self.model = IsolationForest(n_jobs=-1, **self.params)
        self.is_trained = False

    def fit(self, X, y=None):
        """Fit on (mostly) benign traffic."""
        print("Training Isolation Forest...")
        self.model.fit(to_numpy(X))
        self.is_trained = True
        print("Training complete.")
        return self

    def train(self, X_train):
        """Backward-compatible alias for fit()."""
        return self.fit(X_train)

    def predict_anomaly_score(self, X, batch_size=100_000):
        """1-D float array; higher = more anomalous (negated sklearn decision_function)."""
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        return batched(lambda b: -self.model.decision_function(b), X, batch_size)

    def save(self, filepath):
        joblib.dump({'params': self.params, 'model': self.model}, filepath)

    @classmethod
    def load(cls, filepath):
        obj = joblib.load(filepath)
        if not isinstance(obj, dict):  # legacy: bare sklearn model
            obj = {'params': {}, 'model': obj}
        inst = cls(**obj['params'])
        inst.model = obj['model']
        inst.is_trained = True
        return inst
