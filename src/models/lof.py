from sklearn.neighbors import LocalOutlierFactor
import numpy as np
import logging


logger = logging.getLogger(__name__)

# Default maximum training samples for LOF. LOF is O(N^2) in complexity,
# so training on more than ~30-50k rows is impractical.
DEFAULT_MAX_TRAIN_SAMPLES = 30000


class MavisLOF:
    def __init__(self, n_neighbors=20, contamination='auto', metric='minkowski', leaf_size=30, max_train_samples=DEFAULT_MAX_TRAIN_SAMPLES):
        """Local Outlier Factor for semi-supervised anomaly detection.

        Args:
            contamination: 'auto' (default) is appropriate when training on
                clean data. Avoid fixed fractions on 100% benign data.
            max_train_samples: Maximum number of training samples. If X_train
                exceeds this, it is randomly subsampled to avoid O(N^2) blowup.
        """
        # novelty=True allows us to fit on benign data and predict on new data
        self.model = LocalOutlierFactor(
            n_neighbors=n_neighbors, 
            contamination=contamination, 
            novelty=True,
            metric=metric,
            leaf_size=leaf_size,
            n_jobs=-1
        )
        self.max_train_samples = max_train_samples
        self.is_trained = False
        
    def train(self, X_train):
        """Trains the LOF model, with automatic subsampling for large datasets.

        LOF is O(N^2) in complexity. If X_train has more than max_train_samples
        rows, it is randomly subsampled to keep training tractable.
        """
        n_samples = len(X_train)

        if n_samples > self.max_train_samples:
            logger.warning(
                f"LOF training set ({n_samples} rows) exceeds max_train_samples "
                f"({self.max_train_samples}). Subsampling to {self.max_train_samples} rows."
            )
            if hasattr(X_train, 'sample'):
                # pandas DataFrame
                X_train = X_train.sample(n=self.max_train_samples, random_state=42)
            else:
                # numpy array
                rng = np.random.RandomState(42)
                indices = rng.choice(n_samples, size=self.max_train_samples, replace=False)
                X_train = X_train[indices]

        print(f"Training Local Outlier Factor on {len(X_train)} samples...")
        self.model.fit(X_train)
        self.is_trained = True
        print("Training complete.")
        
    def predict_anomaly_score(self, X):
        """
        Returns anomaly score.
        Sklearn LOF returns negative scores for outliers (lower = more abnormal).
        We invert this so higher = more anomalous.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
            
        scores = self.model.decision_function(X)
        inverted_scores = -scores
        return inverted_scores
        
    # Note: LOF with novelty=True can technically be pickled via joblib,
    # but the whole training dataset might be saved in the neighbors tree, making the file huge.
