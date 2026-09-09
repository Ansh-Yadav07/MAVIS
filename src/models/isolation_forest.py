from sklearn.ensemble import IsolationForest
import joblib


class MavisIsolationForest:
    def __init__(self, n_estimators=100, contamination='auto', random_state=42):
        """Isolation Forest for semi-supervised anomaly detection.

        Args:
            contamination: 'auto' (default) is appropriate when training on
                clean data. Sklearn computes the threshold from the training
                data distribution. Avoid setting a fixed fraction (e.g. 0.01)
                when the training set is known to be 100% benign.
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.is_trained = False
        
    def train(self, X_train):
        """
        Trains the Isolation Forest model.
        X_train should be mostly benign traffic.
        """
        print("Training Isolation Forest...")
        self.model.fit(X_train)
        self.is_trained = True
        print("Training complete.")
        
    def predict_anomaly_score(self, X):
        """
        Returns anomaly score. 
        Note: Sklearn's IF returns negative scores for anomalies (lower = more anomalous).
        We invert this so higher = more anomalous, matching MAVIS threat score logic.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained yet.")
        
        # decision_function: The anomaly score of the input samples. 
        # The lower, the more abnormal.
        scores = self.model.decision_function(X)
        
        # Invert scores: higher score = more anomalous
        inverted_scores = -scores
        return inverted_scores
        
    def save(self, filepath):
        joblib.dump(self.model, filepath)
        
    def load(self, filepath):
        self.model = joblib.load(filepath)
        self.is_trained = True
