import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self, threshold: float) -> None:
        self.threshold = threshold
        self.model = IsolationForest(contamination=0.05, random_state=42)
        baseline = np.array([[1, 0.1, 100, 10, 0.0] for _ in range(50)])
        self.model.fit(baseline)

    def score(self, features: dict) -> float:
        vector = np.array(
            [
                features["rpm"],
                features["uri_entropy"],
                features["payload_size"],
                features["header_count"],
                features["error_ratio"],
            ]
        ).reshape(1, -1)
        decision = self.model.decision_function(vector)[0]
        return float(1 - decision)

