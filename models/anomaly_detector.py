from sklearn.ensemble import IsolationForest
import pandas as pd

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        # Train with sample data
        sample_data = pd.DataFrame({
            "action_length": [len(str(i)) for i in range(100)],
            "resource_length": [len(str(i)) for i in range(100)]
        })
        self.model.fit(sample_data)

    def detect(self, features: pd.DataFrame):
        return self.model.predict(features)
