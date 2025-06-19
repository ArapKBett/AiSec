import pandas as pd
import xgboost as xgb
import pickle
import os

class AnomalyDetector:
    def __init__(self, model_path="anomaly_detector.pkl"):
        self.model_path = model_path
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = xgb.XGBClassifier(random_state=42)
            # Train with sample data (replace with real dataset)
            sample_data = pd.DataFrame({
                "action_length": [len(str(i)) for i in range(1000)],
                "resource_length": [len(str(i)) for i in range(1000)],
                "ip_numeric": [sum(int(x) for x in f"192.168.1.{i}".split(".")) for i in range(1000)]
            })
            labels = [0] * 950 + [1] * 50  # 5% anomalies
            self.model.fit(sample_data, labels)
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)

    def detect(self, features: pd.DataFrame):
        return self.model.predict(features)
