import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle
import os

class BehaviorAnalytics:
    def __init__(self, model_path="behavior_analytics.pkl"):
        self.model_path = model_path
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            # Train with sample data
            sample_data = pd.DataFrame({
                "action_length": [len(str(i)) for i in range(1000)],
                "resource_length": [len(str(i)) for i in range(1000)],
                "ip_numeric": [sum(int(x) for x in f"192.168.1.{i}".split(".")) for i in range(1000)],
                "hour_of_day": [i % 24 for i in range(1000)]
            })
            self.model.fit(sample_data)
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)

    def analyze(self, activity: pd.DataFrame):
        features = activity[["action_length", "resource_length", "ip_numeric", "hour_of_day"]] if "hour_of_day" in activity else pd.DataFrame({
            "action_length": [len(activity["action"].iloc[0])],
            "resource_length": [len(activity["resource"].iloc[0])],
            "ip_numeric": [activity["ip_numeric"].iloc[0]],
            "hour_of_day": [int(activity["timestamp"].iloc[0].split(" ")[1].split(":")[0])]
        })
        is_anomaly = self.model.predict(features)[0] == -1
        return {"is_suspicious": is_anomaly}
