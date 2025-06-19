from sklearn.feature_extraction.text import TfidfVectorizer
import xgboost as xgb
import pandas as pd
import pickle
import os

class PhishingDetector:
    def __init__(self, model_path="phishing_detector.pkl", vectorizer_path="tfidf_vectorizer.pkl"):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            with open(vectorizer_path, "rb") as f:
                self.vectorizer = pickle.load(f)
        else:
            self.vectorizer = TfidfVectorizer(max_features=5000)
            self.model = xgb.XGBClassifier(random_state=42)
            # Train with sample data (replace with real dataset)
            emails = pd.DataFrame({
                "text": ["win free money click here", "team meeting at 10am", "urgent account locked"],
                "sender_domain_length": [10, 15, 12],
                "has_attachment": [1, 0, 1]
            })
            labels = [1, 0, 1]
            X_text = self.vectorizer.fit_transform(emails["text"])
            X_meta = emails[["sender_domain_length", "has_attachment"]].values
            X = pd.concat([pd.DataFrame(X_text.toarray()), pd.DataFrame(X_meta)], axis=1)
            self.model.fit(X, labels)
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
            with open(vectorizer_path, "wb") as f:
                pickle.dump(self.vectorizer, f)

    def detect(self, email: str):
        # Simplified: assumes email is text-only (extend with metadata)
        X_text = self.vectorizer.transform([email])
        X_meta = pd.DataFrame([[10, 0]], columns=["sender_domain_length", "has_attachment"])
        X = pd.concat([pd.DataFrame(X_text.toarray()), X_meta], axis=1)
        prob = self.model.predict_proba(X)[0][1]
        return {"is_phishing": prob > 0.5, "confidence": float(prob)}
