import pandas as pd
from sklearn.model_selection import train_test_split
from transformers import BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments
from sklearn.feature_extraction.text import TfidfVectorizer
import xgboost as xgb
import torch
import pickle
import os

def train_llm_analyzer():
    # Load dataset (e.g., Kaggle log dataset)
    data = pd.DataFrame({
        "log": ["Failed login from 192.168.1.100", "Successful login for user admin"],
        "label": [1, 0]  # 1: malicious, 0: benign
    })
    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
    model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=2)

    # Tokenize data
    encodings = tokenizer(data["log"].tolist(), truncation=True, padding=True, max_length=128)
    dataset = [{"input_ids": encodings["input_ids"][i], "attention_mask": encodings["attention_mask"][i], "labels": data["label"].iloc[i]} for i in range(len(data))]

    # Split data
    train_data, eval_data = train_test_split(dataset, test_size=0.2, random_state=42)

    training_args = TrainingArguments(
        output_dir="./bert_log_classifier",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_data,
        eval_dataset=eval_data
    )
    trainer.train()
    model.save_pretrained("bert_log_classifier")
    tokenizer.save_pretrained("bert_log_classifier")

def train_phishing_detector():
    # Load phishing dataset
    data = pd.read_csv("data/phishing_dataset.csv")  # Replace with real dataset
    vectorizer = TfidfVectorizer(max_features=5000)
    X_text = vectorizer.fit_transform(data["text"])
    X_meta = data[["sender_domain_length", "has_attachment"]]
    X = pd.concat([pd.DataFrame(X_text.toarray()), X_meta], axis=1)
    y = data["is_phishing"]
    model = xgb.XGBClassifier(random_state=42)
    model.fit(X, y)
    with open("phishing_detector.pkl", "wb") as f:
        pickle.dump(model, f)
    with open("tfidf_vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)

if __name__ == "__main__":
    os.makedirs("bert_log_classifier", exist_ok=True)
    train_llm_analyzer()
    train_phishing_detector()
