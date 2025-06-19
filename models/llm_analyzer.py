from transformers import BertTokenizer, BertForSequenceClassification, pipeline
import torch
import os

class LLMAnalyzer:
    def __init__(self, model_path="bert_log_classifier"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        if os.path.exists(model_path):
            self.model = BertForSequenceClassification.from_pretrained(model_path).to(self.device)
            self.tokenizer = BertTokenizer.from_pretrained(model_path)
        else:
            self.model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=2).to(self.device)
            self.tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
            # Placeholder for fine-tuning (run scripts/train_models.py)
        self.classifier = pipeline(
            "text-classification",
            model=self.model,
            tokenizer=self.tokenizer,
            device=0 if torch.cuda.is_available() else -1
        )

    def analyze_log(self, log: str):
        result = self.classifier(log)[0]
        is_malicious = result["label"] == "LABEL_1"  # LABEL_1: malicious
        return {"is_malicious": is_malicious, "confidence": result["score"]}
