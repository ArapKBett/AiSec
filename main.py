from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
from models.anomaly_detector import AnomalyDetector
from models.llm_analyzer import LLMAnalyzer
from models.phishing_detector import PhishingDetector
from models.behavior_analytics import BehaviorAnalytics

app = FastAPI(title="AI-Powered Cybersecurity Program")

# Pydantic models for request/response
class LogEntry(BaseModel):
    log: str

class EmailContent(BaseModel):
    email: str

class UserActivity(BaseModel):
    user_id: str
    timestamp: str
    action: str
    resource: str

# Initialize models
anomaly_detector = AnomalyDetector()
llm_analyzer = LLMAnalyzer()
phishing_detector = PhishingDetector()
behavior_analytics = BehaviorAnalytics()

@app.post("/analyze_log")
async def analyze_log(entry: LogEntry):
    try:
        result = llm_analyzer.analyze_log(entry.log)
        return {"log": entry.log, "is_malicious": result["is_malicious"], "confidence": result["confidence"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/detect_anomaly")
async def detect_anomaly(activity: UserActivity):
    try:
        features = pd.DataFrame([{
            "action_length": len(activity.action),
            "resource_length": len(activity.resource)
        }])
        is_anomaly = anomaly_detector.detect(features)
        return {"user_id": activity.user_id, "is_anomaly": bool(is_anomaly[0] == -1)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/detect_phishing")
async def detect_phishing(content: EmailContent):
    try:
        result = phishing_detector.detect(content.email)
        return {"email": content.email, "is_phishing": result["is_phishing"], "confidence": result["confidence"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze_behavior")
async def analyze_behavior(activity: UserActivity):
    try:
        result = behavior_analytics.analyze(pd.DataFrame([activity.dict()]))
        return {"user_id": activity.user_id, "is_suspicious": result["is_suspicious"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
