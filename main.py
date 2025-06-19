from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import pandas as pd
from models.anomaly_detector import AnomalyDetector
from models.llm_analyzer import LLMAnalyzer
from models.phishing_detector import PhishingDetector
from models.behavior_analytics import BehaviorAnalytics
from utils.auth import verify_token, create_access_token
from utils.logger import setup_logger
from database.db import get_db, log_analysis_result
import structlog

app = FastAPI(title="Production-Grade AI Cybersecurity Program")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
logger = setup_logger()

# Pydantic models
class LogEntry(BaseModel):
    log: str

class EmailContent(BaseModel):
    email: str

class UserActivity(BaseModel):
    user_id: str
    timestamp: str
    action: str
    resource: str
    ip_address: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Initialize models
anomaly_detector = AnomalyDetector()
llm_analyzer = LLMAnalyzer()
phishing_detector = PhishingDetector()
behavior_analytics = BehaviorAnalytics()

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Simplified authentication (replace with real user DB check)
    if form_data.username == "admin" and form_data.password == "secret":
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Invalid credentials")

@app.post("/analyze_log")
async def analyze_log(entry: LogEntry, token: str = Depends(oauth2_scheme)):
    logger.info("Analyzing log", log=entry.log)
    try:
        verify_token(token)
        result = llm_analyzer.analyze_log(entry.log)
        # Store result in DB
        with get_db() as db:
            log_analysis_result(db, entry.log, result["is_malicious"], result["confidence"])
        return {"log": entry.log, "is_malicious": result["is_malicious"], "confidence": result["confidence"]}
    except Exception as e:
        logger.error("Error analyzing log", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/detect_anomaly")
async def detect_anomaly(activity: UserActivity, token: str = Depends(oauth2_scheme)):
    logger.info("Detecting anomaly", user_id=activity.user_id)
    try:
        verify_token(token)
        features = pd.DataFrame([{
            "action_length": len(activity.action),
            "resource_length": len(activity.resource),
            "ip_numeric": sum(int(x) for x in activity.ip_address.split("."))
        }])
        is_anomaly = anomaly_detector.detect(features)
        return {"user_id": activity.user_id, "is_anomaly": bool(is_anomaly[0] == -1)}
    except Exception as e:
        logger.error("Error detecting anomaly", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/detect_phishing")
async def detect_phishing(content: EmailContent, token: str = Depends(oauth2_scheme)):
    logger.info("Detecting phishing", email=content.email[:50])
    try:
        verify_token(token)
        result = phishing_detector.detect(content.email)
        return {"email": content.email, "is_phishing": result["is_phishing"], "confidence": result["confidence"]}
    except Exception as e:
        logger.error("Error detecting phishing", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze_behavior")
async def analyze_behavior(activity: UserActivity, token: str = Depends(oauth2_scheme)):
    logger.info("Analyzing behavior", user_id=activity.user_id)
    try:
        verify_token(token)
        features = pd.DataFrame([{
            "user_id": activity.user_id,
            "action_length": len(activity.action),
            "resource_length": len(activity.resource),
            "ip_numeric": sum(int(x) for x in activity.ip_address.split("."))
        }])
        result = behavior_analytics.analyze(features)
        return {"user_id": activity.user_id, "is_suspicious": result["is_suspicious"]}
    except Exception as e:
        logger.error("Error analyzing behavior", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
