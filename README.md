# Production-Grade AI Cybersecurity Program
A FastAPI-based application for incident analysis, threat detection, log analysis, phishing detection, and user behavior analytics.

## Setup (Local PC)
1. Clone the repo: `git clone <your-repo-url>`
2. Install dependencies: `pip install -r requirements.txt`
3. Initialize DB: `python -c "from database.db import init_db; init_db()"`
4. Train models: `python scripts/train_models.py`
5. Run: `python main.py`

## Authentication
- Obtain token: `curl -X POST http://localhost:8000/token -d "username=admin&password=secret"`
- Use token in requests: `-H "Authorization: Bearer <token>"`

## Setup (Render)
1. Push code to a GitHub repo.
2. Create a new Web Service on Render, linking to your repo.
3. Set environment to Docker, port 8000.
4. Add env variable: `SECRET_KEY=your-secret-key`
5. Deploy.

## Endpoints
- POST /token: Get JWT token.
- POST /analyze_log: Analyze logs using BERT.
- POST /detect_anomaly: Detect anomalies using XGBoost.
- POST /detect_phishing: Detect phishing emails using XGBoost.
- POST /analyze_behavior: Analyze user behavior using Isolation Forest.
- GET /health: Check server status.
