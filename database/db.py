import sqlite3
from contextlib import contextmanager

@contextmanager
def get_db():
    conn = sqlite3.connect("cybersecurity.db")
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as db:
        with open("database/schema.sql", "r") as f:
            db.executescript(f.read())

def log_analysis_result(db, log: str, is_malicious: bool, confidence: float):
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO log_analysis (log, is_malicious, confidence, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (log, is_malicious, confidence)
    )
    db.commit()
