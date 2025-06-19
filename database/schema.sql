CREATE TABLE IF NOT EXISTS log_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log TEXT NOT NULL,
    is_malicious BOOLEAN NOT NULL,
    confidence FLOAT NOT NULL,
    timestamp DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    is_anomaly BOOLEAN,
    timestamp_recorded DATETIME NOT NULL
);
