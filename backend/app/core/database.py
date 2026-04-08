"""SQLite database setup for scan logs."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import os
from backend.app.core.config import BASE_DIR

if os.getenv("VERCEL") == "1":
    DB_PATH = Path("/tmp/shieldyono.db")
else:
    DB_PATH = BASE_DIR / "shieldyono.db"
_local = threading.local()


def get_connection() -> sqlite3.Connection:
    """Thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            resolved_url TEXT,
            risk_score REAL,
            risk_tier TEXT,
            verdict TEXT,
            confidence REAL,
            reasons TEXT,
            features TEXT,
            scanned_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_logs(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_logs(scanned_at);
        CREATE INDEX IF NOT EXISTS idx_risk_tier ON scan_logs(risk_tier);
    """)
    conn.commit()


def insert_scan(scan_data: dict):
    """Insert a scan result into the database."""
    import json
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO scan_logs 
        (scan_id, url, resolved_url, risk_score, risk_tier, verdict, confidence, reasons, features, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data["scan_id"],
        scan_data["url"],
        scan_data.get("resolved_url", ""),
        scan_data.get("risk_score", 0),
        scan_data.get("risk_tier", "UNKNOWN"),
        scan_data.get("verdict", ""),
        scan_data.get("confidence", 0),
        json.dumps(scan_data.get("reasons", [])),
        json.dumps(scan_data.get("features", {})),
        scan_data.get("scanned_at", datetime.now(timezone.utc).isoformat()),
    ))
    conn.commit()


def get_recent_scans(limit: int = 20) -> list[dict]:
    """Fetch recent scan records."""
    import json
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_logs ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d["reasons"] = json.loads(d.get("reasons", "[]"))
        d["features"] = json.loads(d.get("features", "{}"))
        results.append(d)
    return results


def get_analytics() -> dict:
    """Dashboard analytics summary."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as c FROM scan_logs").fetchone()["c"]
    safe = conn.execute("SELECT COUNT(*) as c FROM scan_logs WHERE risk_tier='SAFE'").fetchone()["c"]
    suspicious = conn.execute("SELECT COUNT(*) as c FROM scan_logs WHERE risk_tier='SUSPICIOUS'").fetchone()["c"]
    phishing = conn.execute("SELECT COUNT(*) as c FROM scan_logs WHERE risk_tier='PHISHING'").fetchone()["c"]
    avg_score = conn.execute("SELECT AVG(risk_score) as a FROM scan_logs").fetchone()["a"] or 0
    return {
        "total_scans": total,
        "safe_count": safe,
        "suspicious_count": suspicious,
        "phishing_count": phishing,
        "avg_risk_score": round(avg_score, 1),
    }
