import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent.parent.parent / "anzuelo.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            vector TEXT NOT NULL,
            target TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            details_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_incident(vector: str, target: str, verdict: str, risk_score: int, details: dict):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO incidents (timestamp, vector, target, verdict, risk_score, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (now, vector, target[:300], verdict, risk_score, json.dumps(details)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] Error al guardar incidente: {e}")

def get_recent_incidents(limit: int = 50):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, vector, target, verdict, risk_score, details_json 
            FROM incidents 
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "vector": r["vector"],
                "target": r["target"],
                "verdict": r["verdict"],
                "risk_score": r["risk_score"],
                "details": json.loads(r["details_json"])
            })
        conn.close()
        return results
    except Exception as e:
        print(f"[DB ERROR] Error al consultar historial: {e}")
        return []

def clear_all_incidents():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM incidents")
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False
