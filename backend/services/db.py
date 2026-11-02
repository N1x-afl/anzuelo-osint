import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent.parent.parent / "anzuelo.db"

# Perfiles demo — mismas credenciales que ya estaban documentadas en el README
# (ver sección "Notas de Seguridad"). Solo se usan para sembrar la tabla la
# primera vez que se crea; a partir de ahí, cambiar la clave desde la UI
# ("Clave" → Cambiar Contraseña) actualiza el hash real en SQLite.
_DEFAULT_USERS = [
    ("admin", "admin123", "admin"),
    ("analista", "analista123", "analista"),
    ("viewer", "viewer123", "viewer"),
]


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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Import diferido para evitar un ciclo de importación (auth.py importa db.py)
        from backend.services.auth import hash_password
        for username, password, role in _DEFAULT_USERS:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hash_password(password), role),
            )
        conn.commit()

    conn.close()


def get_user_by_username(username: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None
        return {"username": r["username"], "password_hash": r["password_hash"], "role": r["role"]}
    except Exception as e:
        print(f"[DB ERROR] Error al consultar usuario '{username}': {e}")
        return None


def update_user_password(username: str, new_password_hash: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
        conn.commit()
        updated = cursor.rowcount > 0
        conn.close()
        return updated
    except Exception as e:
        print(f"[DB ERROR] Error al actualizar clave de '{username}': {e}")
        return False

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

def get_incident_by_id(incident_id: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, vector, target, verdict, risk_score, details_json
            FROM incidents
            WHERE id = ?
        """, (incident_id,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None
        return {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "vector": r["vector"],
            "target": r["target"],
            "verdict": r["verdict"],
            "risk_score": r["risk_score"],
            "details": json.loads(r["details_json"])
        }
    except Exception as e:
        print(f"[DB ERROR] Error al consultar incidente #{incident_id}: {e}")
        return None

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
