"""
Fixtures compartidas para la suite de tests de Anzuelo.

Puntos clave:
- Cada test que necesita el backend completo (fixture `client`) corre contra
  una base de datos SQLite temporal y aislada (nunca toca anzuelo.db real).
- backend/main.py ejecuta init_db() e instancia el Limiter a nivel de módulo,
  así que para lograr aislamiento real entre tests recargamos el módulo
  (importlib.reload) después de parchear DB_PATH — esto también resetea el
  estado en memoria del rate limiter entre tests, evitando que un test
  "contamine" el límite de intentos de otro.
- No se configuran API keys de Threat Intelligence en los tests: así todas
  las integraciones externas (VirusTotal, AbuseIPDB, URLhaus) degradan sin
  intentar red, y los tests corren rápido y determinísticos incluso sin
  conexión a internet (p. ej. en CI).
"""

import importlib
import os

import pytest
from fastapi.testclient import TestClient

os.environ["ANZUELO_JWT_SECRET"] = "test-secret-not-for-production-32bytes-min"
os.environ["ANZUELO_JWT_EXPIRE_MINUTES"] = "60"
os.environ.pop("VIRUSTOTAL_API_KEY", None)
os.environ.pop("ABUSEIPDB_API_KEY", None)
os.environ.pop("ABUSECH_AUTH_KEY", None)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test_anzuelo.db"

    import backend.services.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", db_file)

    import backend.main as main_module
    importlib.reload(main_module)  # re-corre init_db() ya con el DB_PATH parcheado

    with TestClient(main_module.app) as test_client:
        yield test_client


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_token(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture()
def viewer_token(client):
    resp = client.post("/api/auth/login", json={"username": "viewer", "password": "viewer123"})
    assert resp.status_code == 200
    return resp.json()["access_token"]
