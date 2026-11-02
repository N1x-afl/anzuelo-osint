"""
Tests de integración contra la API completa (FastAPI TestClient), cubriendo
autenticación, control de roles, rate limiting y los flujos de análisis/
historial/export de punta a punta — usando la base de datos temporal aislada
que arma conftest.py.

Se usa el vector SMS para los análisis: a diferencia de email/URL, no dispara
consultas WHOIS (que si intentarían red real), así que estos tests corren
limpios incluso sin conectividad.
"""

def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------

def test_protected_endpoint_without_token_returns_401(client):
    resp = client.get("/api/history")
    assert resp.status_code == 401


def test_login_wrong_password_returns_401(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "incorrecta"})
    assert resp.status_code == 401


def test_login_unknown_user_returns_401(client):
    resp = client.post("/api/auth/login", json={"username": "no-existe", "password": "x"})
    assert resp.status_code == 401


def test_login_success_returns_jwt(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"
    assert len(data["access_token"]) > 20


def test_me_endpoint_reflects_logged_in_user(client, admin_token):
    resp = client.get("/api/auth/me", headers=auth_headers(admin_token))
    assert resp.status_code == 200
    assert resp.json() == {"username": "admin", "role": "admin"}


def test_me_endpoint_rejects_garbage_token(client):
    resp = client.get("/api/auth/me", headers=auth_headers("esto-no-es-un-jwt"))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Control de roles
# ---------------------------------------------------------------------------

def test_viewer_cannot_clear_history(client, viewer_token):
    resp = client.delete("/api/history", headers=auth_headers(viewer_token))
    assert resp.status_code == 403


def test_admin_can_clear_history(client, admin_token):
    resp = client.delete("/api/history", headers=auth_headers(admin_token))
    assert resp.status_code == 200
    assert resp.json()["success"] is True


def test_viewer_can_still_read_history(client, viewer_token):
    resp = client.get("/api/history", headers=auth_headers(viewer_token))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Cambio de contraseña
# ---------------------------------------------------------------------------

def test_change_password_flow(client, admin_token):
    resp = client.post(
        "/api/auth/change-password",
        headers=auth_headers(admin_token),
        json={"current_password": "admin123", "new_password": "nuevaClaveSegura456"},
    )
    assert resp.status_code == 200

    # la clave vieja ya no sirve
    old_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert old_login.status_code == 401

    # la clave nueva sí
    new_login = client.post("/api/auth/login", json={"username": "admin", "password": "nuevaClaveSegura456"})
    assert new_login.status_code == 200


def test_change_password_wrong_current_password(client, admin_token):
    resp = client.post(
        "/api/auth/change-password",
        headers=auth_headers(admin_token),
        json={"current_password": "no-es-esta", "new_password": "nuevaClaveSegura456"},
    )
    # 400 (clave actual incorrecta), no 401: el JWT es válido, no se trata
    # de una sesión inválida/expirada.
    assert resp.status_code == 400


def test_change_password_too_short_is_rejected(client, admin_token):
    resp = client.post(
        "/api/auth/change-password",
        headers=auth_headers(admin_token),
        json={"current_password": "admin123", "new_password": "abc"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_login_rate_limited_after_5_attempts_per_minute(client):
    for _ in range(5):
        resp = client.post("/api/auth/login", json={"username": "admin", "password": "mal"})
        assert resp.status_code == 401

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "mal"})
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Análisis + historial + export (vector SMS: no toca red externa)
# ---------------------------------------------------------------------------

def test_analyze_sms_requires_auth(client):
    resp = client.post("/api/analyze/sms", json={"message": "hola"})
    assert resp.status_code == 401


def test_analyze_sms_creates_incident_visible_in_history(client, admin_token):
    resp = client.post(
        "/api/analyze/sms",
        headers=auth_headers(admin_token),
        json={"message": "URGENTE verifique su cuenta bancaria ya"},
    )
    assert resp.status_code == 200
    assert resp.json()["is_smishing_probable"] is True

    history = client.get("/api/history", headers=auth_headers(admin_token)).json()
    assert len(history) == 1
    assert history[0]["vector"] == "Smishing"


def test_analyze_sms_empty_message_returns_400(client, admin_token):
    resp = client.post("/api/analyze/sms", headers=auth_headers(admin_token), json={"message": "   "})
    assert resp.status_code == 400


def test_export_csv_requires_auth(client):
    resp = client.get("/api/export/csv")
    assert resp.status_code == 401


def test_export_csv_with_auth_returns_csv(client, admin_token):
    client.post(
        "/api/analyze/sms",
        headers=auth_headers(admin_token),
        json={"message": "urgente clave banco"},
    )
    resp = client.get("/api/export/csv", headers=auth_headers(admin_token))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "ID,Timestamp,Vector" in resp.text


def test_export_incident_pdf_not_found_returns_404(client, admin_token):
    resp = client.get("/api/export/incident/99999/pdf", headers=auth_headers(admin_token))
    assert resp.status_code == 404


def test_export_incident_pdf_found_returns_pdf(client, admin_token):
    client.post(
        "/api/analyze/sms",
        headers=auth_headers(admin_token),
        json={"message": "urgente clave banco"},
    )
    history = client.get("/api/history", headers=auth_headers(admin_token)).json()
    incident_id = history[0]["id"]

    resp = client.get(f"/api/export/incident/{incident_id}/pdf", headers=auth_headers(admin_token))
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")


def test_export_history_pdf_with_broken_analyst_param_does_not_500(client, admin_token):
    """Antes del fix, ?analyst=<broken tiraba un 500 sin capturar porque
    reportlab interpreta ese valor como markup XML sin cerrar."""
    resp = client.get(
        "/api/export/history/pdf?analyst=%3Cbroken",
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")


def test_export_endpoints_are_rate_limited(client, admin_token):
    """/api/history y /api/export/* no tenían @limiter.limit, a diferencia de
    login y los endpoints de análisis — un usuario autenticado de cualquier
    rol podía pedir en loop la generación de PDFs (CPU) sin ningún freno."""
    for _ in range(10):
        resp = client.get("/api/export/history/pdf", headers=auth_headers(admin_token))
        assert resp.status_code == 200

    resp = client.get("/api/export/history/pdf", headers=auth_headers(admin_token))
    assert resp.status_code == 429


def test_health_endpoint_is_public(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "online"
