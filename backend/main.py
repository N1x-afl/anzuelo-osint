import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno (.env) antes de importar servicios que las leen
# (ej. backend/services/threat_intel.py lee VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY al importarse)
load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.services.analyzer import ForensicAnalyzer
from backend.services.db import (
    init_db, save_incident, get_recent_incidents, get_incident_by_id,
    clear_all_incidents, get_user_by_username, update_user_password
)
from backend.services import report_export
from backend.services import auth

# Inicializar tabla SQLite (incidentes + usuarios, con seed de perfiles demo) al arrancar
init_db()

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Anzuelo · Validador OSINT de Phishing",
    description="API REST de triage forense y respuesta técnica contra ingeniería social.",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailPayload(BaseModel):
    raw_headers: str

class SMSPayload(BaseModel):
    message: str

class URLPayload(BaseModel):
    url: str

class LoginPayload(BaseModel):
    username: str
    password: str

class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "Anzuelo OSINT Core Engine",
        "version": "1.0.0",
        "auth": {
            "jwt_secret_configured": bool(os.getenv("ANZUELO_JWT_SECRET", "").strip())
        },
        "threat_intel": {
            "virustotal_configured": bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip()),
            "abuseipdb_configured": bool(os.getenv("ABUSEIPDB_API_KEY", "").strip()),
            "urlhaus_configured": bool(os.getenv("ABUSECH_AUTH_KEY", "").strip())
        }
    }

# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------

@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request, payload: LoginPayload):
    user = get_user_by_username(payload.username.strip())
    if not user or not auth.verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuario o clave incorrectos.")
    return auth.create_access_token(username=user["username"], role=user["role"])

@app.get("/api/auth/me")
def whoami(current_user: dict = Depends(auth.get_current_user)):
    return current_user

@app.post("/api/auth/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    payload: ChangePasswordPayload,
    current_user: dict = Depends(auth.get_current_user),
):
    user = get_user_by_username(current_user["username"])
    if not user or not auth.verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="La clave actual no es correcta.")
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="La nueva clave debe tener al menos 6 caracteres.")
    new_hash = auth.hash_password(payload.new_password)
    update_user_password(current_user["username"], new_hash)
    return {"success": True}

# ---------------------------------------------------------------------------
# Análisis (requieren sesión autenticada)
# ---------------------------------------------------------------------------

@app.post("/api/analyze/email")
@limiter.limit("20/minute")
def analyze_email(request: Request, payload: EmailPayload, current_user: dict = Depends(auth.get_current_user)):
    if not payload.raw_headers.strip():
        raise HTTPException(status_code=400, detail="Cabeceras vacías.")
    res = ForensicAnalyzer.analyze_email_headers(payload.raw_headers)
    save_incident(
        vector="Email",
        target=f"From: {res.get('from', 'Desconocido')} | Subject: {res.get('subject', 'Sin asunto')}",
        verdict=res.get("verdict", "Evaluado"),
        risk_score=res.get("risk_score", 0),
        details=res
    )
    return res

@app.post("/api/analyze/sms")
@limiter.limit("20/minute")
def analyze_sms(request: Request, payload: SMSPayload, current_user: dict = Depends(auth.get_current_user)):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Mensaje vacío.")
    res = ForensicAnalyzer.analyze_sms(payload.message)
    save_incident(
        vector="Smishing",
        target=payload.message[:120],
        verdict="Probable Smishing" if res.get("is_smishing_probable") else "Bajo Riesgo",
        risk_score=res.get("urgency_score", 0),
        details=res
    )
    return res

@app.post("/api/analyze/url")
@limiter.limit("20/minute")
def analyze_url(request: Request, payload: URLPayload, current_user: dict = Depends(auth.get_current_user)):
    if not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL vacía.")
    res = ForensicAnalyzer.analyze_url_chain(payload.url)
    save_incident(
        vector="URL / Redirección",
        target=payload.url,
        verdict=res.get("verdict", "Evaluado"),
        risk_score=res.get("risk_score", 0),
        details=res
    )
    return res

@app.post("/api/analyze/qr-image")
@limiter.limit("20/minute")
async def analyze_qr_image(request: Request, file: UploadFile = File(...), current_user: dict = Depends(auth.get_current_user)):
    contents = await file.read()
    if not contents:
        return {"success": False, "error": "El archivo subido está vacío."}
    res = ForensicAnalyzer.decode_and_analyze_qr_image(contents)
    if res.get("success"):
        url_analysis = res.get("url_analysis") or {}
        save_incident(
            vector="QR / Quishing",
            target=res.get("payload", "")[:120],
            verdict=url_analysis.get("verdict", f"Tipo: {res.get('type')}"),
            risk_score=url_analysis.get("risk_score", 75 if res.get("is_url") else 10),
            details=res
        )
    return res

# Endpoints de Historial SQLite
@app.get("/api/history")
def get_history(current_user: dict = Depends(auth.get_current_user)):
    return get_recent_incidents(limit=50)

@app.delete("/api/history")
def clear_history(current_user: dict = Depends(auth.require_admin)):
    success = clear_all_incidents()
    return {"success": success}

# Endpoints de Exportación de Evidencia (CSV / PDF forense)
@app.get("/api/export/csv")
def export_csv(current_user: dict = Depends(auth.get_current_user)):
    incidents = get_recent_incidents(limit=1000)
    csv_text = report_export.incidents_to_csv(incidents)
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=anzuelo_historial.csv"}
    )

@app.get("/api/export/history/pdf")
def export_history_pdf(analyst: str = "No especificado", current_user: dict = Depends(auth.get_current_user)):
    incidents = get_recent_incidents(limit=200)
    pdf_bytes = report_export.history_to_pdf(incidents, analyst=analyst)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=anzuelo_historial.pdf"}
    )

@app.get("/api/export/incident/{incident_id}/pdf")
def export_incident_pdf(incident_id: int, analyst: str = "No especificado", current_user: dict = Depends(auth.get_current_user)):
    incident = get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incidente #{incident_id} no encontrado.")
    pdf_bytes = report_export.incident_to_pdf(incident, analyst=analyst)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=anzuelo_incidente_{incident_id}.pdf"}
    )

# Servir Frontend Unificado
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
