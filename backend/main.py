from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from backend.services.analyzer import ForensicAnalyzer

app = FastAPI(
    title="Anzuelo · Validador OSINT de Phishing",
    description="API REST de triage forense y respuesta técnica contra ingeniería social.",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de solicitud
class EmailPayload(BaseModel):
    raw_headers: str

class SMSPayload(BaseModel):
    message: str

class URLPayload(BaseModel):
    url: str

# Endpoints de API
@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "Anzuelo OSINT Core Engine",
        "version": "1.0.0"
    }

@app.post("/api/analyze/email")
def analyze_email(payload: EmailPayload):
    if not payload.raw_headers.strip():
        raise HTTPException(status_code=400, detail="Cabeceras vacías.")
    return ForensicAnalyzer.analyze_email_headers(payload.raw_headers)

@app.post("/api/analyze/sms")
def analyze_sms(payload: SMSPayload):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Mensaje vacío.")
    return ForensicAnalyzer.analyze_sms(payload.message)

@app.post("/api/analyze/url")
def analyze_url(payload: URLPayload):
    if not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL vacía.")
    return ForensicAnalyzer.analyze_url_chain(payload.url)

@app.post("/api/analyze/qr-image")
async def analyze_qr_image(file: UploadFile = File(...)):
    contents = await file.read()
    if not contents:
        return {"success": False, "error": "El archivo subido está vacío."}
    return ForensicAnalyzer.decode_and_analyze_qr_image(contents)

# Servir Frontend Unificado
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
