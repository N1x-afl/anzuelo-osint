# Anzuelo · Validador OSINT de Phishing

Plataforma web táctica y ligera de análisis forense y validación OSINT contra vectores de ingeniería social: **Email Phishing**, **Smishing (SMS)** y **Quishing (códigos QR)**.

## Arquitectura
- **Frontend:** HTML5, Tailwind CSS, Canvas dinámico interactivo y split-screen con gestión RBAC.
- **Backend:** FastAPI + Uvicorn con módulos de inspección de cabeceras RFC, resolución de DNS/SPF/DKIM/DMARC y desempaquetado de cadenas HTTP.

## Despliegue Local
\`\`\`fish
source venv/bin/activate.fish
uvicorn backend.main:app --reload --port 8000
\`\`\`
