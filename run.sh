#!/usr/bin/env bash
set -e

# Ir al directorio del script
cd "$(dirname "$0")"

# Asegurar dependencias en venv
./venv/bin/python -m pip install --quiet pillow pyzbar

# Levantar Anzuelo Unificado
echo "🚀 Iniciando Anzuelo OSINT en http://localhost:8001"
exec ./venv/bin/uvicorn backend.main:app --reload --port 8001
