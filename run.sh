#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

./venv/bin/python -m pip install --quiet pillow pyzbar

echo "🚀 Iniciando Anzuelo OSINT en todas las interfaces (0.0.0.0:8001)..."
exec ./venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8001
