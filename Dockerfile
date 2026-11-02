# Anzuelo · OSINT Phishing & Social Engineering Triage Platform
#
# Imagen de un solo proceso: FastAPI + Uvicorn sirviendo tanto la API como el
# frontend estático. anzuelo.db se guarda fuera de la imagen (ver volumen en
# docker-compose.yml) para que el historial de incidentes y los usuarios
# persistan entre reconstrucciones del contenedor.

FROM python:3.12-slim

# libzbar0: dependencia nativa de pyzbar para decodificar códigos QR.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend

# anzuelo.db vive en /app (se monta como volumen externo en docker-compose.yml)
# para no perder el historial/usuarios al reconstruir la imagen.
EXPOSE 8001

# Sin --reload: ese flag es para desarrollo local (run.sh), no para producción en contenedor.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
