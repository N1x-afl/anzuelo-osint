# Anzuelo · OSINT Phishing & Social Engineering Triage Platform
#
# Build multi-stage: la etapa "builder" instala las dependencias de Python en
# un prefijo aislado; la etapa final solo copia ese resultado ya armado, sin
# arrastrar la caché de pip ni listas de paquetes de apt — la imagen final
# queda más liviana que instalando todo en una sola etapa.
#
# Imagen de un solo proceso: FastAPI + Uvicorn sirviendo tanto la API como el
# frontend estático. anzuelo.db se guarda fuera de la imagen (ver volumen en
# docker-compose.yml) para que el historial de incidentes y los usuarios
# persistan entre reconstrucciones del contenedor.

# --- Etapa 1: build de dependencias Python -----------------------------
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Etapa 2: imagen final, liviana -------------------------------------
FROM python:3.12-slim

# libzbar0: única dependencia nativa en runtime (pyzbar la usa para
# decodificar códigos QR). No se necesita ningún compilador: ninguna de las
# dependencias de requirements.txt compila nada en esta plataforma (se
# instalan todas como wheels precompiladas).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Paquetes Python ya instalados en la etapa anterior, sin la caché de pip.
COPY --from=builder /install /usr/local

WORKDIR /app
COPY backend ./backend
COPY frontend ./frontend

# anzuelo.db vive en /app (se monta como volumen externo en docker-compose.yml)
# para no perder el historial/usuarios al reconstruir la imagen.
EXPOSE 8001

# Sin --reload: ese flag es para desarrollo local (run.sh), no para producción en contenedor.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
