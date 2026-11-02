# Anzuelo · OSINT Phishing & Social Engineering Triage Platform

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/Storage-SQLite3-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Homelab%20%2F%20Educational-orange)

Plataforma unificada de respuesta preliminar y análisis forense rápido frente a vectores de ingeniería social (Phishing de correo, Smishing por SMS y Quishing vía códigos QR), orientada a analistas de seguridad, equipos de respuesta a incidentes (CSIRT/SOC) y entornos homelab.

---

## 🎯 Características Principales

- **Análisis Forense de Cabeceras RFC 822 (Email):** Extracción de remitente, saltos SMTP (`Received`) y resolución activa de registros DNS para validación de políticas **SPF**, **DKIM** y **DMARC**.
- **Heurística de Smishing (SMS):** Evaluación de patrones lingüísticos y disparadores de coerción/urgencia con extracción automática de URLs objetivos.
- **Desempaquetador de QR & Trazado de Quishing:** Decodificación directa de matrices QR desde archivos de imagen (PNG, JPG, WEBP) o inspección manual de enlaces, con trazado de cadena de saltos y redirecciones HTTP hasta el destino final.
- **Persistencia Local con SQLite:** Registro de auditoría integrado para trazabilidad de incidentes sin dependencias de bases de datos externas.
- **Arquitectura de Proceso Único:** Backend en FastAPI y Frontend (HTML/Tailwind CSS) servidos bajo el mismo socket y proceso, accesible localmente o mediante la IP física de la LAN.
- **Interfaz táctica tipo SOC:** fondo de red animado (nodos conectados sobre Canvas), barrido de radar, esquinas HUD en los paneles y estados de "escaneo" en los botones de acción.

---

## 📸 Capturas de Pantalla

> Las capturas actuales corresponden a una versión previa de la interfaz. La UI fue rediseñada con estética SOC/cyberpunk (fondo de red animado, radar, HUD) — se van a actualizar en el próximo corte.

### 1. Consola de Acceso & Identidad Visual
![Login Split Screen](docs/screenshots/01-login.png)

### 2. Triage de Cabeceras de Correo Electrónico
![Análisis Email](docs/screenshots/02-email-analysis.png)

### 3. Detección Heurística de Smishing
![Análisis Smishing](docs/screenshots/03-sms-smishing.png)

### 4. Decodificación de QR Payload & Quishing
![Análisis Quishing](docs/screenshots/04-qr-quishing.png)

### 5. Registro y Auditoría Local en SQLite
![Historial de Incidentes](docs/screenshots/05-sqlite-history.png)

---

## 🛠️ Stack Tecnológico

- **Backend:** Python 3.11+ + FastAPI + Uvicorn
- **Frontend:** HTML5 semántico + Tailwind CSS (CDN) + FontAwesome (CDN)
- **Procesamiento de Imágenes & Códigos:** `Pillow`, `pyzbar` (librería nativa `zbar`)
- **Resolución Forense de Red:** `dnspython`, `requests`, `socket`
- **Almacenamiento:** SQLite3 (`anzuelo.db`, local — no versionado en git)
- **Sistema Operativo Base:** CachyOS / Arch Linux

---

## 🚀 Despliegue y Ejecución Rápida

### 1. Requisitos Previos (Dependencia de Zbar)

Anzuelo requiere la librería C de `zbar` instalada en el sistema para decodificar códigos QR mediante `pyzbar`. Según tu distribución de Linux, instalala con el gestor correspondiente:

**Arch Linux / CachyOS:**
```bash
sudo pacman -S --needed zbar
```

**Ubuntu / Debian / Linux Mint:**
```bash
sudo apt install libzbar0
```

**Fedora / RHEL:**
```bash
sudo dnf install zbar
```

### 2. Clonar el Repositorio y Configurar el Entorno

```bash
git clone https://github.com/N1x-afl/anzuelo-osint.git
cd anzuelo-osint

# Crear y activar entorno virtual
python -m venv venv
source venv/bin/activate.fish   # En Fish shell
# source venv/bin/activate      # En Bash/Zsh

pip install -r requirements.txt
```

### 3. Puesta en Marcha con Script Unificado

```bash
chmod +x run.sh
./run.sh
```

Por defecto el servicio queda escuchando en `0.0.0.0:8001` — accesible desde `http://localhost:8001` y desde cualquier equipo de la misma LAN por la IP física del host.

---

## ⚠️ Notas de Seguridad (leer antes de exponerlo fuera de tu red local)

Anzuelo está pensado para uso personal/homelab, no como servicio expuesto a internet sin revisión adicional:

- **El login es una puerta de entrada de frontend, no autenticación real.** Los perfiles rápidos (`admin`/`admin123`, etc.) están hardcodeados en el JavaScript del cliente y no hay validación de credenciales en el backend — cualquiera que acceda a la página puede "entrar" sin clave real. Sirve para separar vistas/roles visualmente, no como control de acceso.
- **CORS está abierto a cualquier origen** (`allow_origins=["*"]`) en `backend/main.py`, pensado para desarrollo local y acceso LAN. Si lo exponés más allá de tu red de confianza, restringilo a los orígenes que realmente necesites.
- **`anzuelo.db` queda en tu máquina y no se sube al repo** (está en `.gitignore`), ya que acumula el historial real de incidentes/correos/SMS que analices.

---

## 🛡️ Licencia y Propósito

Este software ha sido desarrollado con propósitos educativos, de investigación OSINT y respuesta defensiva ante incidentes.

Distribuido bajo licencia [MIT](LICENSE).
