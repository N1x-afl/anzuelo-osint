# Anzuelo · OSINT Phishing & Social Engineering Triage Platform

Plataforma unificada de respuesta preliminar y análisis forense rápido frente a vectores de ingeniería social (Phishing de correo, Smishing por SMS y Quishing vía códigos QR), orientada a analistas de seguridad, equipos de respuesta a incidentes (CSIRT/SOC) y entornos homelab.

---

## 🎯 Características Principales

- **Análisis Forense de Cabeceras RFC 822 (Email):** Extracción de remitente, saltos SMTP (`Received`) y resolución activa de registros DNS para validación de políticas **SPF**, **DKIM** y **DMARC**.
- **Heurística de Smishing (SMS):** Evaluación de patrones lingüísticos y disparadores de coerción/urgencia con extracción automática de URLs objetivos.
- **Desempaquetador de QR & Trazado de Quishing:** Decodificación directa de matrices QR desde archivos de imagen (PNG, JPG, WEBP) o inspección manual de enlaces, con trazado de cadena de saltos y redirecciones HTTP hasta el destino final.
- **Persistencia Local con SQLite:** Registro de auditoría integrado para trazabilidad de incidentes sin dependencias de bases de datos externas.
- **Arquitectura de Proceso Único:** Backend en FastAPI y Frontend (HTML/Tailwind CSS) servidos bajo el mismo socket y proceso, accesible localmente o mediante la IP física de la LAN.

---

## 📸 Capturas de Pantalla

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

- **Backend:** Python 3.14 + FastAPI + Uvicorn
- **Frontend:** HTML5 semántico + Tailwind CSS (CDN) + FontAwesome
- **Procesamiento de Imágenes & Códigos:** `Pillow`, `pyzbar` (librería nativa `zbar`)
- **Resolución Forense de Red:** `dnspython`, `requests`, `socket`
- **Almacenamiento:** SQLite3 (`anzuelo.db`)
- **Sistema Operativo Base:** CachyOS / Arch Linux

---

## 🚀 Despliegue y Ejecución Rápida

### 1. Requisitos Previos (Dependencia de Zbar)

Anzuelo requiere la librería C de `zbar` instalada en el sistema para decodificar códigos QR mediante `pyzbar`. Según tu distribución de Linux, instalala con el gestor correspondiente:

- **Arch Linux / CachyOS:**
  ```bash
  sudo pacman -S --needed zbar


- **Ubuntu / Debian / Linux Mint:**
  ```bash
  sudo apt install libzbar0

- **Fedora / RHEL:**  
  ```bash
  sudo dnf install zbar

# Clonar el Repositorio y Configurar el Entorno

git clone [https://github.com/N1x-afl/anzuelo-osint.git](https://github.com/N1x-afl/anzuelo-osint.git)
cd anzuelo-osint

# Crear y activar entorno virtual
python -m venv venv
source venv/bin/activate.fish   # En Fish shell
# source venv/bin/activate       # En Bash/Zsh


# Puesta en Marcha con Script Unificado

chmod +x run.sh
./run.sh


## 🛡️ Licencia y Propósito

Este software ha sido desarrollado con propósitos educativos, de investigación OSINT y respuesta defensiva ante incidentes.
	
