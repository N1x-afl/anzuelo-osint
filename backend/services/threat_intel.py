"""
Integraciones de Threat Intelligence externas para Anzuelo.

Todas las funciones son best-effort y degradan de forma elegante:
- Si falta la API key correspondiente, devuelven {"available": False, "reason": "..."}
  en vez de lanzar una excepción o romper el análisis principal.
- Si la API externa falla (timeout, 5xx, etc.), también degradan en vez de
  propagar el error hacia arriba.

VirusTotal y AbuseIPDB requieren API key propia (gratuitas, ver README).
WHOIS es pública y no requiere key. URLhaus (abuse.ch) requiere, desde 2025,
un Auth-Key gratuito registrado en https://auth.abuse.ch/ (antes era abierta
sin autenticación — abuse.ch migró todas sus APIs a este esquema).
"""

import os
import base64
from datetime import datetime, timezone
import requests
import whois as whois_lib

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "").strip()

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"

TIMEOUT = 6  # segundos — no queremos que una API externa lenta trabe el triage
WHOIS_TIMEOUT = 8  # el protocolo WHOIS (puerto 43) suele ser más lento que una API REST


def _unavailable(reason: str) -> dict:
    return {"available": False, "reason": reason}


def check_domain_virustotal(domain: str) -> dict:
    """Reputación de dominio en VirusTotal (motores que lo marcan como malicioso)."""
    if not domain:
        return _unavailable("Sin dominio para consultar.")
    if not VT_API_KEY:
        return _unavailable("VIRUSTOTAL_API_KEY no configurada (ver .env.example).")

    try:
        resp = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"available": True, "found": False}
        resp.raise_for_status()

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation"),
            "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
        }
    except Exception as e:
        return _unavailable(f"Error consultando VirusTotal: {e}")


def check_url_virustotal(url: str) -> dict:
    """Reputación de URL en VirusTotal."""
    if not url:
        return _unavailable("Sin URL para consultar.")
    if not VT_API_KEY:
        return _unavailable("VIRUSTOTAL_API_KEY no configurada (ver .env.example).")

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"available": True, "found": False}
        resp.raise_for_status()

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        }
    except Exception as e:
        return _unavailable(f"Error consultando VirusTotal: {e}")


def check_ip_abuseipdb(ip: str) -> dict:
    """Reputación de IP en AbuseIPDB (score 0-100 de confianza de abuso)."""
    if not ip or ip in ("No resoluble", ""):
        return _unavailable("Sin IP resuelta para consultar.")
    if not ABUSEIPDB_API_KEY:
        return _unavailable("ABUSEIPDB_API_KEY no configurada (ver .env.example).")

    try:
        resp = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "available": True,
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_tor": data.get("isTor", False),
            "permalink": f"https://www.abuseipdb.com/check/{ip}",
        }
    except Exception as e:
        return _unavailable(f"Error consultando AbuseIPDB: {e}")


def check_url_urlhaus(url: str) -> dict:
    """Consulta si la URL está en la base pública de malware/phishing de URLhaus (abuse.ch).

    Desde 2025, abuse.ch requiere un Auth-Key gratuito (https://auth.abuse.ch/)
    en todas sus APIs, incluida URLhaus — sin él, la consulta devuelve 401.
    """
    if not url:
        return _unavailable("Sin URL para consultar.")
    if not ABUSECH_AUTH_KEY:
        return _unavailable(
            "ABUSECH_AUTH_KEY no configurada — desde 2025 abuse.ch requiere un "
            "Auth-Key gratuito (ver .env.example)."
        )

    try:
        resp = requests.post(
            f"{URLHAUS_BASE}/url/",
            data={"url": url},
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            timeout=TIMEOUT,
        )
        if resp.status_code == 401:
            return _unavailable("Auth-Key de abuse.ch inválida o expirada.")
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            return {"available": True, "found": False}

        return {
            "available": True,
            "found": True,
            "threat": data.get("threat"),
            "url_status": data.get("url_status"),
            "tags": data.get("tags") or [],
            "permalink": data.get("urlhaus_reference"),
        }
    except Exception as e:
        return _unavailable(f"Error consultando URLhaus: {e}")


def _first(value):
    """python-whois a veces devuelve listas (ej. varios creation_date reportados
    por distintos registradores del mismo TLD) — nos quedamos con el primero."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def check_domain_whois(hostname: str) -> dict:
    """
    Edad y datos de registro del dominio (WHOIS, puerto 43 — no requiere API key).
    Un dominio registrado hace pocos días/semanas es una señal fuerte de phishing:
    la infraestructura maliciosa suele armarse recién antes de la campaña.

    python-whois ya reduce un hostname con subdominios (ej. mail.ejemplo.com.ar)
    al dominio registrable (ejemplo.com.ar) usando su propia lista de sufijos
    públicos embebida — no depende de red para esa parte.
    """
    if not hostname:
        return _unavailable("Sin dominio para consultar.")

    try:
        record = whois_lib.whois(hostname, timeout=WHOIS_TIMEOUT)
    except Exception as e:
        return _unavailable(f"Error consultando WHOIS: {e}")

    apex = _first(record.get("domain_name")) or hostname
    if isinstance(apex, str):
        apex = apex.lower()

    creation = _first(record.get("creation_date"))
    if not isinstance(creation, datetime):
        # el registro existe pero sin fecha de creación parseable (privacidad del
        # registrador, TLD con WHOIS no estandarizado, etc.) — no es un error.
        return {"available": True, "found": False, "domain": apex}

    try:
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days

        registrar = _first(record.get("registrar"))
        expiration = _first(record.get("expiration_date"))

        return {
            "available": True,
            "found": True,
            "domain": apex,
            "creation_date": creation.strftime("%Y-%m-%d"),
            "age_days": age_days,
            "registrar": registrar,
            "expiration_date": expiration.strftime("%Y-%m-%d") if isinstance(expiration, datetime) else None,
        }
    except Exception as e:
        return _unavailable(f"Error interpretando respuesta WHOIS: {e}")
