"""
Integraciones de Threat Intelligence externas para Anzuelo.

Todas las funciones son best-effort y degradan de forma elegante:
- Si falta la API key correspondiente, devuelven {"available": False, "reason": "..."}
  en vez de lanzar una excepción o romper el análisis principal.
- Si la API externa falla (timeout, 5xx, etc.), también degradan en vez de
  propagar el error hacia arriba.

VirusTotal y AbuseIPDB requieren API key propia (gratuitas, ver README).
URLhaus (abuse.ch) es pública y no requiere key.
"""

import os
import base64
import requests

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"

TIMEOUT = 6  # segundos — no queremos que una API externa lenta trabe el triage


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
    """Consulta si la URL está en la base pública de malware/phishing de URLhaus (abuse.ch). No requiere API key."""
    if not url:
        return _unavailable("Sin URL para consultar.")

    try:
        resp = requests.post(
            f"{URLHAUS_BASE}/url/",
            data={"url": url},
            timeout=TIMEOUT,
        )
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
