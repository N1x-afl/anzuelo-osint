"""
Tests unitarios de backend/services/threat_intel.py.

Todas las llamadas HTTP/WHOIS se mockean — ninguno de estos tests toca red
real, así que corren igual con o sin conectividad (y sin gastar cuota de las
APIs externas).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from backend.services import threat_intel


# ---------------------------------------------------------------------------
# Degradación sin API key configurada (no debe pegarle a la red)
# ---------------------------------------------------------------------------

def test_virustotal_domain_without_key_degrades_without_network():
    with patch.object(threat_intel, "VT_API_KEY", ""):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            result = threat_intel.check_domain_virustotal("example.com")
            mock_get.assert_not_called()
    assert result == {"available": False, "reason": "VIRUSTOTAL_API_KEY no configurada (ver .env.example)."}


def test_abuseipdb_without_key_degrades_without_network():
    with patch.object(threat_intel, "ABUSEIPDB_API_KEY", ""):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            result = threat_intel.check_ip_abuseipdb("1.2.3.4")
            mock_get.assert_not_called()
    assert result["available"] is False


def test_urlhaus_without_auth_key_degrades_without_network():
    with patch.object(threat_intel, "ABUSECH_AUTH_KEY", ""):
        with patch("backend.services.threat_intel.requests.post") as mock_post:
            result = threat_intel.check_url_urlhaus("https://example.com")
            mock_post.assert_not_called()
    assert result["available"] is False
    assert "Auth-Key" in result["reason"]


def test_abuseipdb_without_ip_degrades_without_network():
    result = threat_intel.check_ip_abuseipdb("No resoluble")
    assert result == {"available": False, "reason": "Sin IP resuelta para consultar."}


# ---------------------------------------------------------------------------
# URLhaus: 401 (key inválida) vs. match positivo
# ---------------------------------------------------------------------------

def test_urlhaus_401_means_invalid_key():
    with patch.object(threat_intel, "ABUSECH_AUTH_KEY", "key-invalida"):
        with patch("backend.services.threat_intel.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_post.return_value = mock_resp
            result = threat_intel.check_url_urlhaus("https://example.com")

    assert result == {"available": False, "reason": "Auth-Key de abuse.ch inválida o expirada."}


def test_urlhaus_sends_auth_key_header_and_parses_match():
    with patch.object(threat_intel, "ABUSECH_AUTH_KEY", "key-valida-123"):
        with patch("backend.services.threat_intel.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = lambda: None
            mock_resp.json.return_value = {
                "query_status": "ok", "threat": "malware_download",
                "url_status": "online", "tags": ["exe"],
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"
            }
            mock_post.return_value = mock_resp
            result = threat_intel.check_url_urlhaus("https://malicious.example/x.exe")
            _, kwargs = mock_post.call_args
            assert kwargs["headers"] == {"Auth-Key": "key-valida-123"}

    assert result["found"] is True
    assert result["threat"] == "malware_download"


def test_urlhaus_no_match_returns_found_false():
    with patch.object(threat_intel, "ABUSECH_AUTH_KEY", "key-valida"):
        with patch("backend.services.threat_intel.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = lambda: None
            mock_resp.json.return_value = {"query_status": "no_results"}
            mock_post.return_value = mock_resp
            result = threat_intel.check_url_urlhaus("https://benigna.example")

    assert result == {"available": True, "found": False}


# ---------------------------------------------------------------------------
# VirusTotal: 404 (no encontrado) vs. match
# ---------------------------------------------------------------------------

def test_virustotal_domain_404_means_not_found():
    with patch.object(threat_intel, "VT_API_KEY", "key-valida"):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_get.return_value = mock_resp
            result = threat_intel.check_domain_virustotal("nunca-visto.example")

    assert result == {"available": True, "found": False}


def test_virustotal_domain_malicious_match():
    with patch.object(threat_intel, "VT_API_KEY", "key-valida"):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = lambda: None
            mock_resp.json.return_value = {
                "data": {"attributes": {
                    "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 80},
                    "reputation": -50,
                }}
            }
            mock_get.return_value = mock_resp
            result = threat_intel.check_domain_virustotal("malicioso.example")

    assert result["found"] is True
    assert result["malicious"] == 8
    assert result["suspicious"] == 2
    assert result["total_engines"] == 90


# ---------------------------------------------------------------------------
# WHOIS: dominio joven, dominio viejo, sin fecha, error
# ---------------------------------------------------------------------------

def test_whois_young_domain_reports_age_in_days():
    creation = datetime.now(timezone.utc) - timedelta(days=5)
    with patch("backend.services.threat_intel.whois_lib.whois") as mock_whois:
        mock_whois.return_value = {
            "domain_name": "recien-registrado.example",
            "creation_date": creation,
            "registrar": "NiceNIC",
            "expiration_date": creation + timedelta(days=365),
        }
        result = threat_intel.check_domain_whois("recien-registrado.example")

    assert result["available"] is True
    assert result["found"] is True
    assert result["age_days"] in (4, 5)  # tolerancia por redondeo de horas
    assert result["registrar"] == "NiceNIC"


def test_whois_no_creation_date_is_not_an_error():
    with patch("backend.services.threat_intel.whois_lib.whois") as mock_whois:
        mock_whois.return_value = {"domain_name": "privado.example", "creation_date": None}
        result = threat_intel.check_domain_whois("privado.example")

    assert result == {"available": True, "found": False, "domain": "privado.example"}


def test_whois_handles_list_valued_fields():
    """python-whois a veces devuelve listas (varios registradores reportan la
    misma fecha) — confirma que _first() las aplana sin romper."""
    creation = datetime(2015, 3, 1, tzinfo=timezone.utc)
    with patch("backend.services.threat_intel.whois_lib.whois") as mock_whois:
        mock_whois.return_value = {
            "domain_name": ["GOOGLE.COM", "google.com"],
            "creation_date": [creation, creation],
            "registrar": ["MarkMonitor Inc."],
        }
        result = threat_intel.check_domain_whois("google.com")

    assert result["domain"] == "google.com"
    assert result["registrar"] == "MarkMonitor Inc."


def test_whois_connection_error_degrades_gracefully():
    with patch("backend.services.threat_intel.whois_lib.whois") as mock_whois:
        mock_whois.side_effect = Exception("timed out")
        result = threat_intel.check_domain_whois("inalcanzable.example")

    assert result["available"] is False
    assert "timed out" in result["reason"]


# ---------------------------------------------------------------------------
# HaveIBeenPwned: sin key, 404 (sin brechas), match positivo, 401, 429
# ---------------------------------------------------------------------------

def test_hibp_without_key_degrades_without_network():
    with patch.object(threat_intel, "HIBP_API_KEY", ""):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            result = threat_intel.check_email_hibp("victima@example.com")
            mock_get.assert_not_called()
    assert result["available"] is False
    assert "HIBP_API_KEY" in result["reason"]


def test_hibp_without_email_degrades_without_network():
    result = threat_intel.check_email_hibp("")
    assert result == {"available": False, "reason": "Sin dirección de email para consultar."}


def test_hibp_404_means_no_breaches():
    with patch.object(threat_intel, "HIBP_API_KEY", "key-valida"):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_get.return_value = mock_resp
            result = threat_intel.check_email_hibp("limpio@example.com")

    assert result == {"available": True, "found": False}


def test_hibp_found_breaches_returns_names_and_count():
    with patch.object(threat_intel, "HIBP_API_KEY", "key-valida"):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = lambda: None
            mock_resp.json.return_value = [{"Name": "Adobe"}, {"Name": "LinkedIn"}]
            mock_get.return_value = mock_resp
            result = threat_intel.check_email_hibp("filtrado@example.com")
            _, kwargs = mock_get.call_args
            assert kwargs["headers"]["hibp-api-key"] == "key-valida"

    assert result["available"] is True
    assert result["found"] is True
    assert result["breach_count"] == 2
    assert result["breach_names"] == ["Adobe", "LinkedIn"]


def test_hibp_401_means_invalid_key():
    with patch.object(threat_intel, "HIBP_API_KEY", "key-invalida"):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_get.return_value = mock_resp
            result = threat_intel.check_email_hibp("alguien@example.com")

    assert result["available"] is False
    assert "inválida" in result["reason"]


def test_hibp_429_degrades_without_crashing():
    with patch.object(threat_intel, "HIBP_API_KEY", "key-valida"):
        with patch("backend.services.threat_intel.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_get.return_value = mock_resp
            result = threat_intel.check_email_hibp("alguien@example.com")

    assert result["available"] is False
    assert "rate" in result["reason"]


# ---------------------------------------------------------------------------
# ip-api.com (geolocalización de IP): sin IP, éxito, fallo
# ---------------------------------------------------------------------------

def test_geolocation_without_ip_degrades_without_network():
    with patch("backend.services.threat_intel.requests.get") as mock_get:
        result = threat_intel.check_ip_geolocation("")
        mock_get.assert_not_called()
    assert result == {"available": False, "reason": "Sin IP de origen para geolocalizar."}


def test_geolocation_success_returns_country_and_flags():
    with patch("backend.services.threat_intel.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = lambda: None
        mock_resp.json.return_value = {
            "status": "success", "country": "Rumania", "countryCode": "RO",
            "regionName": "Bucarest", "city": "Bucarest", "isp": "DataCenter SRL",
            "org": "DataCenter SRL", "proxy": False, "hosting": True,
        }
        mock_get.return_value = mock_resp
        result = threat_intel.check_ip_geolocation("45.33.12.10")
        args, _ = mock_get.call_args
        assert "45.33.12.10" in args[0]

    assert result["available"] is True
    assert result["found"] is True
    assert result["country"] == "Rumania"
    assert result["is_hosting"] is True
    assert result["is_proxy_or_vpn"] is False


def test_geolocation_api_failure_status_degrades_gracefully():
    with patch("backend.services.threat_intel.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = lambda: None
        mock_resp.json.return_value = {"status": "fail", "message": "invalid query"}
        mock_get.return_value = mock_resp
        result = threat_intel.check_ip_geolocation("no-es-una-ip")

    assert result["available"] is False
    assert "invalid query" in result["reason"]


def test_geolocation_network_error_degrades_gracefully():
    with patch("backend.services.threat_intel.requests.get") as mock_get:
        mock_get.side_effect = Exception("timed out")
        result = threat_intel.check_ip_geolocation("8.8.8.8")

    assert result["available"] is False
    assert "timed out" in result["reason"]


def test_whois_empty_hostname_degrades_without_network():
    with patch("backend.services.threat_intel.whois_lib.whois") as mock_whois:
        result = threat_intel.check_domain_whois("")
        mock_whois.assert_not_called()
    assert result == {"available": False, "reason": "Sin dominio para consultar."}
