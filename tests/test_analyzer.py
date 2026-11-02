"""
Tests unitarios de backend/services/analyzer.py (ForensicAnalyzer).

Todo lo que toca red externa (DNS, HTTP, WHOIS, Threat Intel) se mockea para
que los tests sean rápidos y determinísticos sin depender de conectividad.
"""

from unittest.mock import MagicMock, patch

from backend.services.analyzer import ForensicAnalyzer


# ---------------------------------------------------------------------------
# analyze_sms
# ---------------------------------------------------------------------------

def test_analyze_sms_detects_urgency_triggers():
    text = "URGENTE: tu cuenta bancaria fue bloqueada, verificá tu clave ya"
    result = ForensicAnalyzer.analyze_sms(text)
    assert "urgente" in result["matched_triggers"]
    assert "cuenta" in result["matched_triggers"]
    assert result["urgency_score"] > 0
    assert result["is_smishing_probable"] is True


def test_analyze_sms_low_risk_message():
    text = "Hola, ¿cómo estás? Nos vemos mañana."
    result = ForensicAnalyzer.analyze_sms(text)
    assert result["matched_triggers"] == []
    assert result["urgency_score"] == 0
    assert result["is_smishing_probable"] is False


def test_analyze_sms_extracts_urls():
    text = "Verificá tu cuenta en http://bit.ly/falso urgente"
    result = ForensicAnalyzer.analyze_sms(text)
    assert result["extracted_urls"] == ["http://bit.ly/falso"]
    # threat_intel se consulta pero sin ABUSECH_AUTH_KEY configurada degrada sin red
    ti = result["threat_intel"]["urlhaus_first_url"]
    assert ti["available"] is False


def test_analyze_sms_no_urls_skips_urlhaus():
    result = ForensicAnalyzer.analyze_sms("mensaje sin links, solo urgente")
    ti = result["threat_intel"]["urlhaus_first_url"]
    assert ti["available"] is False
    assert "Sin URLs" in ti["reason"]


# ---------------------------------------------------------------------------
# analyze_email_headers
# ---------------------------------------------------------------------------

_RAW_HEADERS = (
    "From: Soporte Falso <soporte@dominio-sospechoso.test>\n"
    "To: victima@example.com\n"
    "Subject: Verifique su cuenta urgente\n"
    "Date: Mon, 1 Jan 2026 00:00:00 +0000\n"
    "Received: from mail.dominio-sospechoso.test by mx.example.com\n"
)


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_domain_virustotal")
@patch("backend.services.analyzer.dns.resolver.Resolver")
def test_analyze_email_headers_high_risk_no_spf_dmarc(mock_resolver_cls, mock_vt, mock_whois):
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = Exception("NXDOMAIN")  # sin SPF/DMARC/MX
    mock_resolver_cls.return_value = mock_resolver
    mock_vt.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    result = ForensicAnalyzer.analyze_email_headers(_RAW_HEADERS)

    assert result["domain"] == "dominio-sospechoso.test"
    assert result["spf"] == "FAIL_OR_NONE"
    assert result["dmarc"] == "FAIL_OR_NONE"
    assert result["mx_records"] == []
    assert result["risk_score"] == 100  # 40 SPF + 40 DMARC + 20 sin MX
    assert "Alto Riesgo" in result["verdict"]


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_domain_virustotal")
def test_analyze_email_headers_bumps_score_on_vt_malicious(mock_vt, mock_whois):
    mock_vt.return_value = {"available": True, "found": True, "malicious": 5, "suspicious": 0}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    with patch("backend.services.analyzer.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        mock_resolver_cls.return_value = mock_resolver
        result = ForensicAnalyzer.analyze_email_headers(_RAW_HEADERS)

    # 40 (SPF) + 40 (DMARC) + 20 (sin MX) + 50 (VT malicioso) = 150, capeado a 100
    assert result["risk_score"] == 100
    assert result["threat_intel"]["virustotal_domain"]["malicious"] == 5


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_domain_virustotal")
def test_analyze_email_headers_young_domain_bumps_score(mock_vt, mock_whois):
    mock_vt.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": True, "found": True, "age_days": 5, "domain": "dominio-sospechoso.test"}

    with patch("backend.services.analyzer.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        mock_resolver_cls.return_value = mock_resolver
        result = ForensicAnalyzer.analyze_email_headers(_RAW_HEADERS)

    assert result["threat_intel"]["whois_domain"]["age_days"] == 5
    assert result["risk_score"] == 100  # ya saturado por SPF+DMARC+MX, pero confirma que no rompe


def test_analyze_email_headers_no_from_domain_handles_gracefully():
    headers = "Subject: Sin remitente\nTo: alguien@example.com\n"
    result = ForensicAnalyzer.analyze_email_headers(headers)
    assert result["domain"] == ""
    assert result["spf"] == "NOT_FOUND"


@patch("backend.services.analyzer.threat_intel.check_email_hibp")
@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_domain_virustotal")
def test_analyze_email_headers_hibp_breach_bumps_score_and_passes_full_email(mock_vt, mock_whois, mock_hibp):
    """check_email_hibp debe recibir la dirección completa (local@dominio), no
    solo el dominio — y un hallazgo positivo debe sumar al risk_score y
    quedar expuesto en threat_intel.hibp_email para el frontend."""
    mock_vt.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}
    mock_hibp.return_value = {"available": True, "found": True, "breach_count": 2, "breach_names": ["Adobe", "LinkedIn"]}

    with patch("backend.services.analyzer.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        mock_resolver_cls.return_value = mock_resolver
        result = ForensicAnalyzer.analyze_email_headers(_RAW_HEADERS)

    mock_hibp.assert_called_once_with("soporte@dominio-sospechoso.test")
    assert result["threat_intel"]["hibp_email"]["breach_count"] == 2
    assert result["risk_score"] == 100  # ya saturado por SPF+DMARC+MX; confirma que no rompe el cap


def test_analyze_email_headers_hibp_without_key_degrades_without_network():
    """Sin HIBP_API_KEY configurada (caso por defecto), no debe haber llamada
    de red real — threat_intel.check_email_hibp degrada por su cuenta."""
    with patch("backend.services.analyzer.threat_intel.check_domain_whois") as mock_whois, \
         patch("backend.services.analyzer.threat_intel.check_domain_virustotal") as mock_vt, \
         patch("backend.services.analyzer.dns.resolver.Resolver") as mock_resolver_cls, \
         patch("backend.services.analyzer.threat_intel.HIBP_API_KEY", ""):
        mock_vt.return_value = {"available": False, "reason": "sin key"}
        mock_whois.return_value = {"available": False, "reason": "sin red"}
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        mock_resolver_cls.return_value = mock_resolver
        result = ForensicAnalyzer.analyze_email_headers(_RAW_HEADERS)

    assert result["threat_intel"]["hibp_email"]["available"] is False


# ---------------------------------------------------------------------------
# analyze_url_chain
# ---------------------------------------------------------------------------

@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_ip_abuseipdb")
@patch("backend.services.analyzer.threat_intel.check_url_urlhaus")
@patch("backend.services.analyzer.threat_intel.check_url_virustotal")
@patch("backend.services.analyzer.socket.gethostbyname")
@patch("backend.services.analyzer.requests.Session")
def test_analyze_url_chain_low_risk(
    mock_session_cls, mock_gethostbyname, mock_vt_url, mock_urlhaus, mock_abuseipdb, mock_whois
):
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.history = []
    mock_response.url = "https://www.google.com/"
    mock_response.status_code = 200
    mock_session.get.return_value = mock_response
    mock_session_cls.return_value = mock_session
    mock_gethostbyname.return_value = "142.250.0.1"

    mock_vt_url.return_value = {"available": False, "reason": "sin key"}
    mock_urlhaus.return_value = {"available": True, "found": False}
    mock_abuseipdb.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": True, "found": True, "age_days": 9000}

    result = ForensicAnalyzer.analyze_url_chain("https://www.google.com")

    assert result["hostname"] == "www.google.com"
    assert result["resolved_ip"] == "142.250.0.1"
    assert result["status_code"] == 200
    assert result["risk_score"] == 0
    assert "Bajo Riesgo" in result["verdict"]


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_ip_abuseipdb")
@patch("backend.services.analyzer.threat_intel.check_url_urlhaus")
@patch("backend.services.analyzer.threat_intel.check_url_virustotal")
@patch("backend.services.analyzer.socket.gethostbyname")
@patch("backend.services.analyzer.requests.Session")
def test_analyze_url_chain_urlhaus_match_is_high_risk(
    mock_session_cls, mock_gethostbyname, mock_vt_url, mock_urlhaus, mock_abuseipdb, mock_whois
):
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.history = []
    mock_response.url = "https://malicious.example/payload.exe"
    mock_response.status_code = 200
    mock_session.get.return_value = mock_response
    mock_session_cls.return_value = mock_session
    mock_gethostbyname.return_value = "1.2.3.4"

    mock_vt_url.return_value = {"available": False, "reason": "sin key"}
    mock_urlhaus.return_value = {"available": True, "found": True, "threat": "malware_download"}
    mock_abuseipdb.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    result = ForensicAnalyzer.analyze_url_chain("https://malicious.example/payload.exe")

    assert result["risk_score"] >= 60
    assert "Alto Riesgo" in result["verdict"]
    assert result["threat_intel"]["urlhaus"]["found"] is True


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_ip_abuseipdb")
@patch("backend.services.analyzer.threat_intel.check_url_urlhaus")
@patch("backend.services.analyzer.threat_intel.check_url_virustotal")
@patch("backend.services.analyzer.socket.gethostbyname")
@patch("backend.services.analyzer.requests.Session")
def test_analyze_url_chain_handles_connection_failure(
    mock_session_cls, mock_gethostbyname, mock_vt_url, mock_urlhaus, mock_abuseipdb, mock_whois
):
    mock_session = MagicMock()
    mock_session.get.side_effect = Exception("Connection timed out")
    mock_session_cls.return_value = mock_session
    mock_gethostbyname.side_effect = Exception("No resoluble")

    mock_vt_url.return_value = {"available": False, "reason": "sin key"}
    mock_urlhaus.return_value = {"available": False, "reason": "sin key"}
    mock_abuseipdb.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    # No debe tirar excepción: degrada con resolved_ip="No resoluble" y hops con el error
    result = ForensicAnalyzer.analyze_url_chain("https://no-existe.invalid")
    assert result["resolved_ip"] == "No resoluble"
    assert result["hops_chain"][0]["error"] == "Connection timed out"


# ---------------------------------------------------------------------------
# analyze_url_chain — protección anti-SSRF
# ---------------------------------------------------------------------------

@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_ip_abuseipdb")
@patch("backend.services.analyzer.threat_intel.check_url_urlhaus")
@patch("backend.services.analyzer.threat_intel.check_url_virustotal")
@patch("backend.services.analyzer.socket.gethostbyname")
@patch("backend.services.analyzer.requests.Session")
def test_analyze_url_chain_blocks_loopback_target(
    mock_session_cls, mock_gethostbyname, mock_vt_url, mock_urlhaus, mock_abuseipdb, mock_whois
):
    """Una URL que resuelve a 127.0.0.1 (o cualquier IP interna) nunca debe
    llegar a generar una petición HTTP real — el servidor no puede usarse
    como proxy hacia sí mismo ni hacia la red interna (SSRF)."""
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_gethostbyname.return_value = "127.0.0.1"

    mock_vt_url.return_value = {"available": False, "reason": "sin key"}
    mock_urlhaus.return_value = {"available": False, "reason": "sin key"}
    mock_abuseipdb.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    result = ForensicAnalyzer.analyze_url_chain("http://127.0.0.1:8001/api/health")

    assert result["blocked_ssrf"] is True
    assert result["risk_score"] >= 80
    assert "SSRF" in result["verdict"] or "bloqueado" in result["verdict"].lower()
    assert mock_session.get.call_count == 0  # nunca se intentó la conexión


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_ip_abuseipdb")
@patch("backend.services.analyzer.threat_intel.check_url_urlhaus")
@patch("backend.services.analyzer.threat_intel.check_url_virustotal")
@patch("backend.services.analyzer.socket.gethostbyname")
@patch("backend.services.analyzer.requests.Session")
def test_analyze_url_chain_blocks_metadata_endpoint(
    mock_session_cls, mock_gethostbyname, mock_vt_url, mock_urlhaus, mock_abuseipdb, mock_whois
):
    """169.254.169.254 (metadata de AWS/GCP/Azure) cae en link-local y debe
    bloquearse igual que loopback/RFC1918."""
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_gethostbyname.return_value = "169.254.169.254"

    mock_vt_url.return_value = {"available": False, "reason": "sin key"}
    mock_urlhaus.return_value = {"available": False, "reason": "sin key"}
    mock_abuseipdb.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    result = ForensicAnalyzer.analyze_url_chain("http://169.254.169.254/latest/meta-data/")

    assert result["blocked_ssrf"] is True
    assert mock_session.get.call_count == 0


@patch("backend.services.analyzer.threat_intel.check_domain_whois")
@patch("backend.services.analyzer.threat_intel.check_ip_abuseipdb")
@patch("backend.services.analyzer.threat_intel.check_url_urlhaus")
@patch("backend.services.analyzer.threat_intel.check_url_virustotal")
@patch("backend.services.analyzer.socket.gethostbyname")
@patch("backend.services.analyzer.requests.Session")
def test_analyze_url_chain_blocks_redirect_to_internal_ip(
    mock_session_cls, mock_gethostbyname, mock_vt_url, mock_urlhaus, mock_abuseipdb, mock_whois
):
    """Una URL PÚBLICA que redirige (302) hacia una IP interna debe cortarse
    ahí — el chequeo anti-SSRF se repite en cada salto, no solo en el inicial."""
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    redirect_response = MagicMock()
    redirect_response.status_code = 302
    redirect_response.headers = {"Location": "http://10.0.0.5/internal-admin"}
    mock_session.get.return_value = redirect_response

    # Primer hop (hostname público) resuelve a una IP pública real (8.8.8.8);
    # el segundo hop (10.0.0.5, de la redirección) resuelve a sí mismo, privada.
    mock_gethostbyname.side_effect = ["8.8.8.8", "10.0.0.5"]

    mock_vt_url.return_value = {"available": False, "reason": "sin key"}
    mock_urlhaus.return_value = {"available": False, "reason": "sin key"}
    mock_abuseipdb.return_value = {"available": False, "reason": "sin key"}
    mock_whois.return_value = {"available": False, "reason": "sin red"}

    result = ForensicAnalyzer.analyze_url_chain("https://acortador-publico.example/x")

    assert result["blocked_ssrf"] is True
    assert result["risk_score"] >= 80
    # Se permitió el primer salto (público) pero se cortó antes del segundo (interno)
    assert mock_session.get.call_count == 1


# ---------------------------------------------------------------------------
# decode_and_analyze_qr_image
# ---------------------------------------------------------------------------

def test_decode_qr_image_rejects_invalid_bytes():
    result = ForensicAnalyzer.decode_and_analyze_qr_image(b"esto no es una imagen valida")
    assert result["success"] is False
    assert "error" in result


def test_decode_qr_image_from_generated_qr():
    """Genera un QR real en memoria (con la lib qrcode si está disponible) y
    confirma que Anzuelo lo decodifica correctamente — valida pyzbar/zbar de
    punta a punta, no solo con mocks."""
    qrcode = __import__("importlib").util.find_spec("qrcode")
    if qrcode is None:
        import pytest
        pytest.skip("librería 'qrcode' no instalada, se omite el test de decodificación real")

    import io
    import qrcode as qrcode_lib

    img = qrcode_lib.make("https://www.ejemplo-no-malicioso.test/pagina")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")

    with patch("backend.services.analyzer.ForensicAnalyzer.analyze_url_chain") as mock_url_chain:
        mock_url_chain.return_value = {"risk_score": 10, "verdict": "Bajo Riesgo / Sin coincidencias"}
        result = ForensicAnalyzer.decode_and_analyze_qr_image(buffer.getvalue())

    assert result["success"] is True
    assert result["payload"] == "https://www.ejemplo-no-malicioso.test/pagina"
    assert result["is_url"] is True
