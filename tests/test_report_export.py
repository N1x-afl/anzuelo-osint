"""
Tests de backend/services/report_export.py.

reportlab no depende de red ni de fuentes/CDN externos, así que estos tests
corren igual en cualquier entorno, sin mocks.
"""

from backend.services import report_export

_SAMPLE_INCIDENTS = [
    {
        "id": 1, "timestamp": "2026-11-01 20:00:00", "vector": "Email",
        "target": "From: soporte@banco-falso.com", "verdict": "Alto Riesgo",
        "risk_score": 85,
        "details": {
            "domain": "banco-falso.com",
            "threat_intel": {
                "whois_domain": {"available": True, "found": True, "age_days": 12, "registrar": "NiceNIC"}
            }
        }
    },
    {
        "id": 2, "timestamp": "2026-11-01 20:05:00", "vector": "URL / Redirección",
        "target": "https://www.google.com", "verdict": "Bajo Riesgo", "risk_score": 5,
        "details": {"hostname": "google.com"}
    },
]


def test_incidents_to_csv_has_header_and_rows():
    csv_text = report_export.incidents_to_csv(_SAMPLE_INCIDENTS)
    lines = csv_text.strip().split("\r\n")
    assert lines[0].startswith("ID,Timestamp,Vector")
    assert len(lines) == 3  # header + 2 incidentes
    assert "soporte@banco-falso.com" in lines[1]  # el campo "target" del incidente 1
    assert "google.com" not in lines[1]  # no se mezclan los datos de otra fila


def test_incidents_to_csv_includes_integrity_hash_per_row():
    csv_text = report_export.incidents_to_csv(_SAMPLE_INCIDENTS)
    lines = csv_text.strip().split("\r\n")
    # última columna de cada fila de datos es un hash SHA-256 (64 chars hex)
    for line in lines[1:]:
        last_field = line.split(",")[-1]
        assert len(last_field) == 64
        int(last_field, 16)  # no debe tirar ValueError si es hex válido


def test_incidents_to_csv_empty_list():
    csv_text = report_export.incidents_to_csv([])
    lines = csv_text.strip().split("\r\n")
    assert len(lines) == 1  # solo el header


def test_integrity_hash_is_deterministic():
    h1 = report_export._integrity_hash({"a": 1, "b": 2})
    h2 = report_export._integrity_hash({"b": 2, "a": 1})  # mismo contenido, distinto orden
    assert h1 == h2  # json.dumps(sort_keys=True) garantiza el mismo hash

    h3 = report_export._integrity_hash({"a": 1, "b": 3})
    assert h1 != h3


def test_incident_to_pdf_produces_valid_pdf_bytes():
    pdf_bytes = report_export.incident_to_pdf(_SAMPLE_INCIDENTS[0], analyst="Analista de Prueba")
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500  # un PDF vacío/roto sería mucho más chico


def test_history_to_pdf_produces_valid_pdf_bytes():
    pdf_bytes = report_export.history_to_pdf(_SAMPLE_INCIDENTS, analyst="Analista de Prueba")
    assert pdf_bytes.startswith(b"%PDF")


def test_history_to_pdf_empty_list_does_not_crash():
    pdf_bytes = report_export.history_to_pdf([], analyst="Nadie")
    assert pdf_bytes.startswith(b"%PDF")


def test_flatten_handles_nested_threat_intel():
    flat = dict(report_export._flatten(_SAMPLE_INCIDENTS[0]["details"]))
    assert flat["threat_intel.whois_domain.age_days"] == "12"
    assert flat["threat_intel.whois_domain.registrar"] == "NiceNIC"
    assert flat["domain"] == "banco-falso.com"


def test_flatten_handles_none_and_lists():
    flat = dict(report_export._flatten({"a": None, "b": [1, 2, 3], "c": []}))
    assert flat["a"] == "—"
    assert flat["b"] == "1, 2, 3"
    assert flat["c"] == "—"
