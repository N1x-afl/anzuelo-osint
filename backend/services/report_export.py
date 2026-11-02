"""
Generación de reportes de evidencia para Anzuelo: CSV e informes PDF forenses
por incidente, pensados como evidencia exportable con integridad verificable
(hash SHA-256 del payload original) — útil para flujos de cadena de custodia
o anexos de reportes de incidente ISO 27001.

No depende de red ni de fuentes/CDN externos: reportlab genera el PDF
localmente con sus fuentes embebidas.
"""

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

BRAND_CYAN = colors.HexColor("#0e7490")
BRAND_DARK = colors.HexColor("#0f172a")
RISK_HIGH = colors.HexColor("#be123c")
RISK_LOW = colors.HexColor("#047857")


def _integrity_hash(details: dict) -> str:
    """SHA-256 del JSON canónico de los detalles — permite verificar que el
    PDF/CSV exportado no fue alterado respecto al registro original en SQLite."""
    canonical = json.dumps(details, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _flatten(d: dict, prefix: str = "") -> list:
    """Convierte un dict (potencialmente anidado, ej. threat_intel) en una
    lista plana de pares (etiqueta, valor) para mostrar en tabla PDF."""
    rows = []
    for key, value in d.items():
        label = f"{prefix}{key}"
        if isinstance(value, dict):
            rows.extend(_flatten(value, prefix=f"{label}."))
        elif isinstance(value, list):
            if value and all(isinstance(v, dict) for v in value):
                rows.append((label, f"[{len(value)} elemento(s) — ver JSON crudo]"))
            else:
                rows.append((label, ", ".join(str(v) for v in value) if value else "—"))
        else:
            rows.append((label, "—" if value is None else str(value)))
    return rows


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def incidents_to_csv(incidents: list) -> str:
    """Exporta el historial completo (o filtrado) a CSV, con hash de
    integridad por fila para poder verificar cada registro contra la base."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "ID", "Timestamp", "Vector", "Objetivo / Muestra",
        "Veredicto", "Risk Score", "Hash SHA-256 (integridad)"
    ])
    for item in incidents:
        details = item.get("details", {})
        writer.writerow([
            item.get("id"),
            item.get("timestamp"),
            item.get("vector"),
            item.get("target"),
            item.get("verdict"),
            item.get("risk_score"),
            _integrity_hash(details),
        ])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PDF — estilos compartidos
# ---------------------------------------------------------------------------

def _base_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="AnzueloTitle", parent=styles["Title"],
        textColor=BRAND_DARK, fontSize=18, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="AnzueloSubtitle", parent=styles["Normal"],
        textColor=colors.HexColor("#475569"), fontSize=9, spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="AnzueloSection", parent=styles["Heading2"],
        textColor=BRAND_CYAN, fontSize=12, spaceBefore=14, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="AnzueloMono", parent=styles["Code"],
        fontSize=7.5, leading=10, textColor=colors.HexColor("#1e293b"),
    ))
    return styles


def _header_flowables(styles, title: str, analyst: str):
    """
    'analyst' llega de un query param (?analyst=...) que el usuario escribe
    libremente, y Paragraph() interpreta un subconjunto de markup tipo XML
    (<b>, <font>, etc.) — sin escapar, un valor como "?analyst=<broken"
    tira un ValueError sin capturar (500) en cualquiera de los 3 endpoints
    de export, con solo una sesión válida. 'title' siempre es texto fijo
    generado acá mismo (nunca viene de afuera), pero se escapa igual por
    las dudas de que eso cambie más adelante.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_title = _xml_escape(str(title))
    safe_analyst = _xml_escape(str(analyst))
    flow = [
        Paragraph("ANZUELO · OSINT Phishing &amp; Social Engineering Triage", styles["AnzueloSubtitle"]),
        Paragraph(safe_title, styles["AnzueloTitle"]),
        HRFlowable(width="100%", thickness=1.2, color=BRAND_CYAN, spaceAfter=10),
        Paragraph(
            f"<b>Analista / Exportado por:</b> {safe_analyst}&nbsp;&nbsp;|&nbsp;&nbsp;"
            f"<b>Fecha de exportación:</b> {now}",
            styles["Normal"],
        ),
        Spacer(1, 10),
    ]
    return flow


def _verdict_color(risk_score: int):
    return RISK_HIGH if (risk_score or 0) >= 60 else RISK_LOW


# ---------------------------------------------------------------------------
# PDF — informe de un solo incidente (forense, con hash de integridad)
# ---------------------------------------------------------------------------

def incident_to_pdf(incident: dict, analyst: str = "No especificado") -> bytes:
    styles = _base_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=18 * mm, bottomMargin=16 * mm,
        leftMargin=16 * mm, rightMargin=16 * mm,
        title=f"Anzuelo - Incidente #{incident.get('id')}",
    )

    details = incident.get("details", {})
    integrity_hash = _integrity_hash(details)
    risk_score = incident.get("risk_score", 0) or 0

    story = _header_flowables(styles, f"Informe de Incidente #{incident.get('id')}", analyst)

    # Resumen ejecutivo
    story.append(Paragraph("Resumen del Incidente", styles["AnzueloSection"]))
    summary_data = [
        ["Vector", incident.get("vector", "—")],
        ["Timestamp (triage local)", incident.get("timestamp", "—")],
        ["Objetivo / Muestra analizada", incident.get("target", "—")],
        ["Veredicto", incident.get("verdict", "—")],
        ["Risk Score", f"{risk_score}/100"],
    ]
    summary_table = Table(summary_data, colWidths=[55 * mm, 115 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (0, 0), (0, -1), BRAND_DARK),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TEXTCOLOR", (1, 4), (1, 4), _verdict_color(risk_score)),
        ("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)

    # Detalle técnico forense (incluye threat_intel aplanado)
    story.append(Paragraph("Detalle Técnico Forense", styles["AnzueloSection"]))
    flat_rows = _flatten(details)
    if flat_rows:
        detail_data = [["Campo", "Valor"]] + [[k, v[:180]] for k, v in flat_rows]
        detail_table = Table(detail_data, colWidths=[55 * mm, 115 * mm], repeatRows=1)
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_CYAN),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(detail_table)
    else:
        story.append(Paragraph("Sin detalles adicionales registrados.", styles["Normal"]))

    # Cadena de custodia / integridad
    story.append(Paragraph("Integridad y Cadena de Custodia", styles["AnzueloSection"]))
    story.append(Paragraph(
        "El siguiente hash SHA-256 se calcula sobre el JSON canónico de los datos crudos "
        "del incidente tal como quedaron registrados en la base de datos local (SQLite) al "
        "momento del triage. Permite verificar, en cualquier momento posterior, que este "
        "informe no fue alterado respecto al registro original.",
        styles["Normal"],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<font face='Courier'>{integrity_hash}</font>", styles["AnzueloMono"]))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Generado automáticamente por Anzuelo OSINT Core. Este informe es una herramienta de "
        "apoyo al triage preliminar y no constituye un dictamen pericial.",
        styles["AnzueloSubtitle"],
    ))

    doc.build(story)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PDF — resumen de todo el historial
# ---------------------------------------------------------------------------

def history_to_pdf(incidents: list, analyst: str = "No especificado") -> bytes:
    styles = _base_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=18 * mm, bottomMargin=16 * mm,
        leftMargin=14 * mm, rightMargin=14 * mm,
        title="Anzuelo - Historial de Incidentes",
    )

    story = _header_flowables(styles, "Historial de Incidentes", analyst)
    story.append(Paragraph(f"Total de registros incluidos: <b>{len(incidents)}</b>", styles["Normal"]))
    story.append(Spacer(1, 8))

    if not incidents:
        story.append(Paragraph("No hay incidentes registrados en la base de datos.", styles["Normal"]))
    else:
        header = ["ID", "Timestamp", "Vector", "Objetivo", "Veredicto", "Score"]
        rows = [header]
        for item in incidents:
            target = (item.get("target") or "")[:60]
            rows.append([
                str(item.get("id")),
                item.get("timestamp", "—"),
                item.get("vector", "—"),
                target,
                item.get("verdict", "—"),
                f"{item.get('risk_score', 0)}/100",
            ])

        table = Table(rows, colWidths=[12 * mm, 32 * mm, 26 * mm, 58 * mm, 40 * mm, 20 * mm], repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_CYAN),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i, item in enumerate(incidents, start=1):
            if (item.get("risk_score", 0) or 0) >= 60:
                style_cmds.append(("TEXTCOLOR", (4, i), (5, i), RISK_HIGH))
                style_cmds.append(("FONTNAME", (4, i), (5, i), "Helvetica-Bold"))
        table.setStyle(TableStyle(style_cmds))
        story.append(table)

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Generado automáticamente por Anzuelo OSINT Core. Para el detalle forense completo e "
        "integridad verificable de un incidente puntual, exportá su informe individual en PDF.",
        styles["AnzueloSubtitle"],
    ))

    doc.build(story)
    return buffer.getvalue()
