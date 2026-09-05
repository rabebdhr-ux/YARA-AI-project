"""
PDF Report Generator
Builds a PDF version of an existing scan result (the same data already
shown on the result page). Does not invent or fetch any new data - it
only formats what the application already computed and stored.
"""

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    ListFlowable,
    ListItem,
)

_styles = getSampleStyleSheet()

_CELL_STYLE = ParagraphStyle(
    "ReportCell", parent=_styles["BodyText"], fontSize=9, leading=12
)

_LABEL_STYLE = ParagraphStyle(
    "ReportLabel", parent=_CELL_STYLE, textColor=colors.HexColor("#555555")
)

_SMALL_STYLE = ParagraphStyle(
    "ReportSmall", parent=_styles["BodyText"], fontSize=9,
    textColor=colors.HexColor("#666666")
)


def _info_table(rows):
    data = [
        [Paragraph(str(label), _LABEL_STYLE), Paragraph(str(value), _CELL_STYLE)]
        for label, value in rows
    ]

    table = Table(data, colWidths=[1.6 * inch, 4.4 * inch])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
    ]))

    return table


def _bullet_list(items):
    return ListFlowable(
        [ListItem(Paragraph(str(item), _CELL_STYLE)) for item in items],
        bulletType="bullet",
        leftIndent=14,
    )


def generate_pdf_report(result_data, scan_id):
    """
    Build a PDF report from an existing scan result dict (the same
    structure stored in app.py's scan_results / shown on result.html).

    Returns a BytesIO positioned at the start of the PDF content.
    """

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=f"YARA AI Report - {scan_id}",
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    heading = _styles["Heading2"]
    body = _styles["BodyText"]

    elements = []

    # ------------------------------------------------------------
    # HEADER
    # ------------------------------------------------------------

    elements.append(Paragraph("YARA AI - Security Analysis Report", _styles["Title"]))

    elements.append(Paragraph(
        f"Scan ID: {scan_id} &nbsp;|&nbsp; "
        f"Report ID: {result_data.get('report_id', 'N/A')}",
        _SMALL_STYLE
    ))

    elements.append(Spacer(1, 0.25 * inch))

    # ------------------------------------------------------------
    # FILE INFORMATION
    # ------------------------------------------------------------

    elements.append(Paragraph("File Information", heading))

    elements.append(_info_table([
        ("Filename", result_data.get("filename", "Unknown")),
        ("File Size", result_data.get("file_size", "Unknown")),
        ("File Type", result_data.get("file_type", "Unknown")),
        ("SHA-256", result_data.get("sha256", "Unknown")),
        ("MD5", result_data.get("md5", "Unknown")),
        ("Entropy", result_data.get("entropy", "Unknown")),
        ("Scan Date", result_data.get("scan_date", "Unknown")),
    ]))

    elements.append(Spacer(1, 0.2 * inch))

    # ------------------------------------------------------------
    # RISK ASSESSMENT
    # ------------------------------------------------------------

    elements.append(Paragraph("Risk Assessment", heading))

    elements.append(_info_table([
        ("Threat Level", result_data.get("threat_level", "Unknown")),
        ("Risk Score", result_data.get("confidence", "Unknown")),
        ("Status", result_data.get("status", "Unknown")),
    ]))

    risk_indicators = result_data.get("risk_indicators") or []

    if risk_indicators:
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph("Risk Indicators:", body))
        elements.append(_bullet_list(risk_indicators))

    elements.append(Spacer(1, 0.2 * inch))

    # ------------------------------------------------------------
    # YARA DETECTION
    # ------------------------------------------------------------

    yara_matches = result_data.get("yara_matches", 0)

    elements.append(Paragraph(
        f"YARA Detection ({yara_matches} rule(s) matched)", heading
    ))

    yara_rules = result_data.get("yara_rules") or []

    if yara_rules:

        for rule in yara_rules:

            elements.append(Paragraph(
                f"<b>{rule.get('name', 'Unknown Rule')}</b> "
                f"(namespace: {rule.get('namespace', 'default')})",
                body
            ))

            if rule.get("tags"):
                elements.append(Paragraph(
                    f"Tags: {', '.join(rule['tags'])}", _SMALL_STYLE
                ))

            if rule.get("indicators"):
                elements.append(_bullet_list(rule["indicators"]))

            elements.append(Spacer(1, 0.1 * inch))

    else:
        elements.append(Paragraph("No YARA rules matched this file.", body))

    elements.append(Spacer(1, 0.2 * inch))

    # ------------------------------------------------------------
    # AI ANALYSIS
    # ------------------------------------------------------------

    ai = result_data.get("ai") or {}

    elements.append(Paragraph("AI Analysis", heading))

    if ai.get("processing"):

        elements.append(Paragraph(
            "AI analysis was still in progress when this report was "
            "generated. Re-download the report after the analysis "
            "completes on the result page.",
            body
        ))

    else:

        if ai.get("error"):
            elements.append(Paragraph(
                f"<b>AI Analysis Error:</b> {ai['error']}", body
            ))
            elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("Summary:", body))
        elements.append(Paragraph(
            ai.get("summary") or "No AI summary available.", body
        ))
        elements.append(Spacer(1, 0.1 * inch))

        reasons_title = (
            "Why It Matched" if yara_matches else "Why It Did Not Match"
        )

        elements.append(Paragraph(f"{reasons_title}:", body))

        if ai.get("reasons"):
            elements.append(_bullet_list(ai["reasons"]))
        else:
            elements.append(Paragraph(
                "No detailed reasoning was provided by the AI.", body
            ))

        elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("Evidence:", body))

        if ai.get("evidence"):
            elements.append(_bullet_list(ai["evidence"]))
        else:
            elements.append(Paragraph(
                "No additional evidence was provided.", body
            ))

        elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("AI Risk Assessment:", body))
        elements.append(Paragraph(
            ai.get("risk_assessment") or "No AI risk assessment available.",
            body
        ))

        elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("Recommendations:", body))

        if ai.get("recommendations"):
            elements.append(_bullet_list(ai["recommendations"]))
        else:
            elements.append(Paragraph(
                "No recommendations were provided.", body
            ))

    doc.build(elements)

    buffer.seek(0)

    return buffer
