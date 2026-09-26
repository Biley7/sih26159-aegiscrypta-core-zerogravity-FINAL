import io
from typing import List, Optional
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String
from app.models import CheckResult, CheckStatus


def generate_pdf_report(
    domain: str,
    score: int,
    checks: List[CheckResult],
    recommendations: List[str],
    scanned_at: str,
    fuzzy_score: Optional[float] = None,
    linguistic_classification: Optional[str] = None,
    antecedent_scores: Optional[dict] = None,
    playbook: Optional[object] = None
) -> io.BytesIO:
    """
    Generates a professional PDF audit report using reportlab.
    Includes:
    - Domain & timestamp
    - Score with colored progress bar visual
    - Hierarchical fuzzy risk explainability breakdown
    - Per-check breakdown table (Check, Status, Details)
    - Actionable mitigation recommendations & playbook directives
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0F172A")
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=16,
        textColor=colors.HexColor("#64748B")
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    bold_cell_style = ParagraphStyle(
        "BoldCell",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0F172A")
    )

    rec_style = ParagraphStyle(
        "RecStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#1E293B")
    )

    code_style = ParagraphStyle(
        "DocCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("AegisCrypta — Forensic Email Security Audit", title_style))
    class_info = f" &nbsp;|&nbsp; Classification: <b>{linguistic_classification}</b>" if linguistic_classification else ""
    story.append(Paragraph(f"Target Domain: <b>{domain}</b> &nbsp;|&nbsp; Scan Date: {scanned_at}{class_info}", subtitle_style))
    story.append(Spacer(1, 14))

    # 2. Score Visual Section
    if score >= 80:
        score_color = colors.HexColor("#16A34A")  # Green
        status_text = "STRONG POSTURE"
    elif score >= 50:
        score_color = colors.HexColor("#D97706")  # Amber
        status_text = "MODERATE POSTURE (ACTION NEEDED)"
    else:
        score_color = colors.HexColor("#DC2626")  # Red
        status_text = "CRITICAL RISKS DETECTED"

    bar_width = 530
    bar_height = 16
    progress_width = max(8, int((score / 100.0) * bar_width))

    d = Drawing(bar_width, 40)
    d.add(Rect(0, 10, bar_width, bar_height, rx=4, ry=4, fillColor=colors.HexColor("#E2E8F0"), strokeColor=None))
    d.add(Rect(0, 10, progress_width, bar_height, rx=4, ry=4, fillColor=score_color, strokeColor=None))
    
    score_label = f"Overall Posture Score: {score} / 100  —  {status_text}"
    if fuzzy_score is not None:
        score_label += f" (Fuzzy FIS Score: {fuzzy_score:.1f})"
    d.add(String(0, 30, score_label, fontName="Helvetica-Bold", fontSize=10, fillColor=colors.HexColor("#0F172A")))
    story.append(d)
    story.append(Spacer(1, 14))

    # 3. Hierarchical Fuzzy Logic Antecedents
    if antecedent_scores:
        story.append(Paragraph("Hierarchical Fuzzy Logic Antecedents (Tier 1 & 2 Fusion)", section_heading))
        fuzzy_table_data = [
            [
                Paragraph("<b>Antecedent Metric</b>", bold_cell_style),
                Paragraph("<b>Normalized Score</b>", bold_cell_style),
                Paragraph("<b>Status Verdict</b>", bold_cell_style)
            ]
        ]
        for ant_key, ant_val in antecedent_scores.items():
            pct = round(ant_val * 100, 1)
            if ant_val >= 0.75:
                status_html = '<font color="#16A34A"><b>[ EXCELLENT ]</b></font>'
            elif ant_val >= 0.5:
                status_html = '<font color="#D97706"><b>[ ACCEPTABLE ]</b></font>'
            else:
                status_html = '<font color="#DC2626"><b>[ DEFICIT ]</b></font>'
            fuzzy_table_data.append([
                Paragraph(ant_key.replace('_', ' ').title(), body_style),
                Paragraph(f"{pct}% ({ant_val:.2f})", bold_cell_style),
                Paragraph(status_html, body_style)
            ])
        f_table = Table(fuzzy_table_data, colWidths=[200, 130, 200])
        f_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ]))
        story.append(f_table)
        story.append(Spacer(1, 14))

    # 4. Per-Check Breakdown Table
    story.append(Paragraph("Security Checks Evaluation", section_heading))

    table_data = [
        [
            Paragraph("<b>Check</b>", bold_cell_style),
            Paragraph("<b>Status</b>", bold_cell_style),
            Paragraph("<b>Details & Findings</b>", bold_cell_style)
        ]
    ]

    for check in checks:
        if check.status == CheckStatus.PASS:
            st_html = '<font color="#16A34A"><b>[ PASS ]</b></font>'
        elif check.status == CheckStatus.WARN:
            st_html = '<font color="#D97706"><b>[ WARN ]</b></font>'
        elif check.status == CheckStatus.FAIL:
            st_html = '<font color="#DC2626"><b>[ FAIL ]</b></font>'
        else:
            st_html = '<font color="#64748B"><b>[ UNKNOWN ]</b></font>'

        details_txt = ""
        if isinstance(check.details, dict):
            if "message" in check.details:
                details_txt = str(check.details["message"])
            elif "record" in check.details and check.details["record"]:
                details_txt = f"Record: {check.details['record']}"
            elif "primary_mx" in check.details:
                mx_name = check.details['primary_mx']
                stls = check.details.get("starttls", {})
                stls_msg = stls.get("message", "STARTTLS verified")
                details_txt = f"MX: {mx_name} — {stls_msg}"
            else:
                details_txt = ", ".join(f"{k}: {v}" for k, v in check.details.items() if k not in ["tokens", "all_records"])
        else:
            details_txt = str(check.details)

        table_data.append([
            Paragraph(f"<b>{check.name}</b>", bold_cell_style),
            Paragraph(st_html, body_style),
            Paragraph(details_txt, body_style)
        ])

    check_table = Table(table_data, colWidths=[100, 75, 355])
    check_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
    ]))
    story.append(check_table)
    story.append(Spacer(1, 14))

    # 5. Mitigation Recommendations Section
    rec_block = []
    rec_block.append(Paragraph("Actionable Mitigation Recommendations", section_heading))

    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            rec_text = f"<b>{i}.</b> {rec}"
            rec_block.append(Paragraph(rec_text, rec_style))
            rec_block.append(Spacer(1, 4))
    else:
        rec_block.append(Paragraph("✓ No immediate mitigations required. All inspected controls satisfy best security practices.", rec_style))

    story.append(KeepTogether(rec_block))
    story.append(Spacer(1, 14))

    # 6. Automated Hardening Snippets (if playbook present)
    if playbook and hasattr(playbook, 'postfix_main_cf') and playbook.postfix_main_cf:
        pb_block = [
            Paragraph("Automated Hardening Directives (Postfix Snippet)", section_heading),
            Paragraph(playbook.postfix_main_cf[:350].replace('\n', '<br/>'), code_style),
            Spacer(1, 10)
        ]
        story.append(KeepTogether(pb_block))

    # 7. Footer Note
    footer_text = "Generated by AegisCrypta Forensics Engine API — Dual-Paradigm Email Security Platform (SIH 26159 / NTRO Architecture Standards)."
    story.append(Paragraph(footer_text, subtitle_style))

    doc.build(story)
    buffer.seek(0)
    return buffer
