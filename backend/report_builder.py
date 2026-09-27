"""Professional multi-format security report generator."""
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak, Image as RLImage)
from pathlib import Path
from datetime import datetime, timezone
import json
import html


def build_pdf_report(filepath: Path, meta: dict, executions: list,
                     screenshots: list, enriched_services: list,
                     audit_verification: dict, authorized_targets: list):
    doc = SimpleDocTemplate(str(filepath), pagesize=letter,
                            rightMargin=0.6 * inch, leftMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("T", parent=styles["Title"], textColor=colors.HexColor("#0a7c2f"), fontSize=26, spaceAfter=8)
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#0a7c2f"), fontSize=16, spaceAfter=10, spaceBefore=16)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#222"), fontSize=12, spaceAfter=6)
    body = ParagraphStyle("B", parent=styles["BodyText"], fontSize=10, leading=14, spaceAfter=6)
    mono = ParagraphStyle("M", parent=styles["Code"], fontSize=8, leading=11, backColor=colors.HexColor("#f4f4f4"))

    story = []

    # COVER
    story.append(Spacer(1, 1 * inch))
    story.append(Paragraph("ZANGBETO", title))
    story.append(Paragraph("<font size=16 color='#555'>Professional Security Assessment Report</font>", styles["Normal"]))
    story.append(Spacer(1, 0.6 * inch))
    cover_data = [
        ["Engagement:", meta.get("engagement_name", "Security Assessment")],
        ["Client:", meta.get("client_name", "Guardian")],
        ["Report Date:", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
        ["Prepared by:", "Zangbeto Orchestrator v1.0"],
        ["Total Commands Executed:", str(len(executions))],
        ["Audit Chain Status:", audit_verification.get("status", "unknown").upper()],
    ]
    t = Table(cover_data, colWidths=[2.2 * inch, 4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f5ec")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0a7c2f")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "<i>This report was generated automatically by Zangbeto. "
        "All actions are recorded in a SHA-256 hash-chained audit log. "
        "Commands executed inside an isolated Kali Linux container.</i>", body))
    story.append(PageBreak())

    # 1. EXECUTIVE SUMMARY
    story.append(Paragraph("1. Executive Summary", h1))
    critical_count = sum(1 for s in enriched_services for c in s.get("cves", []) if c["cvss"] >= 9.0)
    high_count = sum(1 for s in enriched_services for c in s.get("cves", []) if 7.0 <= c["cvss"] < 9.0)
    medium_count = sum(1 for s in enriched_services for c in s.get("cves", []) if 4.0 <= c["cvss"] < 7.0)
    low_count = sum(1 for s in enriched_services for c in s.get("cves", []) if 0 < c["cvss"] < 4.0)

    summary = (
        f"This assessment performed <b>{len(executions)}</b> security operations against "
        f"<b>{len(authorized_targets)}</b> authorized targets.<br/><br/>"
        f"<b>Findings Summary:</b><br/>"
        f"&nbsp;&nbsp;&nbsp;<font color='#ff2d2d'><b>CRITICAL:</b></font> {critical_count} vulnerabilities (CVSS &gt;= 9.0)<br/>"
        f"&nbsp;&nbsp;&nbsp;<font color='#ff8c00'><b>HIGH:</b></font> {high_count} vulnerabilities (CVSS 7.0-8.9)<br/>"
        f"&nbsp;&nbsp;&nbsp;<font color='#ffd21e'><b>MEDIUM:</b></font> {medium_count} vulnerabilities (CVSS 4.0-6.9)<br/>"
        f"&nbsp;&nbsp;&nbsp;<font color='#50c878'><b>LOW:</b></font> {low_count} vulnerabilities (CVSS &lt; 4.0)<br/><br/>"
        f"<b>Immediate action required.</b> Review the Remediation Priority section below."
    )
    story.append(Paragraph(summary, body))

    # 2. SCOPE
    story.append(Paragraph("2. Authorized Scope", h1))
    story.append(Paragraph("The following targets were explicitly authorized for testing:", body))
    for t_ in sorted(authorized_targets):
        story.append(Paragraph(f"&bull; <font face='Courier'>{html.escape(str(t_))}</font>", body))

    # 3. FINDINGS
    story.append(PageBreak())
    story.append(Paragraph("3. Detailed Findings", h1))
    if enriched_services:
        for i, svc in enumerate(enriched_services, 1):
            max_cvss = max((c["cvss"] for c in svc.get("cves", [])), default=0.0)
            sev_color = "#ff2d2d" if max_cvss >= 9 else "#ff8c00" if max_cvss >= 7 else "#ffd21e" if max_cvss >= 4 else "#50c878"
            story.append(Paragraph(
                f"<b>3.{i} Port {svc['port']}/{svc['protocol']} &mdash; {html.escape(svc['service'])}</b>", h2))
            story.append(Paragraph(
                f"<font color='{sev_color}'><b>Version:</b> {html.escape(svc['version'])} | "
                f"<b>Risk:</b> {max_cvss}/10</font>", body))
            if svc.get("cves"):
                cve_rows = [["CVE ID", "CVSS", "Description"]]
                for c in svc["cves"]:
                    cve_rows.append([c["cve"], str(c["cvss"]), c["description"]])
                cve_table = Table(cve_rows, colWidths=[1.2 * inch, 0.6 * inch, 4.7 * inch])
                cve_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
                ]))
                story.append(cve_table)
                story.append(Spacer(1, 6))
                story.append(Paragraph(
                    f"<b>What this means:</b> An attacker could potentially exploit this service. "
                    f"Update to the latest patch immediately. "
                    f"<b>How to fix:</b> Run <font face='Courier'>apt update &amp;&amp; apt upgrade {svc['service']}</font> "
                    f"or consult the vendor's security advisory.", body))
            else:
                story.append(Paragraph(
                    f"<i>No known CVEs in our knowledge base. Continue to monitor for updates.</i>", body))
            story.append(Spacer(1, 14))
    else:
        story.append(Paragraph("<i>No exploitable services detected.</i>", body))

    # 4. VISUAL FINDINGS
    story.append(PageBreak())
    story.append(Paragraph("4. Visual Findings (Annotated)", h1))
    story.append(Paragraph(
        "Screenshots are automatically colored: "
        "<font color='#ff2d2d'><b>RED</b></font> = CRITICAL, "
        "<font color='#ff8c00'><b>ORANGE</b></font> = HIGH, "
        "<font color='#ffd21e'><b>YELLOW</b></font> = MEDIUM, "
        "<font color='#50c878'><b>GREEN</b></font> = LOW.", body))
    story.append(Spacer(1, 12))
    if screenshots:
        for shot in screenshots[:6]:
            try:
                img = RLImage(str(shot), width=7 * inch, height=3.7 * inch)
                story.append(img)
                story.append(Paragraph(f"<i>{shot.name}</i>", mono))
                story.append(Spacer(1, 12))
            except Exception as e:
                story.append(Paragraph(f"<i>Could not embed {shot.name}: {e}</i>", body))
    else:
        story.append(Paragraph("<i>No visual findings captured.</i>", body))

    # 5. REMEDIATION PRIORITY
    story.append(PageBreak())
    story.append(Paragraph("5. Remediation Priority", h1))
    all_cves = []
    for svc in enriched_services:
        for c in svc.get("cves", []):
            all_cves.append({**c, "port": svc["port"], "service": svc["service"]})
    all_cves.sort(key=lambda x: x["cvss"], reverse=True)

    if all_cves:
        rows = [["Priority", "CVE", "CVSS", "Service", "Fix By"]]
        for c in all_cves[:20]:
            priority = "P0" if c["cvss"] >= 9 else "P1" if c["cvss"] >= 7 else "P2" if c["cvss"] >= 4 else "P3"
            fix_by = "24h" if c["cvss"] >= 9 else "7 days" if c["cvss"] >= 7 else "30 days" if c["cvss"] >= 4 else "90 days"
            rows.append([priority, c["cve"], str(c["cvss"]), c["service"], fix_by])
        rem_table = Table(rows, colWidths=[0.7 * inch, 1.5 * inch, 0.6 * inch, 1.7 * inch, 1.0 * inch])
        rem_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a7c2f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ]))
        story.append(rem_table)
    else:
        story.append(Paragraph("<i>No vulnerabilities requiring remediation.</i>", body))

    # 6. AUDIT CHAIN
    story.append(PageBreak())
    story.append(Paragraph("6. Audit Chain Verification", h1))
    story.append(Paragraph(
        f"<b>Status:</b> {'&#10003; VERIFIED' if audit_verification.get('status') == 'ok' else '&#10007; ISSUE DETECTED'}<br/>"
        f"<b>Entries:</b> {audit_verification.get('entries', 0)}<br/>"
        f"<b>Message:</b> {audit_verification.get('message', '')}<br/><br/>"
        f"Uses SHA-256 hash chaining. Any modification to a past entry breaks the chain.", body))

    # 7. FULL EXECUTION LOG
    story.append(Paragraph("7. Full Execution Log", h1))
    if executions:
        rows = [["#", "Time (UTC)", "Action", "Command"]]
        for i, e in enumerate(executions[-40:], 1):
            ts = e.get("timestamp", "")[:19].replace("T", " ")
            action = e.get("action", "")
            cmd = e.get("details", {}).get("command", "")
            if len(cmd) > 70:
                cmd = cmd[:67] + "..."
            rows.append([str(i), ts, action, cmd])
        exec_table = Table(rows, colWidths=[0.4 * inch, 1.3 * inch, 1.4 * inch, 3.9 * inch])
        exec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ]))
        story.append(exec_table)

    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        f"<i>Report generated by Zangbeto Orchestrator on "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. "
        f"CONFIDENTIAL &mdash; For authorized recipients only.</i>", body))

    doc.build(story)
    return filepath


def build_markdown_report(filepath: Path, meta: dict, executions: list,
                          enriched_services: list, audit_verification: dict,
                          authorized_targets: list):
    lines = []
    lines.append(f"# {meta.get('engagement_name', 'Security Assessment')}\n")
    lines.append(f"**Client:** {meta.get('client_name', 'Guardian')}  ")
    lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"**Prepared by:** Zangbeto Orchestrator v1.0\n")
    lines.append("---\n")
    lines.append("## Executive Summary\n")
    lines.append(f"- Total commands executed: **{len(executions)}**")
    lines.append(f"- Authorized targets: **{len(authorized_targets)}**")
    lines.append(f"- Audit chain status: **{audit_verification.get('status', 'unknown').upper()}**\n")
    lines.append("## Findings\n")
    for i, svc in enumerate(enriched_services, 1):
        max_cvss = max((c["cvss"] for c in svc.get("cves", [])), default=0.0)
        lines.append(f"### {i}. Port {svc['port']}/{svc['protocol']} &mdash; {svc['service']}")
        lines.append(f"**Version:** {svc['version']}  ")
        lines.append(f"**Risk Score:** {max_cvss}/10\n")
        for c in svc.get("cves", []):
            lines.append(f"- **{c['cve']}** (CVSS {c['cvss']}): {c['description']}")
        lines.append("")
    lines.append("## Audit Chain Verification\n")
    lines.append(f"- Status: {audit_verification.get('status')}")
    lines.append(f"- Entries: {audit_verification.get('entries')}\n")
    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath


def build_json_report(filepath: Path, meta: dict, executions: list,
                     enriched_services: list, audit_verification: dict,
                     authorized_targets: list):
    data = {
        "metadata": meta,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authorized_targets": sorted(authorized_targets),
        "executions": executions,
        "findings": enriched_services,
        "audit_verification": audit_verification,
    }
    filepath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return filepath


def build_html_report(filepath: Path, meta: dict, executions: list,
                     enriched_services: list, audit_verification: dict,
                     authorized_targets: list):
    md_path = filepath.with_suffix(".md")
    build_markdown_report(md_path, meta, executions, enriched_services, audit_verification, authorized_targets)
    try:
        import markdown as md
        html_content = md.markdown(md_path.read_text(encoding="utf-8"))
    except Exception:
        html_content = "<pre>" + html.escape(md_path.read_text(encoding="utf-8")) + "</pre>"
    full_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{meta.get('engagement_name','Report')}</title>
<style>body{{font-family:-apple-system,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#222;line-height:1.6}}
h1,h2,h3{{color:#0a7c2f}}code{{background:#f4f4f4;padding:2px 6px;border-radius:3px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#0a7c2f;color:white}}</style></head>
<body>{html_content}</body></html>"""
    filepath.write_text(full_html, encoding="utf-8")
    return filepath