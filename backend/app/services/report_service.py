import os
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.units import inch
from app.core.config import settings
import logging

logger = logging.getLogger("smartshield.reports")

def generate_scan_pdf(scan_data: dict, output_filename: str) -> str:
    """
    Generates a professional PDF report for a completed scan.
    """
    output_path = os.path.join(settings.PDF_DIR, output_filename)
    os.makedirs(settings.PDF_DIR, exist_ok=True)
    
    # Establish document template
    doc = SimpleDocTemplate(
        output_path, 
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom premium styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#0F172A'), # Slate 900
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748B'), # Slate 500
        spaceAfter=25
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#1E293B'), # Slate 800
        spaceBefore=15,
        spaceAfter=10
    )
    
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155') # Slate 700
    )
    
    bold_body_style = ParagraphStyle(
        'BoldBodyCustom',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    # Alert banner styling based on verdict
    verdict = scan_data.get("fusion_result", {}).get("category", "Safe")
    verdict_colors = {
        "Safe": {
            "bg": "#DCFCE7", # Light green
            "text": "#166534",
            "border": "#86EFAC"
        },
        "Suspicious": {
            "bg": "#FEF3C7", # Light amber
            "text": "#92400E",
            "border": "#FCD34D"
        },
        "Dangerous": {
            "bg": "#FEE2E2", # Light red
            "text": "#991B1B",
            "border": "#FCA5A5"
        }
    }
    
    v_style = verdict_colors.get(verdict, verdict_colors["Safe"])
    
    story = []
    
    # Title & Metadata Header
    story.append(Paragraph("SmartShield AI Threat Assessment", title_style))
    meta_text = f"<b>Report ID:</b> {scan_data.get('_id', 'N/A')} | <b>Scan Type:</b> {scan_data.get('type', 'N/A').upper()} | <b>Date:</b> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    story.append(Paragraph(meta_text, subtitle_style))
    story.append(Spacer(1, 10))
    
    # Alert Verdict Banner
    verdict_html = f"<font size='14'><b>VERDICT: {verdict.upper()}</b></font><br/>Risk Score: {scan_data.get('fusion_result', {}).get('final_score', 0.0)}/100 | Confidence: {scan_data.get('fusion_result', {}).get('confidence', 0.0)}%"
    verdict_p = Paragraph(verdict_html, ParagraphStyle('VerdictText', parent=body_style, textColor=colors.HexColor(v_style["text"]), leading=18))
    
    verdict_table = Table([[verdict_p]], colWidths=[doc.width])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(v_style["bg"])),
        ('PADDING', (0,0), (-1,-1), 12),
        ('BOX', (0,0), (-1,-1), 1.5, colors.HexColor(v_style["border"])),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 20))
    
    # Section: Input Analyzed
    story.append(Paragraph("Input Analyzed", section_heading))
    input_data = scan_data.get("input_data", {})
    input_content = input_data.get("content") or input_data.get("url") or "Uploaded File"
    
    if len(input_content) > 300:
        input_content = input_content[:300] + "..."
        
    input_table = Table([[Paragraph(f"<code>{input_content}</code>", body_style)]], colWidths=[doc.width])
    input_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    story.append(input_table)
    story.append(Spacer(1, 15))
    
    # Section: AI Explanation
    story.append(Paragraph("Risk Breakdown & AI Analysis", section_heading))
    explanation_text = scan_data.get("fusion_result", {}).get("explanation", "No explanation details available.")
    story.append(Paragraph(explanation_text, body_style))
    story.append(Spacer(1, 15))
    
    # Score Matrix Table
    qwen_score = scan_data.get("qwen_result", {}).get("score", 0.0) if scan_data.get("qwen_result") else "N/A"
    intel_score = scan_data.get("threat_intel_score", "N/A")
    reputation_score = scan_data.get("url_metadata", {}).get("risk_score", "N/A") if scan_data.get("url_metadata") else "N/A"
    
    matrix_data = [
        [Paragraph("<b>Evaluation Engine</b>", bold_body_style), Paragraph("<b>Risk Score (0-100)</b>", bold_body_style), Paragraph("<b>Verdict</b>", bold_body_style)],
        ["AI Vision & Content Analysis", str(qwen_score), scan_data.get("qwen_result", {}).get("category", "N/A") if scan_data.get("qwen_result") else "N/A"],
    ]
    
    if scan_data.get("type") == "url":
        matrix_data.append(["Threat Intelligence Feeds", str(intel_score), "Dangerous" if isinstance(intel_score, (int,float)) and intel_score > 40 else "Safe"])
        matrix_data.append(["Domain Reputation Analyzer", str(reputation_score), "Suspicious" if isinstance(reputation_score, (int,float)) and reputation_score > 30 else "Safe"])
        
    matrix_table = Table(matrix_data, colWidths=[200, 150, 150])
    matrix_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
    ]))
    story.append(matrix_table)
    story.append(Spacer(1, 15))
    
    # Section: Recommendations
    story.append(Paragraph("Security Recommendations", section_heading))
    recs = scan_data.get("fusion_result", {}).get("recommendations", [])
    for rec in recs:
        story.append(Paragraph(f"• {rec}", body_style))
        story.append(Spacer(1, 4))
        
    # Append Sandbox Evidence (Screenshot + details) if URL scan
    sandbox = scan_data.get("sandbox_report")
    if sandbox and sandbox.get("executed"):
        story.append(PageBreak())
        story.append(Paragraph("Sandbox Verification Evidence", section_heading))
        
        # Check screenshot exists on disk
        screenshot_url = sandbox.get("screenshot_url")
        if screenshot_url:
            filename = screenshot_url.split("/")[-1]
            screenshot_path = os.path.join(settings.SCREENSHOT_DIR, filename)
            
            if os.path.exists(screenshot_path):
                try:
                    # Scaling image to fit page width
                    img = Image(screenshot_path, width=6.5*inch, height=4*inch)
                    story.append(Paragraph("<b>Browser Sandbox Screenshot Capture:</b>", bold_body_style))
                    story.append(Spacer(1, 5))
                    story.append(img)
                    story.append(Spacer(1, 15))
                except Exception as img_err:
                    logger.error(f"Failed to render screenshot in ReportLab: {img_err}")
                    
        # Sandbox behavior log summaries
        story.append(Paragraph("<b>Sandbox Behavior Logs:</b>", bold_body_style))
        story.append(Spacer(1, 5))
        
        findings = sandbox.get("behavior_findings", [])
        if not findings:
            findings = ["No suspicious redirects, automatic downloads, or login forms were flagged inside sandbox browser."]
            
        for fd in findings:
            story.append(Paragraph(f"- {fd}", body_style))
            story.append(Spacer(1, 4))
            
    # Build document
    doc.build(story)
    return output_path
