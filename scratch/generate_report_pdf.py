import os
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.units import inch

def build_pdf():
    md_path = os.path.join(os.path.dirname(__file__), "..", "project_report.md")
    pdf_path = os.path.join(os.path.dirname(__file__), "..", "project_report.pdf")
    
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=10
    )

    h1_style = ParagraphStyle(
        'Heading1Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#334155'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'BulletCustom',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1E293B'),
        backColor=colors.HexColor('#F8FAFC'),
        borderColor=colors.HexColor('#E2E8F0'),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=8
    )

    story = []

    lines = md_text.splitlines()
    in_code_block = False
    code_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check code block
        if line.startswith("```"):
            if in_code_block:
                code_content = "\n".join(code_lines)
                # Escaping HTML tags for reportlab
                code_content = code_content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                formatted_code = "<br/>".join(code_content.splitlines())
                story.append(Paragraph(f"<code>{formatted_code}</code>", code_style))
                story.append(Spacer(1, 6))
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        if not line.strip():
            i += 1
            continue

        if line.startswith("---"):
            story.append(Spacer(1, 4))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CBD5E1'), spaceAfter=8, spaceBefore=4))
            i += 1
            continue

        # Headers
        if line.startswith("# "):
            text = line[2:].strip()
            story.append(Paragraph(text, title_style))
            i += 1
            continue

        if line.startswith("## "):
            text = line[3:].strip()
            story.append(Paragraph(text, h1_style))
            i += 1
            continue

        if line.startswith("### "):
            text = line[4:].strip()
            story.append(Paragraph(text, h2_style))
            i += 1
            continue

        # Convert markdown bold/italic/code
        formatted_line = line
        formatted_line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', formatted_line)
        formatted_line = re.sub(r'\*(.*?)\*', r'<i>\1</i>', formatted_line)
        formatted_line = re.sub(r'`(.*?)`', r'<code>\1</code>', formatted_line)
        formatted_line = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2"><u>\1</u></a>', formatted_line)

        # Bullets
        if line.strip().startswith("* ") or line.strip().startswith("- "):
            clean_text = formatted_line.strip()[2:]
            story.append(Paragraph(f"• {clean_text}", bullet_style))
        elif re.match(r'^\d+\.\s', line.strip()):
            clean_text = formatted_line.strip()
            story.append(Paragraph(clean_text, bullet_style))
        else:
            story.append(Paragraph(formatted_line, body_style))

        i += 1

    doc.build(story)
    print(f"Successfully generated pdf report at: {pdf_path}")

if __name__ == "__main__":
    build_pdf()
