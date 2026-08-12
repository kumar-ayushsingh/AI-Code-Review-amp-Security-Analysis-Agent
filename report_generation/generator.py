import io
import html
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

def generate_pdf_report(summary: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter, 
        rightMargin=50, 
        leftMargin=50, 
        topMargin=50, 
        bottomMargin=50
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    styles.add(ParagraphStyle(
        name='Code', 
        fontName='Courier', 
        fontSize=8, 
        leading=10, 
        backColor=colors.whitesmoke, 
        spaceBefore=6, 
        spaceAfter=6, 
        leftIndent=10,
        rightIndent=10,
        borderColor=colors.silver,
        borderWidth=1,
        borderPadding=6
    ))
    styles.add(ParagraphStyle(
        name='Heading3_Custom', 
        parent=styles['Heading3'], 
        spaceBefore=12, 
        spaceAfter=6, 
        textColor=colors.darkblue
    ))
    styles.add(ParagraphStyle(
        name='OverviewText',
        parent=styles['Normal'],
        leading=14
    ))
    
    Story = []
    
    # Title
    Story.append(Paragraph("CodeGuard Security & Analysis Report", styles['Title']))
    Story.append(Spacer(1, 12))
    
    # Overview
    filename = summary.get("filename") or "Unknown File"
    Story.append(Paragraph(f"<b>File Analyzed:</b> {html.escape(filename)}", styles['Normal']))
    Story.append(Spacer(1, 6))
    
    overview = summary.get("executive_overview") or ""
    Story.append(Paragraph("<b>Executive Overview:</b>", styles['Heading3']))
    Story.append(Paragraph(html.escape(overview), styles['OverviewText']))
    Story.append(Spacer(1, 12))
    
    # Quality Score Calculation
    bd = summary.get("severity_breakdown", {})
    total = bd.get("total", 0)
    crit = bd.get("critical", 0)
    high = bd.get("high", 0)
    med = bd.get("medium", 0)
    low = bd.get("low", 0)
    
    score = 100 - (crit * 20) - (high * 10) - (med * 5) - (low * 2)
    score = max(0, min(100, score))
    
    # Color code the score
    score_color = "green" if score >= 80 else ("orange" if score >= 50 else "red")
    
    Story.append(Paragraph(
        f"<b>Overall Quality Assessment Score:</b> <font color='{score_color}'>{score} / 100</font>", 
        styles['Heading3_Custom']
    ))
    Story.append(Spacer(1, 12))
    
    # Breakdown Table
    Story.append(Paragraph("<b>Severity Breakdown:</b>", styles['Heading3']))
    data = [
        ["Severity", "Count"],
        ["Critical", crit],
        ["High", high],
        ["Medium", med],
        ["Low", low],
        ["Total", total]
    ]
    t = Table(data, colWidths=[150, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('BACKGROUND', (0,1), (-1,-2), colors.beige),
        ('BACKGROUND', (0,-1), (-1,-1), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    Story.append(t)
    Story.append(Spacer(1, 24))
    
    # Detailed Findings
    Story.append(Paragraph("<b>Detailed Findings & Remediations</b>", styles['Heading2']))
    Story.append(Spacer(1, 12))
    
    fixes = summary.get("prioritized_fixes", [])
    if not fixes:
        Story.append(Paragraph("No findings found. Excellent work!", styles['Normal']))
    
    for idx, f in enumerate(fixes):
        ftype = html.escape(f.get('finding_type') or 'Unknown')
        sev = html.escape((f.get('severity') or 'Unknown').upper())
        line = f.get('line_number', 'N/A')
        issue = html.escape(f.get('issue_summary') or '')
        action = html.escape(f.get('remediation_applied') or '')
        orig = f.get('original_code') or ''
        mod = f.get('modified_code') or ''
        
        sev_color = "red" if sev == "CRITICAL" else ("darkorange" if sev == "HIGH" else ("goldenrod" if sev == "MEDIUM" else "green"))
        
        Story.append(Paragraph(
            f"<b>{idx+1}. {ftype}</b> (Severity: <font color='{sev_color}'>{sev}</font>, Line: {line})", 
            styles['Heading3_Custom']
        ))
        Story.append(Paragraph(f"<b>Issue:</b> {issue}", styles['Normal']))
        Story.append(Paragraph(f"<b>Remediation:</b> {action}", styles['Normal']))
        Story.append(Spacer(1, 6))
        
        if orig:
            Story.append(Paragraph("<b>Original Code:</b>", styles['Normal']))
            orig_text = html.escape(orig).replace('\n', '<br/>').replace('  ', '&nbsp;&nbsp;')
            Story.append(Paragraph(orig_text, styles['Code']))
        
        if mod:
            Story.append(Paragraph("<b>Modified Code:</b>", styles['Normal']))
            mod_text = html.escape(mod).replace('\n', '<br/>').replace('  ', '&nbsp;&nbsp;')
            Story.append(Paragraph(mod_text, styles['Code']))
            
        Story.append(Spacer(1, 12))
        
    doc.build(Story)
    
    return buffer.getvalue()
