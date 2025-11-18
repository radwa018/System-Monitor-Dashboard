from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import datetime
import os

def generate_report(data):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"static/reports/system_report_{timestamp}.pdf"
    os.makedirs("static/reports", exist_ok=True)
    
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("System Security Report", styles['Title']))
    story.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 0.3*inch))

    story.append(Paragraph("System Information", styles['Heading2']))
    info_table = [
        ["Hostname", data.get('node', 'N/A')],
        ["OS", data.get('system', 'N/A')],
        ["Uptime", data.get('uptime', 'N/A')],
        ["CPU Usage", f"{data.get('cpu_usage', 0)}%"],
        ["Memory", f"{data.get('memory_used', 0)} GB / {data.get('memory_total', 0)} GB ({data.get('memory_percent', 0)}%)"],
        ["Disk Usage", f"{data.get('disk_percent', 0)}%"],
    ]
    story.append(Table(info_table, colWidths=[200, 300]))
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("Open Ports & Security Alerts", styles['Heading2']))
    ports = data.get('open_ports', [])
    port_data = [["IP", "Port", "Process", "PID", "Status"]]
    for p in ports:
        status = "SUSPICIOUS ⚠" if p.get('suspicious') else "Normal"
        color = colors.red if p.get('suspicious') else colors.green
        port_data.append([p['ip'], str(p['port']), p['process'], str(p['pid'] or 'N/A'), status])
    
    table = Table(port_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,-1), (-1,-1), colors.lightgrey),
    ]))
    story.append(table)

    doc.build(story)
    return filename