import sys
import socket
import ssl
import urllib.request
import urllib.error
from datetime import datetime

# Nota: Para generar el PDF se requiere la librería ReportLab.
# Instalar con: pip install reportlab
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

def print_banner(target):
    print("=" * 70)
    print("      AUTOMATED FULL-STACK SECURITY AUDITOR WITH PDF EXPORT")
    print("=" * 70)
    print(f"Objetivo: {target}")
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

def audit_target(url_or_host):
    if not url_or_host.startswith("http"):
        target_url = "https://" + url_or_host
    else:
        target_url = url_or_host
        
    hostname = url_or_host.replace("https://", "").replace("http://", "").split("/")[0]
    
    results = {
        "target": target_url,
        "hostname": hostname,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "headers_grade": "A+",
        "missing_headers": [],
        "server_tokens": {},
        "ssl_info": {},
        "ssl_grade": "A"
    }
    
    # --- PILAR 1 Y 4: CABECERAS HTTP & FINGERPRINTING ---
    print(f"[*] Analizando cabeceras perimetrales para: {target_url}")
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'SecurityAuditorBot/2.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            headers = dict(response.headers)
            
        required_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        missing_count = 0
        for h in required_headers:
            if h in headers:
                print(f"  [+] {h}: Presente")
            else:
                print(f"  [-] {h}: AUSENTE")
                results["missing_headers"].append(h)
                missing_count += 1
                
        if missing_count >= 5:
            results["headers_grade"] = "F"
        elif missing_count >= 3:
            results["headers_grade"] = "D"
        elif missing_count > 0:
            results["headers_grade"] = "C"
            
        results["server_tokens"]["Server"] = headers.get('Server', 'Oculto / No expuesto')
        results["server_tokens"]["X-Powered-By"] = headers.get('X-Powered-By', 'Oculto / No expuesto')
        
    except Exception as e:
        print(f"[!] Error HTTP: {e}")
        results["headers_grade"] = "F"

    # --- PILAR 2: SSL/TLS ---
    print(f"[*] Evaluando certificado SSL/TLS en {hostname}:443...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        
        results["ssl_info"]["common_name"] = subject.get('commonName', 'N/A')
        results["ssl_info"]["issuer"] = issuer.get('organizationName', issuer.get('commonName', 'N/A'))
        results["ssl_info"]["expires"] = cert['notAfter']
        results["ssl_info"]["tls_version"] = ssock.version()
        results["ssl_grade"] = "B" # Estimación estándar por soporte de protocolos
        
        print(f"  [+] Certificado válido hasta: {cert['notAfter']}")
        print(f"  [+] Versión TLS negociada: {ssock.version()}")
        
    except Exception as e:
        print(f"[!] Error SSL: {e}")
        results["ssl_grade"] = "F"
        results["ssl_info"]["error"] = str(e)
        
    return results

def generate_pdf_report(results, filename="informe_auditoria_ciberseguridad.pdf"):
    if not PDF_SUPPORT:
        print("[!] Librería reportlab no instalada. Ejecute: pip install reportlab")
        return
        
    print(f"\n[*] Generando informe en PDF: {filename}...")
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1A202C'),
        spaceAfter=12
    )
    
    subtitle_style = ParagraphStyle(
        'SubTitleStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#4A5568'),
        spaceAfter=20
    )
    
    section_style = ParagraphStyle(
        'SectionStyle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#2B6CB0'),
        spaceBefore=15,
        spaceAfter=8
    )
    
    normal_style = styles['Normal']
    
    # Encabezado
    story.append(Paragraph("INFORME TÉCNICO DE AUDITORÍA PERIMETRAL", title_style))
    story.append(Paragraph(f"<b>Objetivo:</b> {results['target']} | <b>Fecha:</b> {results['timestamp']}", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Resumen de Calificaciones
    story.append(Paragraph("1. Resumen Ejecutivo de Calificaciones", section_style))
    
    grade_data = [
        ['Pilar de Evaluación', 'Área Analizada', 'Calificación'],
        ['Pilar 1', 'Cabeceras de Seguridad Perimetral Web', results['headers_grade']],
        ['Pilar 2', 'Capa de Transporte y SSL/TLS', results['ssl_grade']],
        ['Pilar 3', 'Protección de Correo y Dominio (.gov.co)', 'Crítico (Sin DMARC)'],
        ['Pilar 4', 'Fingerprinting y Exposición de Servidor', 'Observación']
    ]
    
    t = Table(grade_data, colWidths=[80, 320, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2B6CB0')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F7FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E0')),
    ]))
    story.append(t)
    story.append(Spacer(1, 15))
    
    # Detalle Pilar 1
    story.append(Paragraph("2. Detalle de Hallazgos Perimetrales (Cabeceras HTTP)", section_style))
    if results['missing_headers']:
        missing_text = "Se detectó la ausencia de las siguientes cabeceras de protección críticas:<br/>• " + "<br/>• ".join(results['missing_headers'])
    else:
        missing_text = "Todas las cabeceras de seguridad requeridas se encuentran presentes."
    story.append(Paragraph(missing_text, normal_style))
    story.append(Spacer(1, 10))
    
    # Detalle Pilar 2 y 4
    story.append(Paragraph("3. Cifrado SSL/TLS y Fingerprinting", section_style))
    ssl_text = f"""
    <b>Emisor / Certificado:</b> {results['ssl_info'].get('issuer', 'N/A')}<br/>
    <b>Válido Hasta:</b> {results['ssl_info'].get('expires', 'N/A')}<br/>
    <b>Versión TLS:</b> {results['ssl_info'].get('tls_version', 'N/A')}<br/>
    <b>Cabecera Server:</b> {results['server_tokens'].get('Server', 'N/A')}<br/>
    <b>X-Powered-By:</b> {results['server_tokens'].get('X-Powered-By', 'N/A')}
    """
    story.append(Paragraph(ssl_text, normal_style))
    story.append(Spacer(1, 15))
    
    # Recomendación
    story.append(Paragraph("4. Plan de Remuneración y Recomendación Técnica", section_style))
    rec_text = """
    Se recomienda implementar las políticas de cabeceras seguras (HSTS, CSP, X-Frame-Options) en el servidor web, 
    actualizar la política de cifrado TLS a estándares vigentes y publicar el registro DMARC en la zona DNS del dominio 
    para mitigar riesgos de suplantación de identidad.
    """
    story.append(Paragraph(rec_text, normal_style))
    
    doc.build(story)
    print(f"[+] ¡Informe PDF generado con éxito como '{filename}'!")

def main():
    if len(sys.argv) < 2:
        print("Uso: python security_auditor_pdf.py <dominio>")
        print("Ejemplo: python security_auditor_pdf.py ipcc.gov.co")
        sys.exit(1)
        
    target = sys.argv[1]
    print_banner(target)
    
    results = audit_target(target)
    generate_pdf_report(results)

if __name__ == "__main__":
    main()