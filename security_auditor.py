#!/usr/bin/env python3
"""
================================================================================
SCRIPT DE AUTOMATIZACIÓN DE AUDITORÍA PASIVA FULL-STACK (MULTI-PILAR)
Descripción: Automatiza la revisión perimetral de cabeceras HTTP, inspección SSL/TLS
             y detección de firmas (Fingerprinting) para informes técnicos.
================================================================================
"""

import sys
import socket
import ssl
import urllib.request
import urllib.error
from datetime import datetime

def print_banner(target):
    print("=" * 70)
    print("      AUTOMATED FULL-STACK PASSIVE SECURITY AUDITOR")
    print("=" * 70)
    print(f"Objetivo: {target}")
    print(f"Fecha de ejecución: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

def audit_http_headers(url):
    """Pilar 1 y Pilar 4: Revisión de cabeceras de seguridad y Server Tokens"""
    print(f"[*] Analizando cabeceras perimetrales y fingerprinting para: {url}")
    
    if not url.startswith("http"):
        url = "https://" + url
        
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 SecurityAuditorBot'})
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
        
        print("\n--- [PILAR 1: CABECERAS DE SEGURIDAD WEB] ---")
        missing_count = 0
        for h in required_headers:
            if h in headers:
                print(f"  [+] {h}: Presente")
            else:
                print(f"  [-] {h}: AUSENTE (Brecha perimetral)")
                missing_count += 1
                
        print(f"\nResultado Pilar 1: {'CALIFICACIÓN F (Múltiples ausencias)' if missing_count > 3 else 'Calificación Parcial'}")
        
        print("\n--- [PILAR 4: FINGERPRINTING & SERVER TOKENS] ---")
        server_sig = headers.get('Server', 'No expuesto / Oculto')
        powered_by = headers.get('X-Powered-By', 'No expuesto / Oculto')
        print(f"  [i] Cabecera Server: {server_sig}")
        print(f"  [i] Cabecera X-Powered-By: {powered_by}")
        
    except urllib.error.URLError as e:
        print(f"[!] Error de conexión HTTP: {e.reason}")
    except Exception as e:
        print(f"[!] Error inesperado en HTTP: {e}")

def audit_ssl_certificate(hostname):
    """Pilar 2: Validación del cifrado y certificado SSL/TLS"""
    print(f"\n--- [PILAR 2: CAPA DE TRANSPORTE SSL/TLS] ---")
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[*] Evaluando socket seguro en {hostname}:443...")
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        not_after = cert['notAfter']
        
        print(f"  [+] Common Name (CN): {subject.get('commonName', 'N/A')}")
        print(f"  [+] Emisor: {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
        print(f"  [+] Válido hasta: {not_after}")
        print(f"  [+] Versión TLS negociada: {ssock.version()}")
        print(f"  [i] Estado: Certificado activo y con cadena de confianza.")
        
    except socket.gaierror:
        print(f"[!] No se pudo resolver el hostname: {hostname}")
    except Exception as e:
        print(f"[!] Error al evaluar el certificado SSL: {e}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python security_auditor_fullstack.py <dominio>")
        print("Ejemplo: python security_auditor_fullstack.py ipcc.gov.co")
        sys.exit(1)
        
    target = sys.argv[1]
    print_banner(target)
    
    audit_http_headers(target)
    audit_ssl_certificate(target)
    
    print("\n" + "=" * 70)
    print("Auditoría pasiva full-stack automatizada finalizada con éxito.")
    print("=" * 70)

if __name__ == "__main__":
    main()