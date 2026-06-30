import requests
import sys
import json
import os
import socket
import ssl
from datetime import datetime

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections to prevent man-in-the-middle attacks.",
    "X-Frame-Options": "Prevents Clickjacking attacks by restricting framing.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing exploits.",
    "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
    "Referrer-Policy": "Controls how much referral information is shared when leaving the site."
}

def check_ssl_tls(domain):
    """Establishes a secure handshake to audit TLS versions and certificate expiry."""
    clean_domain = domain.replace("https://", "").replace("http://", "").split('/')[0]
    
    ssl_report = {
        "tls_version": "UNKNOWN",
        "certificate_status": "UNKNOWN",
        "days_until_expiry": None
    }

    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((clean_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                ssl_report["tls_version"] = ssock.version()

                cert = ssock.getpeercert()
                expiry_str = cert.get('notAfter')

                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                remaining_days = (expiry_date - datetime.utcnow()).days
                
                ssl_report["days_until_expiry"] = remaining_days
                
                if remaining_days < 0:
                    ssl_report["certificate_status"] = "EXPIRED"
                elif remaining_days < 30:
                    ssl_report["certificate_status"] = "WARNING_EXPIRING_SOON"
                else:
                    ssl_report["certificate_status"] = "VALID"
                    
    except Exception as e:
        ssl_report["certificate_status"] = f"ERROR: Could not establish secure handshake ({str(e)})"
        
    return ssl_report

def audit_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[+] Auditing Response Headers: {url}")
    
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        print(f"  [-] Connection Error: {e}")
        return None

    site_report = {
        "summary": {"passed": 0, "missing": 0},
        "headers_results": {},
        "ssl_tls_results": {}
    }

    for header, description in SECURITY_HEADERS.items():
        header_key = next((k for k in headers if k.lower() == header.lower()), None)
        
        if header_key:
            site_report["headers_results"][header] = {"status": "PASSED", "value": headers[header_key]}
            site_report["summary"]["passed"] += 1
        else:
            site_report["headers_results"][header] = {"status": "MISSING", "risk": description}
            site_report["summary"]["missing"] += 1
            
    print(f"  [=] Header Posture: {site_report['summary']['passed']}/5 Passed")

    print(f"[+] Launching Transport Layer Handshake...")
    ssl_data = check_ssl_tls(url)
    site_report["ssl_tls_results"] = ssl_data
    print(f"  [=] Transport Layer: Protocol={ssl_data['tls_version']}, Status={ssl_data['certificate_status']}")
    
    return site_report

def main():
    if len(sys.argv) < 2:
        print("Usage: python auditor.py [domain OR targets.txt]")
        sys.exit(1)

    target_input = sys.argv[1]
    all_reports = {}

    if os.path.isfile(target_input) and target_input.endswith('.txt'):
        print(f"[+] Bulk Scan Detected. Reading targets from: {target_input}")
        with open(target_input, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        domains = [target_input]

    for domain in domains:
        report = audit_url(domain)
        if report:
            all_reports[domain] = report

    output_filename = "bulk_audit_report.json"
    with open(output_filename, "w") as f:
        json.dump(all_reports, f, indent=4)
        
    print(f"\n[SUCCESS] Aggregated multi-layer audit complete. Output file: {output_filename}")

if __name__ == "__main__":
    main()