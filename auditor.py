import requests
import sys
import json

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections to prevent man-in-the-middle attacks.",
    "X-Frame-Options": "Prevents Clickjacking attacks by restricting framing.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing exploits.",
    "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
    "Referrer-Policy": "Controls how much referral information is shared when leaving the site."
}

def audit_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[+] Executing Automated Audit for: {url}")
    print("-" * 60)

    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to target URL: {e}")
        return

    # Dictionary to hold our report data
    report_data = {
        "target_url": url,
        "summary": {"passed": 0, "missing": 0},
        "results": {}
    }

    for header, description in SECURITY_HEADERS.items():
        header_key = next((k for k in headers if k.lower() == header.lower()), None)
        
        if header_key:
            print(f"[PASSED] {header}")
            report_data["results"][header] = {
                "status": "PASSED",
                "value": headers[header_key]
            }
            report_data["summary"]["passed"] += 1
        else:
            print(f"[MISSING] {header}")
            report_data["results"][header] = {
                "status": "MISSING",
                "risk": description
            }
            report_data["summary"]["missing"] += 1

    safe_filename = url.replace("https://", "").replace("http://", "").replace("/", "_") + "_report.json"
    
    with open(safe_filename, "w") as f:
        json.dump(report_data, f, indent=4)
    
    print("-" * 60)
    print(f"[SUCCESS] Vulnerability scan complete. Report saved to: {safe_filename}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    audit_url(target)