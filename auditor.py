import requests
import sys

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

    print(f"\n[+] Starting Security Header Audit for: {url}")
    print("-" * 60)

    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to target URL: {e}")
        return

    passed_count = 0
    failed_count = 0

    for header, description in SECURITY_HEADERS.items():
        header_key = next((k for k in headers if k.lower() == header.lower()), None)
        
        if header_key:
            print(f"[PASSED] {header}")
            print(f"         Value: {headers[header_key]}")
            passed_count += 1
        else:
            print(f"[MISSING] {header}")
            print(f"          Risk: {description}")
            failed_count += 1
        print("-" * 60)

    print("\n[=] AUDIT SUMMARY")
    print(f"    Total Checked: {len(SECURITY_HEADERS)}")
    print(f"    Passed:        {passed_count}")
    print(f"    Missing/Weak:  {failed_count}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    audit_url(target)