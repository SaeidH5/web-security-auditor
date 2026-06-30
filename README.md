# 🛡️ OWASP Web Security Configuration Auditor

An automated, lightweight DevSecOps utility written in Python designed to audit public web server responses against critical **OWASP** application security standards. 

This tool evaluates a target URL's HTTP response headers to identify missing or misconfigured defensive layers, helping engineers catch vulnerabilities like Cross-Site Scripting (XSS), Clickjacking, and Man-in-the-Middle (MITM) attacks early.

---

## 🚀 Features

* **Real-time Assessment:** Instantly parses target server metadata using lightweight HTTP `HEAD` requests.
* **OWASP Alignment:** Maps checks directly against core industry-standard security vulnerabilities.
* **Structured JSON Artifacts:** Automatically generates an audit report (`[target]_report.json`) for easy integration into modern DevSecOps pipelines.
* **Risk Intelligence:** Provides clear technical risk justifications for every missing security control.
* **Transport Layer Intelligence:** Initiates secure network handshakes to audit TLS protocol versions and calculate certificate expiration timelines.

---

## 📊 Core Security Headers Checked

| Header | Defensive Purpose | Mitigation Target |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | Enforces mandatory HTTPS encryption. | MITM / Session Hijacking |
| `X-Frame-Options` | Restricts the page from being framed by external sites. | Clickjacking Exploits |
| `X-Content-Type-Options` | Disables automated browser MIME-type sniffing. | Drive-by Malware Downloads |
| `Content-Security-Policy` | Defines a strict script execution whitelist. | Cross-Site Scripting (XSS) |
| `Referrer-Policy` | Restricts data leakage via referral parameters. | Information Disclosure |

---

## 🛠️ Installation & Setup

### Prerequisites
Ensure you have **Python 3.x** and `pip` installed on your machine.

### 1. Clone the Workspace
```bash
git clone https://github.com/Saeidh5/web-security-auditor.git
cd web-security-auditor
```

### 2. Install Required Dependencies
```bash
pip install requests
```

## 💻 Usage & Demonstration
python auditor.py github.com

## Sample Output Report (github.com_report.json)
```json
{
    "target_url": "https://github.com",
    "summary": {
        "passed": 5,
        "missing": 0
    },
    "results": {
        "Strict-Transport-Security": {
            "status": "PASSED",
            "value": "max-age=31536000; includeSubDomains; preload"
        }
    }
}
```