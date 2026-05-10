# ⚡ WebScan Pro

> **Web Application Vulnerability Scanner** — Automated security assessment tool for ethical penetration testers and security researchers.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Purpose-Ethical%20Hacking-red?style=flat-square)

---

## 📌 Overview

WebScan Pro is a modular, multi-threaded web application vulnerability scanner built in Python. It performs automated security assessments against web targets by running a structured pipeline of checks including HTTP header analysis, sensitive file discovery, XSS detection, SQL injection probing, and cookie security auditing.

All results are compiled into a structured JSON or HTML report with a calculated risk score — suitable for inclusion in professional penetration test deliverables.

> ⚠️ **Legal Disclaimer:** This tool is intended **only** for use against systems you own or have explicit written authorization to test. Unauthorized use is illegal and unethical.

---

## 🔍 Features

| Module | Description |
|--------|-------------|
| **Information Gathering** | DNS resolution, IP lookup, SSL/TLS certificate inspection |
| **Security Header Analysis** | Detects missing HSTS, CSP, X-Frame-Options, and other security headers |
| **Sensitive Path Discovery** | Probes for exposed `.git/config`, `.env`, admin panels, backups, and API docs |
| **XSS Detection** | Tests URL parameters for reflected Cross-Site Scripting |
| **SQL Injection Probe** | Error-based SQL injection detection via response analysis |
| **Cookie Auditing** | Flags cookies missing `Secure`, `HttpOnly`, or `SameSite` attributes |
| **Report Generation** | Exports findings as structured JSON or styled HTML |

---

## 🛠️ Tech Stack

- **Language:** Python 3.9+
- **Core Libraries:** `requests`, `socket`, `ssl`, `concurrent.futures`
- **Networking:** TCP/IP, HTTP/HTTPS, DNS resolution
- **Security Concepts:** OWASP Top 10, CVE analysis, header policy enforcement
- **Reporting:** JSON, HTML (self-contained)

---

## 📁 Project Structure

```
webscan-pro/
├── src/
│   ├── scanner.py           # Core scanner engine
│   └── report_generator.py  # HTML report renderer
├── tests/
│   └── test_scanner.py      # Unit tests (pytest)
├── reports/                 # Scan output directory (auto-created)
├── logs/                    # Runtime logs
├── docs/
│   └── sample_report.md     # Example finding format
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/webscan-pro.git
cd webscan-pro

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### Basic Scan

```bash
python src/scanner.py -t https://example.com
```

### Full Scan with Options

```bash
python src/scanner.py \
  -t https://target.com \
  --threads 20 \
  --timeout 8 \
  --output json \
  -v
```

### Generate HTML Report from JSON

```bash
python src/report_generator.py reports/scan_20241201_143022.json
```

### CLI Reference

```
Options:
  -t, --target    Target URL or domain (required)
  --threads       Concurrent threads (default: 10)
  --timeout       Request timeout in seconds (default: 10)
  --output        Output format: json | html | txt
  -v, --verbose   Verbose console output
  -h, --help      Show help message
```

---

## 📊 Sample Output

```json
{
  "report_metadata": {
    "tool": "WebScan Pro v1.0.0",
    "scan_target": "https://example.com",
    "duration_seconds": 12.43,
    "total_findings": 8,
    "risk_score": 23,
    "severity_summary": {
      "CRITICAL": 0, "HIGH": 3, "MEDIUM": 3, "LOW": 2
    }
  },
  "findings": [
    {
      "type": "Missing Security Header",
      "severity": "HIGH",
      "header": "Content-Security-Policy",
      "description": "CSP missing — increased risk of XSS attacks.",
      "recommendation": "Add 'Content-Security-Policy' header to all HTTP responses."
    }
  ]
}
```

---

## 🧪 Running Tests

```bash
# Install pytest if not already installed
pip install pytest

# Run all tests with verbose output
python -m pytest tests/ -v
```

---

## 📋 Scan Phases

```
Phase 1 → Information Gathering   (DNS, IP, SSL, Server fingerprint)
Phase 2 → Security Header Check   (HSTS, CSP, X-Frame-Options, etc.)
Phase 3 → Sensitive Path Discovery (Git, .env, admin, backups)
Phase 4 → XSS Detection           (Reflected XSS in parameters)
Phase 5 → SQL Injection Probe     (Error-based detection)
Phase 6 → Cookie Security Audit   (Secure/HttpOnly/SameSite flags)
         ↓
      JSON / HTML Report with Risk Score
```

---

## 🔐 Skills Demonstrated

- **Penetration Testing** — Structured recon → exploit → report pipeline
- **Web Application Security** — OWASP Top 10 coverage (A01–A07)
- **Python** — OOP, threading, HTTP client, SSL inspection, argparse CLI
- **Network Security** — TCP/IP, DNS, SSL/TLS certificate analysis
- **Cryptography** — TLS protocol and cipher suite inspection
- **Report Writing** — Structured findings with severity ratings and remediation steps

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙋 Author

**[Your Name]**  
Cybersecurity Enthusiast | Penetration Tester  
[LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)

---

> *Built for educational purposes and authorized security testing only.*
