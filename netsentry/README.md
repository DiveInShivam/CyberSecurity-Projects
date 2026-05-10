# 🛡️ NetSentry

> **Network Security Monitor & Port Intelligence Tool** — Automated host discovery, port scanning, service fingerprinting, anomaly detection, and tamper-evident audit logging.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Purpose-Network%20Security-blue?style=flat-square)

---

## 📌 Overview

NetSentry is a Python-based network security monitoring tool designed for authorized penetration testers and network security engineers. It combines host discovery, multi-threaded TCP port scanning, service fingerprinting, and rule-based anomaly detection — all wrapped in a tamper-evident HMAC-SHA256 signed audit log system.

NetSentry maps network exposure, identifies dangerous open ports, and applies security rules to surface misconfigurations and high-risk services — outputting both a structured JSON log and a rich ANSI terminal dashboard.

> ⚠️ **Legal Disclaimer:** Use only against networks and systems you own or have explicit written authorization to test. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws.

---

## 🔍 Features

| Module | Description |
|--------|-------------|
| **Host Discovery** | TCP-ping sweep across CIDR ranges to identify live hosts |
| **Port Scanner** | High-speed multi-threaded TCP port scanner (top 100, ranges, or custom lists) |
| **Service Fingerprinting** | Port-to-service mapping with 40+ protocol entries and risk ratings |
| **Banner Grabbing** | Retrieves service banners from open ports for version identification |
| **Anomaly Detector** | 8 built-in security rules (Telnet, exposed DBs, RDP, VNC, SMB, etc.) |
| **Secure Log Manager** | HMAC-SHA256 signed JSON logs for tamper-evident audit trails |
| **CLI Dashboard** | ANSI-colored terminal report renderer |

---

## 🛠️ Tech Stack

- **Language:** Python 3.9+
- **Networking:** TCP/IP sockets, CIDR addressing, banner grabbing
- **Security:** HMAC-SHA256 log signing, CVE-referenced rule base
- **Concepts:** Network enumeration, port intelligence, anomaly detection
- **Concurrency:** `concurrent.futures.ThreadPoolExecutor`
- **Protocols:** TCP, HTTP, FTP, SSH, SMB, RDP, DNS, SMTP

---

## 📁 Project Structure

```
netsentry/
├── src/
│   ├── netsentry.py         # Core engine: scanner, detector, logger
│   └── dashboard.py         # ANSI terminal report renderer
├── tests/
│   └── test_netsentry.py    # Unit tests (pytest)
├── logs/                    # HMAC-signed scan reports (auto-created)
├── docs/
│   └── port_risk_matrix.md  # Port intelligence reference
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netsentry.git
cd netsentry

# Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### Single Host Port Scan

```bash
python src/netsentry.py -t 192.168.1.1
```

### Scan Top 100 Ports with Verbose Output

```bash
python src/netsentry.py -t example.com --ports top100 -v
```

### Custom Port Range

```bash
python src/netsentry.py -t 10.0.0.5 --ports 1-1024 --threads 200
```

### Specific Ports

```bash
python src/netsentry.py -t 192.168.1.100 --ports 22,80,443,3306,3389,6379
```

### Network Host Discovery (CIDR Sweep)

```bash
python src/netsentry.py --network 192.168.1.0/24
```

### Render Terminal Dashboard from Report

```bash
python src/dashboard.py logs/netsentry_20241201_143022.json
```

### Verify Log File Integrity

```bash
python src/netsentry.py --verify logs/netsentry_20241201_143022.json
```

---

## 📊 Sample Terminal Output

```
  TARGET       : 192.168.1.100 (192.168.1.100)
  OPEN PORTS   : 12
  ANOMALIES    : 4
  RISK SCORE   : 47
  REPORT       : logs/netsentry_20241201_143022.json

⚠  TOP ANOMALIES:
  [CRITICAL] Telnet Exposed — ports [23]
  [CRITICAL] RDP Exposed — ports [3389]
  [HIGH]     SMB Exposed — ports [445, 139]
```

### Sample JSON Report

```json
{
  "report_metadata": {
    "tool": "NetSentry v1.0.0",
    "scan_target": "192.168.1.100",
    "resolved_ip": "192.168.1.100",
    "open_ports_count": 12,
    "anomaly_count": 4,
    "risk_score": 47
  },
  "open_ports": [
    {
      "port": 22,
      "state": "open",
      "service": "SSH",
      "risk": "LOW",
      "note": "Encrypted remote shell. Verify key-based auth only."
    },
    {
      "port": 3389,
      "state": "open",
      "service": "RDP",
      "risk": "CRITICAL",
      "note": "Remote Desktop. Frequent ransomware entry point."
    }
  ],
  "anomalies": [
    {
      "rule_id": "RULE-003",
      "name": "RDP Exposed",
      "severity": "CRITICAL",
      "mitigation": "Restrict RDP behind VPN. Enable NLA. Apply MFA."
    }
  ]
}
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Expected output:
```
tests/test_netsentry.py::TestPortDatabase::test_critical_ports_present PASSED
tests/test_netsentry.py::TestPortDatabase::test_telnet_is_critical PASSED
tests/test_netsentry.py::TestAnomalyDetector::test_rdp_triggers_critical PASSED
tests/test_netsentry.py::TestSecureLogManager::test_detect_tampered_log PASSED
...
```

---

## 🔐 Security Design

### HMAC-SHA256 Signed Logs

Every scan report is signed with an HMAC-SHA256 signature to ensure tamper-evidence:

```
POST-SCAN → JSON report generated
         → HMAC-SHA256 signature computed
         → Signature embedded in report
         → Saved to logs/

AUDIT     → Load report
         → Re-compute HMAC
         → Compare digest (constant-time)
         → VERIFIED or TAMPERED
```

### Port Risk Matrix

NetSentry maintains an internal port intelligence database with 40+ entries rated by risk:

| Risk Level | Example Ports | Reason |
|------------|--------------|--------|
| CRITICAL | 23, 3389, 5900, 6379, 27017 | Plaintext, no auth, known exploits |
| HIGH | 21, 445, 3306, 5432, 2049 | Protocol weaknesses, lateral movement |
| MEDIUM | 25, 53, 80, 143 | Misconfiguration risk |
| LOW | 22, 443 | Encrypted, modern protocols |

---

## 📋 Scan Workflow

```
INPUT: target IP / hostname / CIDR range
  ↓
Phase 1 → DNS Resolution + Host Discovery
Phase 2 → TCP Port Scan (threaded, configurable)
Phase 3 → Service Fingerprinting (port → service + risk)
Phase 4 → Banner Grabbing (FTP, SSH, HTTP banners)
Phase 5 → Anomaly Detection (8 security rules)
Phase 6 → Report Generation (JSON + HMAC signature)
Phase 7 → Terminal Dashboard Render
  ↓
OUTPUT: Signed JSON log + CLI dashboard
```

---

## 🔐 Skills Demonstrated

- **Network Security** — TCP/IP scanning, CIDR enumeration, service enumeration
- **Penetration Testing** — Structured network recon methodology
- **Python** — Sockets, threading, HMAC cryptography, argparse, OOP
- **TCP/IP & Protocols** — Port/protocol mapping, service banner analysis
- **Cryptography** — HMAC-SHA256 tamper-evident log signing
- **Linux** — Designed and tested on Linux; cross-platform compatible
- **Report Writing** — Risk-scored findings with actionable mitigations

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙋 Author

**[Your Name]**  
Cybersecurity Enthusiast | Network Security Researcher  
[LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)

---

> *For authorized network security assessments only. Always obtain written permission before scanning.*
