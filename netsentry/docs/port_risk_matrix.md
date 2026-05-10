# NetSentry — Port Risk Matrix & Protocol Reference

This document details the port intelligence database used by NetSentry for service classification and risk rating.

---

## Risk Level Definitions

| Level | Score | Definition |
|-------|-------|-----------|
| **CRITICAL** | 10 | Actively exploited, plaintext credentials, or default-no-auth services |
| **HIGH** | 5 | Significant attack surface, known CVEs, lateral movement vectors |
| **MEDIUM** | 2 | Misconfiguration risk, indirect exposure |
| **LOW** | 1 | Modern encrypted protocols, typically safe when properly configured |

---

## Full Port Risk Matrix

| Port | Service | Risk | Security Notes |
|------|---------|------|----------------|
| 21 | FTP | HIGH | Plaintext credentials. Replace with SFTP/FTPS. |
| 22 | SSH | LOW | Encrypted. Ensure key-based auth; disable root login. |
| 23 | Telnet | CRITICAL | No encryption. Full session visible in cleartext. Never expose. |
| 25 | SMTP | MEDIUM | Open relay misconfiguration enables spam abuse. |
| 53 | DNS | MEDIUM | Zone transfer (AXFR) vulnerability if unrestricted. |
| 80 | HTTP | MEDIUM | Unencrypted. Should enforce redirect to HTTPS. |
| 110 | POP3 | HIGH | Plaintext email retrieval. Use POP3S (995). |
| 111 | RPCBind | HIGH | Maps RPC services. Enumeration entry point. |
| 135 | MSRPC | HIGH | Windows RPC. Exploited by many legacy worms. |
| 139 | NetBIOS | HIGH | Legacy Windows file sharing. Enable firewall block. |
| 143 | IMAP | MEDIUM | Use IMAPS (993) instead. |
| 443 | HTTPS | LOW | Encrypted web traffic. Verify TLS version ≥ 1.2. |
| 445 | SMB | CRITICAL | EternalBlue (MS17-010) exploit vector. Block at perimeter. |
| 993 | IMAPS | LOW | Encrypted IMAP. |
| 995 | POP3S | LOW | Encrypted POP3. |
| 1433 | MSSQL | HIGH | SQL Server. Brute-force and injection target. |
| 1521 | Oracle DB | HIGH | Oracle listener. Restrict to trusted hosts. |
| 2049 | NFS | HIGH | Often world-readable mounts. Require Kerberos. |
| 3306 | MySQL | HIGH | Never expose directly to internet. Use SSH tunnel. |
| 3389 | RDP | CRITICAL | #1 ransomware entry point. Require VPN + MFA. |
| 5432 | PostgreSQL | HIGH | Bind to localhost. Use SSL for remote connections. |
| 5900 | VNC | CRITICAL | Weak auth, no encryption by default. |
| 6379 | Redis | CRITICAL | Default: no authentication, no encryption. |
| 8080 | HTTP-Alt | MEDIUM | Development server leak. Proxy behind nginx/Apache. |
| 8443 | HTTPS-Alt | LOW | Alternate HTTPS. Verify certificate validity. |
| 9200 | Elasticsearch | CRITICAL | No auth by default. Thousands of exposed instances. |
| 27017 | MongoDB | CRITICAL | No auth by default. Enable `security.authorization`. |

---

## Anomaly Detection Rules

### RULE-001: Telnet Exposed
- **Trigger Port:** 23
- **Severity:** CRITICAL
- **CVE Reference:** General plaintext protocol risk
- **Mitigation:** Disable `telnetd`. Deploy SSH with `PermitRootLogin no` and `PasswordAuthentication no`.

### RULE-002: Database Publicly Accessible
- **Trigger Ports:** 3306, 5432, 1433, 27017, 6379, 9200
- **Severity:** CRITICAL
- **Mitigation:** Bind to `127.0.0.1`. Use SSH tunneling or private VPN for remote access.

### RULE-003: RDP Exposed
- **Trigger Port:** 3389
- **Severity:** CRITICAL
- **CVE Reference:** CVE-2019-0708 (BlueKeep), CVE-2020-0609
- **Mitigation:** Block at firewall. Require VPN before RDP access. Enable NLA and MFA.

### RULE-004: VNC Exposed
- **Trigger Ports:** 5900, 5901
- **Severity:** CRITICAL
- **Mitigation:** Disable VNC or tunnel through SSH. Enable VNC password and firewall rules.

### RULE-005: SMB Exposed
- **Trigger Ports:** 445, 139
- **Severity:** HIGH
- **CVE Reference:** CVE-2017-0144 (EternalBlue / WannaCry)
- **Mitigation:** Block ports 445/139 at perimeter. Disable SMBv1. Apply MS17-010 patches.

### RULE-006: FTP Plain-Text
- **Trigger Port:** 21
- **Severity:** HIGH
- **Mitigation:** Replace with SFTP (port 22) or FTPS (port 990/21 with TLS).

### RULE-007: HTTP Without Redirect
- **Trigger Port:** 80
- **Severity:** MEDIUM
- **Mitigation:** Configure `301 Redirect` to HTTPS. Enable HSTS header.

### RULE-008: NFS Exposed
- **Trigger Port:** 2049
- **Severity:** HIGH
- **Mitigation:** Restrict NFS exports. Require Kerberos v5 authentication. Firewall to trusted CIDRs.

---

## References

- NIST National Vulnerability Database: https://nvd.nist.gov/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- SANS Internet Storm Center: https://isc.sans.edu/
- Shodan Exposure Reports: https://www.shodan.io/report/
