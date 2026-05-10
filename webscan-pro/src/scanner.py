#!/usr/bin/env python3
"""
WebScan Pro - Web Application Vulnerability Scanner
Author: [Your Name]
Version: 1.0.0
License: MIT
"""

import argparse
import requests
import socket
import ssl
import json
import time
import re
import sys
import logging
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/webscan.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class WebScanner:
    """Core web application vulnerability scanner."""

    VERSION = "1.0.0"
    USER_AGENT = f"WebScanPro/{VERSION} (Security Scanner)"

    # Common sensitive paths to probe
    SENSITIVE_PATHS = [
        "/.git/config", "/.env", "/config.php", "/wp-config.php",
        "/admin/", "/admin/login", "/phpmyadmin/", "/.htaccess",
        "/backup/", "/db_backup.sql", "/server-status", "/server-info",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.well-known/",
        "/api/v1/users", "/api/users", "/swagger.json", "/openapi.json",
        "/actuator/env", "/actuator/health", "/.DS_Store", "/WEB-INF/web.xml"
    ]

    # Common default credentials
    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("root", "root"), ("test", "test"), ("user", "password"),
        ("guest", "guest"), ("admin", ""), ("administrator", "administrator")
    ]

    # XSS payloads for testing (non-destructive)
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "';alert('XSS')//",
        '<img src=x onerror=alert(1)>',
        '{{7*7}}', '${7*7}',
    ]

    # SQL Injection payloads (read-only, detection only)
    SQLI_PAYLOADS = [
        "' OR '1'='1", "' OR 1=1--", "1; SELECT 1--",
        "' UNION SELECT NULL--", "admin'--", "1' AND SLEEP(2)--"
    ]

    def __init__(self, target: str, threads: int = 10, timeout: int = 10,
                 verbose: bool = False, output: str = "json"):
        self.target = self._normalize_url(target)
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_format = output
        self.session = self._create_session()
        self.findings: List[Dict] = []
        self.scan_start = datetime.utcnow()
        self.scanned_urls: set = set()

        logger.info(f"WebScan Pro v{self.VERSION} initialized")
        logger.info(f"Target: {self.target}")

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        session.verify = False  # For testing self-signed certs
        return session

    # ─── INFORMATION GATHERING ───────────────────────────────────────────

    def gather_info(self) -> Dict:
        """Collect basic target information."""
        logger.info("Phase 1: Information Gathering")
        info = {}

        try:
            parsed = urlparse(self.target)
            hostname = parsed.hostname
            info["hostname"] = hostname

            # DNS resolution
            try:
                ip = socket.gethostbyname(hostname)
                info["ip_address"] = ip
                info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                info["reverse_dns"] = "N/A"

            # HTTP headers
            resp = self.session.get(self.target, timeout=self.timeout)
            info["status_code"] = resp.status_code
            info["server"] = resp.headers.get("Server", "Unknown")
            info["powered_by"] = resp.headers.get("X-Powered-By", "Unknown")
            info["content_type"] = resp.headers.get("Content-Type", "Unknown")
            info["response_time_ms"] = round(resp.elapsed.total_seconds() * 1000, 2)

            # SSL/TLS check
            if self.target.startswith("https://"):
                info["ssl"] = self._check_ssl(hostname)

        except Exception as e:
            logger.warning(f"Info gathering error: {e}")
            info["error"] = str(e)

        return info

    def _check_ssl(self, hostname: str) -> Dict:
        """Inspect SSL/TLS certificate details."""
        ssl_info = {}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(self.timeout)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                ssl_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                ssl_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                ssl_info["version"] = cert.get("version")
                ssl_info["not_before"] = cert.get("notBefore")
                ssl_info["not_after"] = cert.get("notAfter")
                ssl_info["protocol"] = s.version()
                ssl_info["cipher"] = s.cipher()[0]
        except ssl.SSLError as e:
            ssl_info["error"] = f"SSL Error: {e}"
        except Exception as e:
            ssl_info["error"] = str(e)
        return ssl_info

    # ─── SECURITY HEADER ANALYSIS ────────────────────────────────────────

    def check_security_headers(self) -> List[Dict]:
        """Evaluate presence and configuration of security headers."""
        logger.info("Phase 2: Security Header Analysis")
        findings = []

        required_headers = {
            "Strict-Transport-Security": {
                "severity": "HIGH",
                "description": "HSTS not set — site vulnerable to SSL stripping attacks."
            },
            "Content-Security-Policy": {
                "severity": "HIGH",
                "description": "CSP missing — increased risk of XSS attacks."
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "X-Frame-Options missing — site may be vulnerable to clickjacking."
            },
            "X-Content-Type-Options": {
                "severity": "MEDIUM",
                "description": "X-Content-Type-Options not set — MIME-type sniffing possible."
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "Referrer-Policy not set — sensitive URL data may leak."
            },
            "Permissions-Policy": {
                "severity": "LOW",
                "description": "Permissions-Policy absent — browser features unrestricted."
            },
        }

        leaking_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            headers = resp.headers

            for header, meta in required_headers.items():
                if header not in headers:
                    findings.append({
                        "type": "Missing Security Header",
                        "severity": meta["severity"],
                        "header": header,
                        "description": meta["description"],
                        "recommendation": f"Add '{header}' header to all HTTP responses.",
                        "url": self.target
                    })
                    if self.verbose:
                        logger.warning(f"[{meta['severity']}] Missing: {header}")

            for header in leaking_headers:
                if header in headers:
                    findings.append({
                        "type": "Information Disclosure",
                        "severity": "LOW",
                        "header": header,
                        "value": headers[header],
                        "description": f"'{header}: {headers[header]}' reveals server technology.",
                        "recommendation": f"Remove or obscure the '{header}' header.",
                        "url": self.target
                    })

        except Exception as e:
            logger.error(f"Header check failed: {e}")

        return findings

    # ─── SENSITIVE PATH DISCOVERY ─────────────────────────────────────────

    def discover_sensitive_paths(self) -> List[Dict]:
        """Probe for exposed sensitive files and directories."""
        logger.info("Phase 3: Sensitive Path Discovery")
        findings = []

        def probe_path(path: str):
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in [200, 403, 500]:
                    return {
                        "type": "Sensitive Path Exposed",
                        "severity": "HIGH" if resp.status_code == 200 else "MEDIUM",
                        "url": url,
                        "status_code": resp.status_code,
                        "description": f"Path '{path}' returned HTTP {resp.status_code}.",
                        "recommendation": "Restrict access or remove this resource."
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe_path, p): p for p in self.SENSITIVE_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    if self.verbose:
                        logger.warning(f"[{result['severity']}] Found: {result['url']}")

        return findings

    # ─── XSS DETECTION ───────────────────────────────────────────────────

    def test_xss(self, params: Optional[Dict] = None) -> List[Dict]:
        """Test for reflected XSS in URL parameters."""
        logger.info("Phase 4: XSS Detection")
        findings = []

        test_url = f"{self.target}/search"
        param_key = "q"

        for payload in self.XSS_PAYLOADS:
            try:
                resp = self.session.get(
                    test_url,
                    params={param_key: payload},
                    timeout=self.timeout
                )
                if payload in resp.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "url": test_url,
                        "parameter": param_key,
                        "payload": payload,
                        "description": "Payload reflected in response without sanitization.",
                        "recommendation": "Encode all user-supplied input in HTML context. Implement CSP."
                    })
                    break
            except Exception:
                pass

        return findings

    # ─── SQL INJECTION DETECTION ──────────────────────────────────────────

    def test_sqli(self) -> List[Dict]:
        """Basic SQL injection detection via error-based analysis."""
        logger.info("Phase 5: SQL Injection Detection")
        findings = []

        error_signatures = [
            "mysql_fetch", "ORA-", "SQLite3::", "syntax error",
            "Unclosed quotation", "Microsoft OLE DB", "ODBC Driver",
            "PostgreSQL", "Warning: mysql", "You have an error in your SQL"
        ]

        test_url = f"{self.target}/item"

        for payload in self.SQLI_PAYLOADS:
            try:
                resp = self.session.get(
                    test_url,
                    params={"id": payload},
                    timeout=self.timeout
                )
                for sig in error_signatures:
                    if sig.lower() in resp.text.lower():
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "url": test_url,
                            "parameter": "id",
                            "payload": payload,
                            "error_signature": sig,
                            "description": "SQL error message exposed — injection may be possible.",
                            "recommendation": "Use parameterized queries / prepared statements. Enable WAF."
                        })
                        break
            except Exception:
                pass

        return findings

    # ─── COOKIE ANALYSIS ─────────────────────────────────────────────────

    def analyze_cookies(self) -> List[Dict]:
        """Inspect session cookies for security flags."""
        logger.info("Phase 6: Cookie Security Analysis")
        findings = []

        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing 'Secure' flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing 'HttpOnly' flag")
                samesite = cookie._rest.get("SameSite", None)
                if not samesite:
                    issues.append("Missing 'SameSite' attribute")

                if issues:
                    findings.append({
                        "type": "Insecure Cookie",
                        "severity": "MEDIUM",
                        "cookie_name": cookie.name,
                        "issues": issues,
                        "description": f"Cookie '{cookie.name}' has security misconfigurations.",
                        "recommendation": "Set Secure, HttpOnly, and SameSite=Strict on all cookies.",
                        "url": self.target
                    })
        except Exception as e:
            logger.warning(f"Cookie analysis failed: {e}")

        return findings

    # ─── REPORT GENERATION ───────────────────────────────────────────────

    def generate_report(self, info: Dict) -> Dict:
        """Compile all findings into a structured report."""
        scan_end = datetime.utcnow()
        duration = (scan_end - self.scan_start).total_seconds()

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.get("severity", "INFO"), 99)
        )

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in sorted_findings:
            sev = f.get("severity", "LOW")
            if sev in severity_counts:
                severity_counts[sev] += 1

        risk_score = (
            severity_counts["CRITICAL"] * 10 +
            severity_counts["HIGH"] * 5 +
            severity_counts["MEDIUM"] * 2 +
            severity_counts["LOW"] * 1
        )

        report = {
            "report_metadata": {
                "tool": f"WebScan Pro v{self.VERSION}",
                "scan_target": self.target,
                "scan_start": self.scan_start.isoformat() + "Z",
                "scan_end": scan_end.isoformat() + "Z",
                "duration_seconds": round(duration, 2),
                "total_findings": len(sorted_findings),
                "risk_score": risk_score,
                "severity_summary": severity_counts
            },
            "target_info": info,
            "findings": sorted_findings
        }

        return report

    def run(self) -> Dict:
        """Execute full scan pipeline."""
        logger.info("=" * 60)
        logger.info(f"Starting WebScan Pro scan against: {self.target}")
        logger.info("=" * 60)

        # Phase 1: Info Gathering
        info = self.gather_info()

        # Phase 2–6: Vulnerability checks
        self.findings.extend(self.check_security_headers())
        self.findings.extend(self.discover_sensitive_paths())
        self.findings.extend(self.test_xss())
        self.findings.extend(self.test_sqli())
        self.findings.extend(self.analyze_cookies())

        report = self.generate_report(info)

        logger.info("=" * 60)
        logger.info(f"Scan complete. Total findings: {len(self.findings)}")
        logger.info(f"Risk Score: {report['report_metadata']['risk_score']}")
        logger.info("=" * 60)

        return report


# ─── CLI ENTRY POINT ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WebScan Pro — Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -t https://example.com
  python scanner.py -t example.com --threads 20 --output json -v
  python scanner.py -t https://testsite.local --timeout 5 --output html
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL or domain")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--output", choices=["json", "html", "txt"], default="json",
                        help="Report output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    scanner = WebScanner(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        output=args.output
    )

    report = scanner.run()

    # Save report
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/scan_{timestamp}.json"

    import os
    os.makedirs("reports", exist_ok=True)

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Report saved to: {filename}")
    print(f"[+] Risk Score: {report['report_metadata']['risk_score']}")
    print(f"[+] Findings: {report['report_metadata']['total_findings']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
