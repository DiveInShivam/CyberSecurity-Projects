#!/usr/bin/env python3
"""
NetSentry - Network Security Monitor & Port Intelligence Tool
Author: [Your Name]
Version: 1.0.0
License: MIT

Performs host discovery, port scanning, service fingerprinting,
and network anomaly detection with encrypted log storage.
"""

import argparse
import socket
import struct
import json
import time
import ipaddress
import hashlib
import hmac
import base64
import sys
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/netsentry.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ─── PORT INTELLIGENCE DATABASE ──────────────────────────────────────────────

PORT_DB = {
    # Well-known ports
    21:   {"service": "FTP",        "risk": "HIGH",   "note": "Plain-text file transfer. Prone to credential sniffing."},
    22:   {"service": "SSH",        "risk": "LOW",    "note": "Encrypted remote shell. Verify key-based auth only."},
    23:   {"service": "Telnet",     "risk": "CRITICAL","note": "Unencrypted remote shell. Should never be exposed."},
    25:   {"service": "SMTP",       "risk": "MEDIUM", "note": "Mail relay. Misconfiguration leads to spam abuse."},
    53:   {"service": "DNS",        "risk": "MEDIUM", "note": "DNS server. Test for zone transfer (AXFR) vulnerability."},
    80:   {"service": "HTTP",       "risk": "MEDIUM", "note": "Unencrypted web traffic. Should redirect to HTTPS."},
    110:  {"service": "POP3",       "risk": "HIGH",   "note": "Plain-text email retrieval."},
    111:  {"service": "RPCBind",    "risk": "HIGH",   "note": "RPC service mapper. Exposes attack surface."},
    135:  {"service": "MSRPC",      "risk": "HIGH",   "note": "Windows RPC. Target of many legacy exploits."},
    139:  {"service": "NetBIOS",    "risk": "HIGH",   "note": "Windows file sharing. Vulnerable to enumeration."},
    143:  {"service": "IMAP",       "risk": "MEDIUM", "note": "Email access protocol. Use IMAPS (993) instead."},
    443:  {"service": "HTTPS",      "risk": "LOW",    "note": "Encrypted web traffic."},
    445:  {"service": "SMB",        "risk": "CRITICAL","note": "Windows file sharing. EternalBlue exploit vector."},
    1433: {"service": "MSSQL",      "risk": "HIGH",   "note": "Microsoft SQL Server. Restrict network access."},
    1521: {"service": "Oracle DB",  "risk": "HIGH",   "note": "Oracle database listener."},
    2049: {"service": "NFS",        "risk": "HIGH",   "note": "Network File System. Often misconfigured."},
    3306: {"service": "MySQL",      "risk": "HIGH",   "note": "MySQL database. Should not be internet-facing."},
    3389: {"service": "RDP",        "risk": "CRITICAL","note": "Remote Desktop. Frequent ransomware entry point."},
    5432: {"service": "PostgreSQL", "risk": "HIGH",   "note": "PostgreSQL database. Restrict to localhost."},
    5900: {"service": "VNC",        "risk": "CRITICAL","note": "Remote desktop. Often uses weak auth."},
    6379: {"service": "Redis",      "risk": "CRITICAL","note": "In-memory DB. Frequently exposed without auth."},
    8080: {"service": "HTTP-Alt",   "risk": "MEDIUM", "note": "Alternate HTTP port. Common for dev servers."},
    8443: {"service": "HTTPS-Alt",  "risk": "LOW",    "note": "Alternate HTTPS port."},
    9200: {"service": "Elasticsearch","risk":"CRITICAL","note": "NoSQL search engine. Often exposed without auth."},
    27017:{"service": "MongoDB",    "risk": "CRITICAL","note": "MongoDB. Default install has no authentication."},
}

# Common service banners to grab
BANNER_PORTS = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]

# Risk score weights
RISK_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ─── CORE SCANNER ────────────────────────────────────────────────────────────

class PortScanner:
    """High-performance TCP port scanner with service fingerprinting."""

    def __init__(self, target: str, ports: str = "top100", threads: int = 100,
                 timeout: float = 1.5, verbose: bool = False):
        self.target = target
        self.ip = self._resolve(target)
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.open_ports: List[Dict] = []
        self.scan_start = datetime.utcnow()

    def _resolve(self, host: str) -> str:
        try:
            ip = socket.gethostbyname(host)
            logger.info(f"Resolved {host} → {ip}")
            return ip
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {host}: {e}")
            sys.exit(1)

    def _parse_port_range(self, ports_arg: str) -> List[int]:
        """Parse port specifications: 'top100', '80', '1-1024', '22,80,443'."""
        TOP_100 = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
            # Extended top ports
            1, 7, 9, 13, 19, 26, 37, 79, 88, 106, 113, 119, 144, 179,
            199, 389, 427, 444, 465, 513, 514, 515, 543, 544, 548, 554,
            587, 631, 646, 873, 990, 1025, 1026, 1027, 1028, 1029, 1110,
            1433, 1720, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
            3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
            5631, 5666, 5800, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
            8888, 9100, 9999, 49152, 27017, 6379, 9200
        ]

        if ports_arg == "top100":
            return sorted(set(TOP_100))
        elif "-" in ports_arg:
            start, end = ports_arg.split("-")
            return list(range(int(start), int(end) + 1))
        elif "," in ports_arg:
            return [int(p) for p in ports_arg.split(",")]
        else:
            return [int(ports_arg)]

    def scan_port(self, port: int) -> Optional[Dict]:
        """Attempt TCP connection to a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    port_info = PORT_DB.get(port, {
                        "service": self._guess_service(port),
                        "risk": "UNKNOWN",
                        "note": "Unknown service — manual inspection recommended."
                    })
                    banner = self._grab_banner(port) if port in BANNER_PORTS else ""
                    entry = {
                        "port": port,
                        "state": "open",
                        "service": port_info["service"],
                        "risk": port_info["risk"],
                        "note": port_info["note"],
                        "banner": banner
                    }
                    if self.verbose:
                        logger.info(f"  [{port_info['risk']:8}] {port:5}/tcp  {port_info['service']}")
                    return entry
        except Exception:
            pass
        return None

    def _grab_banner(self, port: int) -> str:
        """Attempt service banner grabbing."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((self.ip, port))
                # Send a generic HTTP request for web ports
                if port in [80, 8080, 8000]:
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                return banner[:200]  # Limit banner length
        except Exception:
            return ""

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return f"unknown({port})"

    def run(self, ports_arg: str = "top100") -> List[Dict]:
        """Execute parallel port scan."""
        ports = self._parse_port_range(ports_arg)
        logger.info(f"Scanning {len(ports)} ports on {self.target} ({self.ip})")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)

        # Sort by port number
        self.open_ports.sort(key=lambda x: x["port"])
        logger.info(f"Found {len(self.open_ports)} open ports")
        return self.open_ports


# ─── NETWORK RANGE SCANNER ───────────────────────────────────────────────────

class NetworkScanner:
    """CIDR range host discovery using ICMP-like TCP ping."""

    def __init__(self, cidr: str, timeout: float = 0.5, threads: int = 200):
        self.cidr = cidr
        self.timeout = timeout
        self.threads = threads
        self.live_hosts: List[str] = []

    def ping_host(self, ip: str) -> Optional[str]:
        """TCP SYN ping on port 80 and 443."""
        for port in [80, 443, 22]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return ip
            except Exception:
                pass
        return None

    def scan(self) -> List[str]:
        """Discover live hosts in a CIDR range."""
        try:
            network = ipaddress.ip_network(self.cidr, strict=False)
        except ValueError as e:
            logger.error(f"Invalid CIDR: {e}")
            return []

        hosts = list(network.hosts())
        logger.info(f"Probing {len(hosts)} hosts in {self.cidr}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.ping_host, str(h)): str(h) for h in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.live_hosts.append(result)
                    logger.info(f"  [LIVE] {result}")

        self.live_hosts.sort()
        logger.info(f"Discovered {len(self.live_hosts)} live hosts")
        return self.live_hosts


# ─── ANOMALY DETECTOR ────────────────────────────────────────────────────────

class AnomalyDetector:
    """Rule-based network configuration anomaly detector."""

    RULES = [
        {
            "id": "RULE-001",
            "name": "Telnet Exposed",
            "ports": [23],
            "severity": "CRITICAL",
            "description": "Telnet (port 23) transmits credentials in plaintext.",
            "mitigation": "Disable Telnet. Use SSH (port 22) with key-based authentication."
        },
        {
            "id": "RULE-002",
            "name": "Database Publicly Accessible",
            "ports": [3306, 5432, 1433, 27017, 6379, 9200],
            "severity": "CRITICAL",
            "description": "Database port exposed to network. Unauthorized access risk.",
            "mitigation": "Bind database to localhost. Use VPN or SSH tunnel for remote access."
        },
        {
            "id": "RULE-003",
            "name": "RDP Exposed",
            "ports": [3389],
            "severity": "CRITICAL",
            "description": "Remote Desktop Protocol accessible. Common ransomware entry vector.",
            "mitigation": "Restrict RDP behind VPN. Enable NLA. Apply MFA."
        },
        {
            "id": "RULE-004",
            "name": "VNC Exposed",
            "ports": [5900, 5901],
            "severity": "CRITICAL",
            "description": "VNC remote access exposed. Often uses weak or no authentication.",
            "mitigation": "Disable VNC or restrict to VPN only. Enable VNC password."
        },
        {
            "id": "RULE-005",
            "name": "SMB Exposed",
            "ports": [445, 139],
            "severity": "HIGH",
            "description": "SMB file sharing port open. Vulnerable to EternalBlue (MS17-010).",
            "mitigation": "Block SMB at firewall. Apply MS17-010 patches. Disable SMBv1."
        },
        {
            "id": "RULE-006",
            "name": "FTP Plain-Text",
            "ports": [21],
            "severity": "HIGH",
            "description": "FTP transmits credentials in cleartext.",
            "mitigation": "Replace with SFTP (SSH port 22) or FTPS (port 990)."
        },
        {
            "id": "RULE-007",
            "name": "HTTP Without HTTPS",
            "ports": [80],
            "severity": "MEDIUM",
            "description": "HTTP port open without verifying HTTPS redirect.",
            "mitigation": "Enable HTTPS and configure 301 redirect from HTTP to HTTPS."
        },
        {
            "id": "RULE-008",
            "name": "NFS Exposed",
            "ports": [2049],
            "severity": "HIGH",
            "description": "Network File System port open. Misconfigured exports lead to data exposure.",
            "mitigation": "Restrict NFS exports. Require Kerberos authentication."
        }
    ]

    def analyze(self, open_ports: List[Dict]) -> List[Dict]:
        """Match open ports against anomaly rules."""
        port_numbers = {p["port"] for p in open_ports}
        triggered = []

        for rule in self.RULES:
            matched = [p for p in rule["ports"] if p in port_numbers]
            if matched:
                triggered.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "matched_ports": matched,
                    "description": rule["description"],
                    "mitigation": rule["mitigation"]
                })

        triggered.sort(key=lambda r: RISK_WEIGHTS.get(r["severity"], 0), reverse=True)
        return triggered


# ─── SECURE LOG MANAGER ──────────────────────────────────────────────────────

class SecureLogManager:
    """HMAC-signed JSON log writer for tamper-evident audit trails."""

    def __init__(self, log_dir: str = "logs", secret: str = "netsentry-default-key"):
        self.log_dir = log_dir
        self.secret = secret.encode()
        os.makedirs(log_dir, exist_ok=True)

    def _sign(self, data: str) -> str:
        sig = hmac.new(self.secret, data.encode(), hashlib.sha256).hexdigest()
        return sig

    def write(self, report: Dict) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.log_dir}/netsentry_{timestamp}.json"

        payload = json.dumps(report, indent=2)
        signature = self._sign(payload)
        report["_integrity"] = {
            "algorithm": "HMAC-SHA256",
            "signature": signature,
            "signed_at": datetime.utcnow().isoformat() + "Z"
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Signed report written: {filename}")
        return filename

    def verify(self, filepath: str) -> bool:
        """Verify log file integrity via HMAC signature."""
        with open(filepath) as f:
            report = json.load(f)

        stored_sig = report.pop("_integrity", {}).get("signature", "")
        payload = json.dumps(report, indent=2)
        expected_sig = self._sign(payload)
        is_valid = hmac.compare_digest(stored_sig, expected_sig)

        if is_valid:
            logger.info(f"[VERIFIED] Log integrity confirmed: {filepath}")
        else:
            logger.warning(f"[TAMPERED] Log integrity check FAILED: {filepath}")

        return is_valid


# ─── REPORT BUILDER ──────────────────────────────────────────────────────────

def build_report(target: str, ip: str, open_ports: List[Dict],
                 anomalies: List[Dict], live_hosts: Optional[List[str]] = None) -> Dict:
    """Compile full NetSentry report."""
    scan_time = datetime.utcnow().isoformat() + "Z"

    risk_score = sum(RISK_WEIGHTS.get(p["risk"], 0) for p in open_ports)
    risk_score += sum(RISK_WEIGHTS.get(a["severity"], 0) for a in anomalies)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for p in open_ports:
        sev_counts[p.get("risk", "UNKNOWN")] = sev_counts.get(p.get("risk", "UNKNOWN"), 0) + 1

    return {
        "report_metadata": {
            "tool": "NetSentry v1.0.0",
            "scan_target": target,
            "resolved_ip": ip,
            "scan_time": scan_time,
            "open_ports_count": len(open_ports),
            "anomaly_count": len(anomalies),
            "risk_score": risk_score,
            "severity_distribution": sev_counts
        },
        "open_ports": open_ports,
        "anomalies": anomalies,
        "live_hosts": live_hosts or [],
        "recommendations": [
            "Close all unnecessary ports at the firewall level.",
            "Replace legacy protocols (Telnet, FTP) with encrypted alternatives.",
            "Restrict database services to localhost or private VLANs.",
            "Apply principle of least privilege to all network services.",
            "Enable intrusion detection/prevention system (IDS/IPS).",
            "Schedule regular penetration tests and port scans.",
        ]
    }


# ─── CLI ENTRY POINT ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetSentry — Network Security Monitor & Port Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netsentry.py -t 192.168.1.1
  python netsentry.py -t example.com --ports 1-1024 --threads 200 -v
  python netsentry.py -t 10.0.0.1 --ports 22,80,443,3306,3389
  python netsentry.py --network 192.168.1.0/24
  python netsentry.py --verify logs/netsentry_20241201_143022.json
        """
    )
    parser.add_argument("-t", "--target", help="Target hostname or IP address")
    parser.add_argument("--network", help="CIDR range for host discovery (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", default="top100",
                        help="Port spec: 'top100', '1-1024', '80,443,8080' (default: top100)")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Connection timeout in seconds")
    parser.add_argument("--verify", help="Verify integrity of a saved log file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    os.makedirs("logs", exist_ok=True)

    # Log file integrity verification mode
    if args.verify:
        log_mgr = SecureLogManager()
        result = log_mgr.verify(args.verify)
        sys.exit(0 if result else 1)

    if not args.target and not args.network:
        parser.error("Provide --target or --network")

    logger.info("=" * 60)
    logger.info("NetSentry v1.0.0 — Network Security Monitor")
    logger.info("=" * 60)

    live_hosts = []
    open_ports = []
    ip = ""

    # Host discovery mode
    if args.network:
        net_scanner = NetworkScanner(args.network, timeout=args.timeout, threads=args.threads)
        live_hosts = net_scanner.scan()

    # Port scan mode
    if args.target:
        scanner = PortScanner(
            target=args.target,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose
        )
        ip = scanner.ip
        open_ports = scanner.run(args.ports)

        # Anomaly detection
        detector = AnomalyDetector()
        anomalies = detector.analyze(open_ports)

        # Build and save report
        report = build_report(args.target, ip, open_ports, anomalies, live_hosts)
        log_mgr = SecureLogManager()
        filepath = log_mgr.write(report)

        # Summary
        print("\n" + "=" * 60)
        print(f"  TARGET       : {args.target} ({ip})")
        print(f"  OPEN PORTS   : {len(open_ports)}")
        print(f"  ANOMALIES    : {len(anomalies)}")
        print(f"  RISK SCORE   : {report['report_metadata']['risk_score']}")
        print(f"  REPORT       : {filepath}")
        print("=" * 60)

        if anomalies:
            print("\n⚠  TOP ANOMALIES:")
            for a in anomalies[:3]:
                print(f"  [{a['severity']}] {a['name']} — ports {a['matched_ports']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
