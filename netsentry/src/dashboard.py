#!/usr/bin/env python3
"""
NetSentry - CLI Dashboard
Renders a formatted terminal report from a saved NetSentry JSON log.
"""

import json
import sys
import os
from datetime import datetime


# ANSI color codes
R  = "\033[91m"  # Red
Y  = "\033[93m"  # Yellow
G  = "\033[92m"  # Green
C  = "\033[96m"  # Cyan
W  = "\033[97m"  # White
M  = "\033[95m"  # Magenta
DIM = "\033[2m"
RST = "\033[0m"
BOLD = "\033[1m"

SEV_COLORS = {
    "CRITICAL": R,
    "HIGH":     "\033[38;5;208m",
    "MEDIUM":   Y,
    "LOW":      G,
    "UNKNOWN":  DIM
}


def sev_color(sev: str) -> str:
    return SEV_COLORS.get(sev, DIM)


def print_banner():
    print(f"""
{C}{BOLD}
  ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
  ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝
{RST}{DIM}  Network Security Monitor v1.0.0  |  Authorized Use Only{RST}
""")


def print_section(title: str):
    width = 70
    print(f"\n{C}{'─' * width}{RST}")
    print(f"{C}  {BOLD}{title}{RST}")
    print(f"{C}{'─' * width}{RST}")


def render_report(filepath: str):
    if not os.path.exists(filepath):
        print(f"{R}[ERROR] File not found: {filepath}{RST}")
        sys.exit(1)

    with open(filepath) as f:
        report = json.load(f)

    meta = report.get("report_metadata", {})
    open_ports = report.get("open_ports", [])
    anomalies = report.get("anomalies", [])
    recommendations = report.get("recommendations", [])
    live_hosts = report.get("live_hosts", [])

    print_banner()

    # ── Summary ──────────────────────────────────────────────────────────────
    print_section("SCAN SUMMARY")
    risk = meta.get("risk_score", 0)
    risk_color = R if risk >= 20 else (Y if risk >= 10 else G)

    print(f"  {W}Target        : {C}{meta.get('scan_target', 'N/A')} ({meta.get('resolved_ip','N/A')}){RST}")
    print(f"  {W}Scan Time     : {DIM}{meta.get('scan_time', 'N/A')}{RST}")
    print(f"  {W}Open Ports    : {BOLD}{meta.get('open_ports_count', 0)}{RST}")
    print(f"  {W}Anomalies     : {BOLD}{meta.get('anomaly_count', 0)}{RST}")
    print(f"  {W}Risk Score    : {risk_color}{BOLD}{risk}{RST}")

    sev_dist = meta.get("severity_distribution", {})
    print(f"\n  {R}CRITICAL: {sev_dist.get('CRITICAL',0):3}  "
          f"\033[38;5;208mHIGH: {sev_dist.get('HIGH',0):3}  "
          f"{Y}MEDIUM: {sev_dist.get('MEDIUM',0):3}  "
          f"{G}LOW: {sev_dist.get('LOW',0):3}{RST}")

    # ── Open Ports ────────────────────────────────────────────────────────────
    if open_ports:
        print_section(f"OPEN PORTS ({len(open_ports)} found)")
        print(f"  {DIM}{'PORT':>6}  {'STATE':8}  {'SERVICE':20}  {'RISK':10}  NOTE{RST}")
        print(f"  {'─'*6}  {'─'*8}  {'─'*20}  {'─'*10}  {'─'*30}")
        for p in open_ports:
            sc = sev_color(p.get("risk", "UNKNOWN"))
            print(f"  {W}{p['port']:>6}{RST}  {'open':8}  {p.get('service','unknown'):20}  "
                  f"{sc}{p.get('risk','?'):10}{RST}  {DIM}{p.get('note','')[:60]}{RST}")
            if p.get("banner"):
                print(f"  {' ':6}  {' ':8}  {DIM}Banner: {p['banner'][:80]}{RST}")

    # ── Anomalies ─────────────────────────────────────────────────────────────
    if anomalies:
        print_section(f"ANOMALIES & RISKS ({len(anomalies)} detected)")
        for a in anomalies:
            sc = sev_color(a["severity"])
            print(f"\n  {sc}{BOLD}[{a['severity']}]{RST} {W}{a['name']}{RST} {DIM}(Rule: {a['rule_id']}){RST}")
            print(f"  {DIM}Ports: {a['matched_ports']}{RST}")
            print(f"  {W}  Issue : {RST}{a['description']}")
            print(f"  {G}  Fix   : {RST}{a['mitigation']}")

    # ── Live Hosts ─────────────────────────────────────────────────────────────
    if live_hosts:
        print_section(f"LIVE HOSTS ({len(live_hosts)} discovered)")
        for h in live_hosts:
            print(f"  {G}● {h}{RST}")

    # ── Recommendations ───────────────────────────────────────────────────────
    print_section("RECOMMENDATIONS")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {C}{i}.{RST} {rec}")

    print(f"\n{DIM}  Report: {filepath}{RST}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python dashboard.py <netsentry_report.json>")
        sys.exit(1)
    render_report(sys.argv[1])
