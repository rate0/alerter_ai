"""
demo_inject.py — Inject a fresh synthetic alert into Elasticsearch for live demo.

Usage (in terminal 2 while main.py is running in terminal 1):
    python demo_inject.py
    python demo_inject.py --type ransomware
    python demo_inject.py --type lateral
    python demo_inject.py --type defender

The main.py polling loop will pick it up within 30 seconds and send a Telegram message.
"""

import argparse
import json
import sys
import urllib3
from datetime import datetime, timezone

from dotenv import load_dotenv
import os

load_dotenv()

urllib3.disable_warnings()

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)

BASE = os.getenv("ES_HOST", "https://localhost:9200")
AUTH = (os.getenv("ES_USER", "elastic"), os.getenv("ES_PASS", "changeme"))
INDEX = os.getenv("ALERTS_INDEX", ".alerts-security.alerts-default")

# ── Alert templates ────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


ALERT_TEMPLATES = {
    "ransomware": {
        "kibana.alert.rule.name": "Ransomware - Mass File Encryption Detected",
        "kibana.alert.severity": "critical",
        "kibana.alert.risk_score": 99,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": "Mass file rename with .locked extension detected",
        "event.action": "file",
        "event.category": "malware",
        "host.name": "WORKSTATION-42",
        "process.name": "vssadmin.exe",
        "process.executable": "C:\\Windows\\System32\\vssadmin.exe",
        "file.path": "C:\\Users\\jsmith\\Documents\\report.docx.locked",
        "destination.ip": "185.220.101.5",
        "destination.port": 4444,
        "@timestamp": _ts(),
    },
    "lateral": {
        "kibana.alert.rule.name": "Lateral Movement - Pass-the-Hash Attack",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 85,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": "NTLM authentication with hashed credentials from non-DC host",
        "event.action": "network",
        "event.category": "intrusion_detection",
        "host.name": "CORP-PC-07",
        "process.name": "lsass.exe",
        "destination.ip": "10.10.10.200",
        "destination.port": 445,
        "source.ip": "10.10.10.50",
        "@timestamp": _ts(),
    },
    "defender": {
        "kibana.alert.rule.name": "Endpoint Security - Windows Defender Scan",
        "kibana.alert.severity": "low",
        "kibana.alert.risk_score": 15,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": "MpCmdRun.exe performed scheduled signature update",
        "event.action": "process",
        "event.category": "authentication",
        "host.name": "OFFICE-PC-12",
        "process.name": "MpCmdRun.exe",
        "process.executable": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
        "@timestamp": _ts(),
    },
    "exfiltration": {
        "kibana.alert.rule.name": "Data Exfiltration - Unusual DNS Tunnel Traffic",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 78,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": "Abnormally long DNS query strings detected to external domain",
        "event.action": "dns",
        "event.category": "network",
        "host.name": "DEV-LAPTOP-03",
        "process.name": "nslookup.exe",
        "destination.ip": "8.8.8.8",
        "destination.port": 53,
        "@timestamp": _ts(),
    },
}


def inject_alert(alert_type: str = "ransomware") -> str:
    """
    Insert a synthetic alert into Elasticsearch.
    Returns the new document _id.
    """
    template = ALERT_TEMPLATES.get(alert_type)
    if template is None:
        print(f"Unknown alert type '{alert_type}'. Choose: {list(ALERT_TEMPLATES.keys())}")
        sys.exit(1)

    # Refresh timestamp to "now" so the polling loop picks it up
    template["@timestamp"] = _ts()

    url = f"{BASE}/{INDEX}/_doc"
    resp = requests.post(
        url,
        auth=AUTH,
        verify=False,
        headers={"Content-Type": "application/json"},
        json=template,
        timeout=10,
    )

    if resp.status_code not in (200, 201):
        print(f"ERROR: ES returned {resp.status_code}: {resp.text}")
        sys.exit(1)

    doc_id = resp.json().get("_id", "?")
    return doc_id


def main():
    parser = argparse.ArgumentParser(description="Inject a demo alert into Elasticsearch")
    parser.add_argument(
        "--type",
        default="ransomware",
        choices=list(ALERT_TEMPLATES.keys()),
        help="Alert template to inject (default: ransomware)",
    )
    args = parser.parse_args()

    alert_type = args.type
    template = ALERT_TEMPLATES[alert_type]

    print("\n" + "=" * 60)
    print(f"  INJECTING DEMO ALERT: {alert_type.upper()}")
    print("=" * 60)
    print(f"  Rule:     {template['kibana.alert.rule.name']}")
    print(f"  Severity: {template['kibana.alert.severity'].upper()}")
    print(f"  Host:     {template.get('host.name', 'N/A')}")
    print(f"  Time:     {template['@timestamp']}")
    print()

    doc_id = inject_alert(alert_type)

    print(f"  Injected into ES  =>  _id = {doc_id}")
    print()
    print("  Waiting for main.py to pick it up (up to 30 seconds)...")
    print("  Watch Telegram for the incoming triage verdict!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
