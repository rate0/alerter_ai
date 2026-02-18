"""
test_ml.py — validate ML classifier scoring on all demo alert types.
Run: python test_ml.py
"""
import logging, sys, os
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s - %(message)s")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml_classifier import explain_score, ml_fallback_verdict, _SCORE_MIN, _SCORE_MAX, _SCORE_RANGE

print()
print("=== CALIBRATION STATS ===")
print(f"  p2  (most anomalous training sample) = {_SCORE_MIN:.4f}")
print(f"  p98 (most normal   training sample)  = {_SCORE_MAX:.4f}")
print(f"  normalisation range                  = {_SCORE_RANGE:.4f}")

ALERTS = [
    {
        "_id": "test-1",
        "kibana.alert.rule.name": "Malware - Suspicious PowerShell Encoded Command",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 73,
        "event.action": "process",
        "event.category": "process",
        "host.name": "WIN-TEST-01",
        "process.name": "powershell.exe",
        "process.executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    },
    {
        "_id": "test-2",
        "kibana.alert.rule.name": "Lateral Movement - SMB Admin Share Access",
        "kibana.alert.severity": "critical",
        "kibana.alert.risk_score": 91,
        "event.action": "network",
        "event.category": "network",
        "host.name": "WIN-DC-01",
        "process.name": "wmic.exe",
        "file.path": r"C:\Windows\Temp\beacon.exe",
        "destination.ip": "10.0.0.5",
        "destination.port": 445,
    },
    {
        "_id": "test-3",
        "kibana.alert.rule.name": "Endpoint Security - Windows Defender Update",
        "kibana.alert.severity": "low",
        "kibana.alert.risk_score": 15,
        "event.action": "process",
        "event.category": "process",
        "host.name": "WIN-TEST-02",
        "process.name": "MpCmdRun.exe",
        "process.executable": r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
    },
    {
        "_id": "test-4",
        "kibana.alert.rule.name": "Ransomware - Mass File Encryption Detected",
        "kibana.alert.severity": "critical",
        "kibana.alert.risk_score": 99,
        "event.action": "file",
        "event.category": "malware",
        "host.name": "WORKSTATION-42",
        "process.name": "vssadmin.exe",
        "process.executable": r"C:\Windows\System32\vssadmin.exe",
        "file.path": r"C:\Users\jsmith\Documents\report.docx.locked",
        "destination.ip": "185.220.101.5",
        "destination.port": 4444,
    },
    {
        "_id": "test-5",
        "kibana.alert.rule.name": "Lateral Movement - Pass-the-Hash (lsass)",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 85,
        "event.action": "network",
        "event.category": "intrusion_detection",
        "host.name": "CORP-PC-07",
        "process.name": "lsass.exe",
        "destination.ip": "10.10.10.200",
        "source.ip": "10.10.10.50",
    },
    {
        "_id": "test-6",
        "kibana.alert.rule.name": "Data Exfiltration - DNS Tunneling",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 78,
        "event.action": "dns",
        "event.category": "dns",
        "host.name": "DEV-LAPTOP-03",
        "process.name": "nslookup.exe",
        "destination.ip": "8.8.8.8",
    },
    {
        "_id": "test-7",
        "kibana.alert.rule.name": "System Noise - svchost periodic check",
        "kibana.alert.severity": "low",
        "kibana.alert.risk_score": 5,
        "event.action": "process",
        "event.category": "process",
        "host.name": "FILESERVER-01",
        "process.name": "svchost.exe",
    },
    {
        "_id": "test-8",
        "kibana.alert.rule.name": "Malware - PowerShell Encoded Macro Dropper",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 80,
        "event.action": "start",
        "event.category": "process",
        "host.name": "CORP-LAPTOP-07",
        "process.name": "powershell.exe",
        "process.command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
        "process.parent.name": "WINWORD.EXE",
        "process.parent.command_line": "WINWORD.EXE /n invoice.docx",
        "destination.ip": "185.220.101.42",
        "destination.port": 4444,
    },
]

# Expected labels after the improved ML pipeline.
# PowerShell encoded cmd:          CRITICAL (encoded cmds are a major TTI red flag)
# Pass-the-Hash lsass:             CRITICAL (IDS category + src+dst IP overrides safe-process)
# DNS Tunneling:                   CRITICAL (high risk_score 78 + dest_ip + high severity)
# PowerShell Encoded Macro Dropper: CRITICAL (encoded cmdline boost +0.15 + dest_ip C2 + high sev)
EXPECTED_LABELS = ["CRITICAL", "CRITICAL", "LOW", "CRITICAL", "CRITICAL", "CRITICAL", "LOW", "CRITICAL"]
EXPECTED_VERDICTS = ["ESCALATE", "ESCALATE", "CLOSE", "ESCALATE", "ESCALATE", "ESCALATE", "CLOSE", "ESCALATE"]

print()
print("=== ALERT SCORING RESULTS ===")
print(f"{'Alert Name':<55} {'Sev':<10} {'Score':<8} {'Label':<10} {'Expected':<12} Status")
print("-" * 110)

all_pass = True
for alert, exp_label, exp_verdict in zip(ALERTS, EXPECTED_LABELS, EXPECTED_VERDICTS):
    result = explain_score(alert)
    score = result["anomaly_score"]
    label = result["risk_label"]
    name = alert["kibana.alert.rule.name"][:53]
    sev = alert["kibana.alert.severity"]
    ok = "PASS" if label == exp_label else "FAIL"
    if ok == "FAIL":
        all_pass = False
    print(f"{name:<55} {sev:<10} {score:<8.4f} {label:<10} {exp_label:<12} [{ok}]")
    for factor in result["risk_factors"]:
        print(f"    > {factor}")
    print()

print()
print("=== ML FALLBACK VERDICTS ===")
for score_val, exp_v in [(0.85, "ESCALATE"), (0.60, "OPEN"), (0.20, "CLOSE")]:
    v = ml_fallback_verdict(score_val)
    ok = "PASS" if v["verdict"] == exp_v else "FAIL"
    print(f"  score={score_val:.2f} => verdict={v['verdict']:<8} confidence={v['confidence']:.2f}  [{ok}]")

print()
if all_pass:
    print("[ALL ML TESTS PASSED]")
else:
    print("[SOME ML TESTS FAILED - review output above]")
    sys.exit(1)
