"""
Full end-to-end pipeline test.
Fetches real alerts from ES, runs ML + Groq triage, sends Telegram, writes audit.
"""
import sys, os, logging
sys.path.insert(0, '.')
os.chdir(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")

from elastic_client import build_client, ping_cluster, fetch_new_alerts
from ml_classifier import score_alert, ml_fallback_verdict
from triage_agent import triage_alert
from telegram_notifier import send_alert_notification
from audit_logger import log_triage_decision, get_all_records

print("\n" + "="*60)
print("  SOC AI TRIAGE — FULL END-TO-END TEST")
print("="*60)

# Step 1: ES connectivity
print("\n[1] Elasticsearch connectivity...")
client = build_client()
assert ping_cluster(client), "FAIL: Cannot reach ES"
print("    PASS — cluster reachable")

# Step 2: Fetch alerts
print("\n[2] Fetching alerts (last 24h)...")
alerts = fetch_new_alerts(client, after_timestamp="now-24h")
print(f"    Found {len(alerts)} alert(s)")
assert len(alerts) > 0, "FAIL: No alerts found — generate some first"

# Step 3: Process each alert through full pipeline
print("\n[3] Running triage pipeline...")
results = []
for i, alert in enumerate(alerts):
    name = alert.get("kibana.alert.rule.name") or alert.get("rule.name","?")
    sev  = alert.get("kibana.alert.severity","?")
    print(f"\n    Alert {i+1}: [{sev}] {name}")

    # ML scoring
    score, label = score_alert(alert)
    print(f"    ML score={score:.4f}  label={label}")

    # Groq triage (with ML fallback)
    result = triage_alert(alert, score, label, ml_fallback_fn=ml_fallback_verdict)
    verdict     = result.get("verdict","?")
    confidence  = result.get("confidence", 0)
    explanation = result.get("explanation","")
    checklist   = result.get("checklist",[])
    source      = result.get("source","?")
    print(f"    Verdict={verdict}  confidence={confidence:.0%}  source={source}")
    print(f"    Explanation: {explanation[:100]}...")

    # Telegram notification
    ok = send_alert_notification(
        alert_name=name, verdict=verdict, explanation=explanation,
        confidence=confidence, checklist=checklist,
        severity=sev, anomaly_score=score, risk_label=label, source=source,
    )
    print(f"    Telegram: {'SENT' if ok else 'FAILED'}")

    # Audit log
    log_triage_decision(
        alert_id=alert["_id"], alert_name=name,
        host_name=alert.get("host.name","UNKNOWN"),
        severity=sev, verdict=verdict, ai_explanation=explanation,
        confidence=confidence, anomaly_score=score,
        checklist=checklist, source=source,
    )
    print(f"    Audit: WRITTEN")
    results.append({"name": name, "verdict": verdict, "source": source})

# Step 4: Summary
print("\n" + "="*60)
print("  RESULTS SUMMARY")
print("="*60)
for r in results:
    print(f"  {r['verdict']:8} | {r['source']:11} | {r['name']}")

records = get_all_records()
print(f"\nAudit records total: {len(records)}")
print("audit.log and audit_records.json — WRITTEN")
print("\n[ALL TESTS PASSED]")
