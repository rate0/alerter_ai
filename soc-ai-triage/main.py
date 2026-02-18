"""
main.py — SOC AI Triage Service entry point.

Polling loop that:
  1. Fetches new alerts from Elasticsearch (.alerts-security.alerts-default)
  2. Scores each alert with the ML classifier (IsolationForest)
  3. Sends alert context to Groq LLM for triage verdict
  4. Posts results to Telegram
  5. Writes every decision to the audit log

Usage
-----
    python main.py

Environment variables are loaded from .env (see .env.example).
"""

import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

# Load .env before any other imports that use env vars
load_dotenv()

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("service.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("soc-triage")

# ── Local modules ─────────────────────────────────────────────────────────────
from audit_logger import log_triage_decision
from elastic_client import build_client, fetch_new_alerts, ping_cluster
from ml_classifier import ml_fallback_verdict, score_alert
from telegram_notifier import send_alert_notification, send_shutdown_notification, send_startup_notification
from triage_agent import triage_alert

# ── Configuration ─────────────────────────────────────────────────────────────
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))  # seconds

# ── Graceful shutdown ─────────────────────────────────────────────────────────
_running = True


def _handle_signal(signum, frame):
    global _running
    logger.info("Shutdown signal received (%s). Stopping...", signum)
    _running = False


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Core processing ───────────────────────────────────────────────────────────

def process_alert(alert: dict) -> None:
    """
    Full triage pipeline for a single alert.
    """
    alert_id = alert.get("_id", "unknown")
    alert_name = (
        alert.get("kibana.alert.rule.name")
        or alert.get("rule.name")
        or "Unknown Rule"
    )
    host_name = alert.get("host.name", "UNKNOWN_HOST")
    severity = alert.get("kibana.alert.severity", "unknown")

    logger.info("Processing alert id=%s name='%s' severity=%s", alert_id, alert_name, severity)

    # ── Step 1: ML scoring ────────────────────────────────────────────────────
    anomaly_score, risk_label = score_alert(alert)
    logger.info("ML score=%.4f label=%s", anomaly_score, risk_label)

    # ── Step 2: AI triage ─────────────────────────────────────────────────────
    triage_result = triage_alert(
        alert=alert,
        anomaly_score=anomaly_score,
        risk_label=risk_label,
        ml_fallback_fn=ml_fallback_verdict,
    )

    verdict = triage_result.get("verdict", "OPEN")
    explanation = triage_result.get("explanation", "No explanation available.")
    confidence = float(triage_result.get("confidence", 0.5))
    checklist = triage_result.get("checklist", [])
    threat_type = triage_result.get("threat_type", "Unknown")
    source = triage_result.get("source", "unknown")

    logger.info(
        "Triage result: verdict=%s threat=%s confidence=%.2f source=%s",
        verdict, threat_type, confidence, source,
    )

    # ── Step 3: Telegram notification ─────────────────────────────────────────
    send_alert_notification(
        alert_name=alert_name,
        verdict=verdict,
        explanation=explanation,
        confidence=confidence,
        checklist=checklist,
        severity=severity,
        anomaly_score=anomaly_score,
        risk_label=risk_label,
        source=source,
    )

    # ── Step 4: Audit log ─────────────────────────────────────────────────────
    log_triage_decision(
        alert_id=alert_id,
        alert_name=alert_name,
        host_name=host_name,
        severity=severity,
        verdict=verdict,
        ai_explanation=explanation,
        confidence=confidence,
        anomaly_score=anomaly_score,
        checklist=checklist,
        source=source,
        extra={
            "threat_type": threat_type,
            "event_action": alert.get("event.action"),
            "process_name": alert.get("process.name"),
            "destination_ip": alert.get("destination.ip"),
        },
    )


def run_polling_loop(es_client) -> None:
    """
    Main event loop: poll ES for new alerts and process each one.
    Anchors to the current time on startup so pre-existing alerts are not
    re-processed every time the service restarts.
    """
    processed_ids: set = set()
    # Anchor to "now" — only alerts arriving AFTER startup are processed.
    # This prevents re-sending old alerts on every restart.
    last_timestamp: str = datetime.now(timezone.utc).isoformat()

    logger.info("Starting polling loop (interval=%ds, anchor=%s).", POLL_INTERVAL, last_timestamp)

    while _running:
        try:
            alerts = fetch_new_alerts(
                client=es_client,
                after_timestamp=last_timestamp,
                processed_ids=processed_ids,
            )

            if alerts:
                logger.info("Found %d new alert(s). Processing...", len(alerts))
                for alert in alerts:
                    if not _running:
                        break
                    try:
                        process_alert(alert)
                        processed_ids.add(alert["_id"])
                    except Exception as exc:
                        logger.error(
                            "Error processing alert %s: %s",
                            alert.get("_id", "?"),
                            exc,
                            exc_info=True,
                        )

                # Advance the timestamp anchor to the last processed alert
                last_ts_raw = alerts[-1].get("@timestamp")
                if last_ts_raw:
                    last_timestamp = last_ts_raw
                    logger.debug("Timestamp anchor updated to: %s", last_timestamp)

                # Keep processed_ids from growing unbounded (keep last 1000)
                if len(processed_ids) > 1000:
                    oldest = list(processed_ids)[: len(processed_ids) - 1000]
                    for oid in oldest:
                        processed_ids.discard(oid)
            else:
                logger.debug("No new alerts found.")

        except Exception as exc:
            logger.error("Polling loop error: %s", exc, exc_info=True)

        # Wait for next poll cycle (interruptible)
        for _ in range(POLL_INTERVAL):
            if not _running:
                break
            time.sleep(1)

    logger.info("Polling loop stopped.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    logger.info("=" * 60)
    logger.info(" SOC AI Triage Service — starting up")
    logger.info(" Timestamp: %s", datetime.now(timezone.utc).isoformat())
    logger.info("=" * 60)

    # Build ES client
    es_client = build_client()

    # Verify connectivity (retry up to 5 times)
    for attempt in range(1, 6):
        if ping_cluster(es_client):
            break
        logger.warning(
            "ES not reachable (attempt %d/5). Retrying in 10s...", attempt
        )
        time.sleep(10)
    else:
        logger.error("Cannot connect to Elasticsearch after 5 attempts. Exiting.")
        sys.exit(1)

    # Notify operator
    send_startup_notification()

    # Start polling
    run_polling_loop(es_client)

    send_shutdown_notification()
    logger.info("SOC AI Triage Service stopped cleanly.")


if __name__ == "__main__":
    main()
