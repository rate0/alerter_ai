"""
audit_logger.py — Audit trail for SOC AI Triage decisions.
Writes structured records to both a human-readable .log file and a JSON file.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv()

AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "audit.log")
AUDIT_JSON_FILE = os.getenv("AUDIT_JSON_FILE", "audit_records.json")

# Configure audit file handler (separate from root logger)
audit_file_logger = logging.getLogger("audit")
audit_file_logger.setLevel(logging.INFO)
audit_file_logger.propagate = False  # Don't bubble up to root logger

if not audit_file_logger.handlers:
    _fh = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    _fh.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    )
    audit_file_logger.addHandler(_fh)


def _load_json_records() -> list:
    """Load existing JSON audit records from disk."""
    if not os.path.exists(AUDIT_JSON_FILE):
        return []
    try:
        with open(AUDIT_JSON_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_json_records(records: list) -> None:
    """Persist JSON audit records to disk."""
    try:
        with open(AUDIT_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False, default=str)
    except OSError as exc:
        logging.getLogger(__name__).error("Failed to save audit JSON: %s", exc)


def log_triage_decision(
    alert_id: str,
    alert_name: str,
    host_name: str,
    severity: str,
    verdict: str,
    ai_explanation: str,
    confidence: float,
    anomaly_score: float,
    checklist: list,
    source: str = "groq",
    operator: str = "ai-triage-bot",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Record a triage decision in both the text audit log and the JSON file.

    Parameters
    ----------
    alert_id        : Elasticsearch _id of the alert document.
    alert_name      : Human-readable rule/alert name.
    host_name       : Hostname (already scrubbed before this call).
    severity        : Alert severity label.
    verdict         : OPEN | CLOSE | ESCALATE
    ai_explanation  : Two-sentence reasoning from Groq (or ML fallback).
    confidence      : Float 0-1 from Groq.
    anomaly_score   : Float from IsolationForest / rule-based classifier.
    checklist       : List of action items.
    source          : "groq" | "ml_fallback"
    operator        : Who/what made the decision.
    extra           : Any additional key-value pairs to store.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # ── Text audit log ─────────────────────────────────────────────────────────
    log_line = (
        f"OPERATOR={operator} | ALERT_ID={alert_id} | NAME={alert_name} | "
        f"HOST={host_name} | SEVERITY={severity} | VERDICT={verdict} | "
        f"CONFIDENCE={confidence:.2f} | ANOMALY={anomaly_score:.4f} | SOURCE={source}"
    )
    audit_file_logger.info(log_line)

    # ── JSON audit record ──────────────────────────────────────────────────────
    record: Dict[str, Any] = {
        "timestamp": timestamp,
        "operator": operator,
        "alert_id": alert_id,
        "alert_name": alert_name,
        "host_name": host_name,
        "severity": severity,
        "verdict": verdict,
        "ai_explanation": ai_explanation,
        "confidence": confidence,
        "anomaly_score": anomaly_score,
        "checklist": checklist,
        "source": source,
    }
    if extra:
        record.update(extra)

    records = _load_json_records()
    records.append(record)
    _save_json_records(records)


def get_all_records() -> list:
    """Return all stored audit records as a Python list."""
    return _load_json_records()
