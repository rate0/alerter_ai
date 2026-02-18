"""
triage_agent.py — Groq LLM-powered SOC triage agent.

Sends a scrubbed alert context to Groq's Llama model and parses the
structured JSON verdict.  Falls back to the ML classifier if Groq is
unavailable or rate-limited.

Security notes
--------------
* PII scrubbing replaces real hostnames, IPs, usernames, and file paths
  with generic tokens BEFORE the data leaves this service.
* The output JSON is validated; prompt-injection attempts that corrupt
  the schema are caught and cause a fallback to ML verdict.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.2-3b-preview")
GROQ_MAX_RPM = int(os.getenv("GROQ_MAX_RPM", "20"))

# Minimum seconds between Groq calls to stay under RPM limit
_MIN_CALL_INTERVAL = 60.0 / GROQ_MAX_RPM  # e.g. 3 s at 20 RPM
_last_call_ts: float = 0.0

# ── PII scrubbing ─────────────────────────────────────────────────────────────

# Regex patterns for common PII / sensitive values
_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
_HOSTNAME_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+)\b"
)
_WIN_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:[^\\\n\"]+\\)*[^\\\n\"]*"
)
_NIX_PATH_RE = re.compile(
    r"/(?:[^\s/\n]+/)+[^\s/\n]+"
)
_USERNAME_RE = re.compile(
    r"\b(?:user|username|account)[=:\s]+([A-Za-z0-9_\-\.@]+)",
    re.IGNORECASE,
)


def _scrub_pii(data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Replace sensitive values in `data` with generic tokens.

    Returns
    -------
    scrubbed_data : dict with replaced values
    mapping       : token → original value (kept server-side only, never sent to LLM)
    """
    mapping: Dict[str, str] = {}
    ip_counter = [0]
    host_counter = [0]
    path_counter = [0]

    def _replace_ip(val: str) -> str:
        def _sub(m: re.Match) -> str:
            ip = m.group(0)
            token = f"IP_{ip_counter[0] + 1}"
            if ip not in mapping.values():
                ip_counter[0] += 1
                mapping[token] = ip
            return token
        return _IP_RE.sub(_sub, val)

    def _replace_paths(val: str) -> str:
        def _sub(m: re.Match) -> str:
            path = m.group(0)
            token = f"PATH_{path_counter[0] + 1}"
            if path not in mapping.values():
                path_counter[0] += 1
                mapping[token] = path
            return token
        val = _WIN_PATH_RE.sub(_sub, val)
        val = _NIX_PATH_RE.sub(_sub, val)
        return val

    def _process_value(v: Any) -> Any:
        if isinstance(v, str):
            v = _replace_ip(v)
            v = _replace_paths(v)
            return v
        if isinstance(v, dict):
            return {k: _process_value(vv) for k, vv in v.items()}
        if isinstance(v, list):
            return [_process_value(item) for item in v]
        return v

    scrubbed: Dict[str, Any] = {}
    for key, value in data.items():
        # Scrub host.name specifically
        if key == "host.name" and isinstance(value, str):
            token = f"HOST_{host_counter[0] + 1}"
            mapping[token] = value
            host_counter[0] += 1
            scrubbed[key] = token
        else:
            scrubbed[key] = _process_value(value)

    return scrubbed, mapping


def _unscrub_response(response: Dict[str, Any], pii_map: Dict[str, str]) -> Dict[str, Any]:
    """
    Replace PII placeholder tokens back with real values in the AI response.
    This restores HOST_1, IP_1, PATH_1 etc. to actual hostnames/IPs/paths
    so Telegram notifications show real data.
    """
    if not pii_map:
        return response

    def _replace_tokens(text: str) -> str:
        result = text
        for token, original in pii_map.items():
            result = result.replace(token, original)
        return result

    # Unscrub explanation
    if "explanation" in response and isinstance(response["explanation"], str):
        response["explanation"] = _replace_tokens(response["explanation"])

    # Unscrub checklist items
    if "checklist" in response and isinstance(response["checklist"], list):
        response["checklist"] = [
            _replace_tokens(item) if isinstance(item, str) else item
            for item in response["checklist"]
        ]

    return response


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    """Remove None / empty values from a dict."""
    return {k: v for k, v in d.items() if v is not None and v != "" and v != []}


# ── Prompt construction ───────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a senior SOC (Security Operations Center) analyst with 10+ years of incident response "
    "experience in threat hunting, malware analysis, and DFIR. "
    "You will receive a full Elastic Defend security alert including all available event fields. "
    "Analyze it thoroughly and return ONLY a valid JSON object with no text outside the JSON.\n\n"
    "Required JSON keys:\n"
    "  \"threat_type\": one of: Malware | Ransomware | Lateral Movement | Credential Access | "
    "Persistence | Exfiltration | Defense Evasion | False Positive | Investigation Required\n"
    "  \"verdict\": one of: CLOSE | OPEN | ESCALATE\n"
    "  \"explanation\": 2-3 sentences. Be SPECIFIC and technical: name the exact MITRE ATT&CK "
    "technique if applicable (e.g. T1059.001 PowerShell, T1003.001 LSASS Memory, T1486 Data Encryption), "
    "reference the actual process name, command line, parent process, or network IOCs from the alert, "
    "and explain what the attacker is attempting to achieve. If False Positive, explain why.\n"
    "  \"confidence\": float 0.0-1.0 reflecting certainty in the verdict\n"
    "  \"checklist\": array of exactly 5 specific, actionable steps. "
    "Reference actual values from the alert (e.g. 'Decode the base64 payload in process.command_line "
    "using CyberChef', 'Block IP 1.2.3.4 at the perimeter firewall'). "
    "Steps must be concrete — avoid generic advice.\n\n"
    "Verdict rules:\n"
    "  ESCALATE: ML score >= 0.7, OR severity=critical, OR confirmed attacker TTP\n"
    "  OPEN: ML score 0.4-0.7, OR suspicious but needs investigation\n"
    "  CLOSE: clearly benign/false positive with solid justification\n\n"
    "Do not include ANY text before or after the JSON object."
)

_USER_PROMPT_TEMPLATE = """Full Elastic Defend alert for SOC triage:

{alert_json}

ML Anomaly Score: {anomaly_score:.4f}  (0.0 = normal, 1.0 = maximally anomalous)
ML Risk Label: {risk_label}

Analyze all available fields above — process command line, parent process, network indicators, "
file paths, user context — and provide a technically precise triage verdict.
Return ONLY the JSON object."""


def _build_user_prompt(
    llm_context: Dict[str, Any], anomaly_score: float, risk_label: str
) -> str:
    alert_json = json.dumps(llm_context, indent=2, ensure_ascii=False, default=str)
    return _USER_PROMPT_TEMPLATE.format(
        alert_json=alert_json,
        anomaly_score=anomaly_score,
        risk_label=risk_label,
    )


# ── JSON output validation ────────────────────────────────────────────────────

_VALID_VERDICTS = {"CLOSE", "OPEN", "ESCALATE"}
_VALID_THREAT_TYPES = {"Malware", "False Positive", "Investigation Required"}


def _validate_groq_response(parsed: Any) -> Optional[Dict[str, Any]]:
    """
    Validate that the parsed Groq response matches the expected schema.
    Returns the validated dict, or None if validation fails (triggers ML fallback).
    This guards against prompt-injection attempts corrupting the schema.
    """
    if not isinstance(parsed, dict):
        logger.warning("Groq response is not a dict: %s", type(parsed))
        return None

    required_keys = {"threat_type", "verdict", "explanation", "confidence", "checklist"}
    if not required_keys.issubset(parsed.keys()):
        missing = required_keys - parsed.keys()
        logger.warning("Groq response missing keys: %s", missing)
        return None

    if parsed["verdict"] not in _VALID_VERDICTS:
        logger.warning("Invalid verdict from Groq: '%s'", parsed["verdict"])
        parsed["verdict"] = "OPEN"  # Safe default

    # Sanitise threat_type
    if parsed["threat_type"] not in _VALID_THREAT_TYPES:
        parsed["threat_type"] = "Investigation Required"

    # Clamp confidence
    try:
        parsed["confidence"] = float(max(0.0, min(1.0, parsed["confidence"])))
    except (TypeError, ValueError):
        parsed["confidence"] = 0.5

    # Ensure checklist is a list of strings
    if not isinstance(parsed["checklist"], list):
        parsed["checklist"] = [str(parsed["checklist"])]
    parsed["checklist"] = [str(item) for item in parsed["checklist"][:10]]

    # Sanitise explanation — cap length, strip injection attempts
    explanation = str(parsed.get("explanation", ""))[:500]
    parsed["explanation"] = explanation

    return parsed


# ── Groq API call ─────────────────────────────────────────────────────────────

def _call_groq(messages: List[Dict[str, str]], retries: int = 3) -> Optional[str]:
    """
    Call the Groq API with rate-limit retry logic.
    Returns the raw content string, or None on failure.
    """
    global _last_call_ts

    try:
        from groq import Groq, RateLimitError, APIError  # type: ignore
    except ImportError:
        logger.error("groq package not installed. Run: pip install groq")
        return None

    client = Groq(api_key=GROQ_API_KEY)

    for attempt in range(1, retries + 1):
        # Rate-limit throttle
        now = time.monotonic()
        elapsed = now - _last_call_ts
        if elapsed < _MIN_CALL_INTERVAL:
            sleep_time = _MIN_CALL_INTERVAL - elapsed
            logger.debug("Rate-limit throttle: sleeping %.2f s", sleep_time)
            time.sleep(sleep_time)

        try:
            _last_call_ts = time.monotonic()
            completion = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                temperature=0.15,     # Slightly higher for more natural language
                max_tokens=800,       # Enough for 3-sentence explanation + 5 detailed steps
                stop=None,
            )
            content = completion.choices[0].message.content
            logger.debug("Groq raw response: %s", content[:300])
            return content

        except RateLimitError:
            wait = 60 / GROQ_MAX_RPM * (attempt + 1)
            logger.warning(
                "Groq 429 rate limit (attempt %d/%d). Waiting %.1f s...",
                attempt, retries, wait,
            )
            time.sleep(wait)

        except APIError as exc:
            logger.error("Groq API error (attempt %d/%d): %s", attempt, retries, exc)
            # Don't retry on permanent errors (bad model, auth, etc.)
            if hasattr(exc, 'status_code') and exc.status_code in (400, 401, 403):
                return None
            if attempt == retries:
                return None
            time.sleep(5 * attempt)

        except Exception as exc:
            logger.error("Unexpected Groq error: %s", exc)
            return None

    return None


def _parse_groq_content(content: str) -> Optional[Dict[str, Any]]:
    """Extract and parse the JSON object from Groq's text response."""
    if not content:
        return None

    # Try direct parse first
    try:
        return json.loads(content.strip())
    except json.JSONDecodeError:
        pass

    # Try to extract JSON block from surrounding text (handles markdown fences)
    json_match = re.search(r"\{[\s\S]*\}", content)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    logger.warning("Could not parse JSON from Groq response: %s", content[:200])
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def triage_alert(
    alert: Dict[str, Any],
    anomaly_score: float,
    risk_label: str,
    ml_fallback_fn: Any = None,
) -> Dict[str, Any]:
    """
    Main entry point: scrub alert, call Groq, validate response.

    Parameters
    ----------
    alert           : Flat alert dict from elastic_client.
    anomaly_score   : Float from ml_classifier.score_alert().
    risk_label      : String label from ml_classifier.score_alert().
    ml_fallback_fn  : Callable(anomaly_score) → dict, used when Groq fails.

    Returns
    -------
    Dict with keys: verdict, threat_type, explanation, confidence, checklist, source
    """
    # ── 1. Build full structured context ──────────────────────────────────────
    # Separate fields into sections for clear LLM presentation.
    # PII is scrubbed from all sensitive fields before leaving the service.

    # Fields that need PII scrubbing (IPs, hostnames, paths, usernames)
    _PII_FIELDS = {
        "host.name", "host.ip", "host.hostname",
        "process.executable", "process.command_line", "process.args",
        "process.parent.executable", "process.parent.command_line",
        "file.path", "file.directory", "file.name",
        "destination.ip", "destination.domain",
        "source.ip", "source.domain",
        "dns.question.name", "url.full", "url.domain",
        "user.name", "user.email",
        "kibana.alert.reason", "rule.description", "message",
    }

    # Scrub PII from sensitive fields
    pii_candidates = {k: v for k, v in alert.items() if k in _PII_FIELDS and v is not None}
    scrubbed, pii_map = _scrub_pii(pii_candidates)

    # Non-scrubbed safe fields (process.name is kept as-is — it's the binary name, not a path)
    def _safe(key: str) -> Any:
        """Return scrubbed value if PII field, otherwise raw value."""
        if key in scrubbed:
            return scrubbed[key]
        return alert.get(key)

    # Build structured sections — the LLM sees a clear, organized alert document
    llm_context: Dict[str, Any] = {}

    # ── Alert summary ──────────────────────────────────────────────────────────
    llm_context["alert"] = _clean({
        "rule_name":    alert.get("kibana.alert.rule.name") or alert.get("rule.name"),
        "severity":     alert.get("kibana.alert.severity"),
        "risk_score":   alert.get("kibana.alert.risk_score"),
        "reason":       _safe("kibana.alert.reason"),
        "workflow":     alert.get("kibana.alert.workflow_status"),
        "timestamp":    alert.get("@timestamp"),
        "rule_description": _safe("rule.description"),
    })

    # ── Event classification ────────────────────────────────────────────────────
    llm_context["event"] = _clean({
        "category": alert.get("event.category"),
        "action":   alert.get("event.action"),
        "type":     alert.get("event.type"),
        "outcome":  alert.get("event.outcome"),
        "dataset":  alert.get("event.dataset"),
        "module":   alert.get("event.module"),
    })

    # ── Host context ───────────────────────────────────────────────────────────
    llm_context["host"] = _clean({
        "name": _safe("host.name"),
        "ip":   _safe("host.ip"),
        "os":   alert.get("host.os.name"),
        "type": alert.get("host.type"),
    })

    # ── Process context (most critical for understanding what ran) ─────────────
    proc = _clean({
        "name":              alert.get("process.name"),
        "command_line":      _safe("process.command_line"),
        "args":              _safe("process.args"),
        "pid":               alert.get("process.pid"),
        "executable":        _safe("process.executable"),
        "working_directory": alert.get("process.working_directory"),
    })
    parent = _clean({
        "name":         alert.get("process.parent.name"),
        "command_line": _safe("process.parent.command_line"),
        "executable":   _safe("process.parent.executable"),
        "pid":          alert.get("process.parent.pid"),
    })
    if parent:
        proc["parent"] = parent
    if proc:
        llm_context["process"] = proc

    # ── Network indicators ──────────────────────────────────────────────────────
    network = _clean({
        "destination_ip":     _safe("destination.ip"),
        "destination_port":   alert.get("destination.port"),
        "destination_domain": _safe("destination.domain"),
        "source_ip":          _safe("source.ip"),
        "source_port":        alert.get("source.port"),
        "dns_query":          _safe("dns.question.name"),
        "url":                _safe("url.full"),
        "protocol":           alert.get("network.protocol"),
        "direction":          alert.get("network.direction"),
    })
    if network:
        llm_context["network"] = network

    # ── File indicators ─────────────────────────────────────────────────────────
    file_ctx = _clean({
        "path":      _safe("file.path"),
        "name":      _safe("file.name"),
        "extension": alert.get("file.extension"),
        "size":      alert.get("file.size"),
        "hash_sha256": alert.get("file.hash.sha256"),
        "hash_md5":    alert.get("file.hash.md5"),
    })
    if file_ctx:
        llm_context["file"] = file_ctx

    # ── User context ────────────────────────────────────────────────────────────
    user = _clean({
        "name":   _safe("user.name"),
        "domain": alert.get("user.domain"),
        "id":     alert.get("user.id"),
    })
    if user:
        llm_context["user"] = user

    # ── Registry (persistence) ──────────────────────────────────────────────────
    registry = _clean({
        "path":  alert.get("registry.path"),
        "key":   alert.get("registry.key"),
        "value": alert.get("registry.value.name"),
        "data":  alert.get("registry.data.strings"),
    })
    if registry:
        llm_context["registry"] = registry

    # ── Raw log message ─────────────────────────────────────────────────────────
    raw_msg = _safe("message")
    if raw_msg:
        llm_context["raw_log_message"] = raw_msg

    # ── 2. Call Groq ──────────────────────────────────────────────────────────
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set — using ML fallback.")
        result = ml_fallback_fn(anomaly_score) if ml_fallback_fn else {}
        result["source"] = "ml_fallback"
        return result

    user_prompt = _build_user_prompt(llm_context, anomaly_score, risk_label)
    logger.debug("LLM context size: %d chars", len(user_prompt))

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    raw_content = _call_groq(messages)

    if raw_content is None:
        logger.warning("Groq unavailable — using ML fallback.")
        result = ml_fallback_fn(anomaly_score) if ml_fallback_fn else {}
        result["source"] = "ml_fallback"
        return result

    # ── 3. Parse & validate ───────────────────────────────────────────────────
    parsed = _parse_groq_content(raw_content)
    validated = _validate_groq_response(parsed) if parsed else None

    if validated is None:
        logger.warning("Groq response failed validation — using ML fallback.")
        result = ml_fallback_fn(anomaly_score) if ml_fallback_fn else {}
        result["source"] = "ml_fallback"
        return result

    # Restore real values (HOST_1 -> actual hostname, IP_1 -> real IP, etc.)
    # so Telegram notifications show actual data, not sanitized placeholders
    validated = _unscrub_response(validated, pii_map)
    validated["source"] = "groq"
    return validated
