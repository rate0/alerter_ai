"""
ml_classifier.py — Anomaly / risk scoring for SOC AI Triage.

Two-stage scoring pipeline
--------------------------
1. Feature extraction  — 11 numerical features from the alert dict, including
   combined event.category + event.action risk, lateral-movement indicators,
   known-safe / known-dangerous process flags, and encoded command-line detection.
2. IsolationForest     — unsupervised anomaly detector trained on 1 000
   synthetic "normal" alerts whose distribution mirrors real-world SIEM
   baselines (40 % process, 30 % network, 20 % file, 10 % other; mostly
   low/medium severity; ~40 % of process alerts are known-safe binaries).

Score normalization is calibrated from the actual IsolationForest training
distribution (2nd/98th percentile of decision_function scores) so the
mapping to [0, 1] is data-driven rather than a hard-coded constant.

Rule-based post-processing applies domain-driven adjustments on top:
  - Critical/high severity floors
  - Boost for known attacker tools (vssadmin, mshta, certutil …)
  - Boost for encoded/obfuscated command lines (-EncodedCommand, IEX, etc.)
  - Reduction for known-safe system processes (MpCmdRun, svchost …)
    only when there are no C2 network indicators

Output
------
anomaly_score : float in [0, 1]  (0 = normal, 1 = maximally anomalous)
risk_label    : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
"""

import logging
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# ── Severity ordinal mapping ────────────────────────────────────────────────────
SEVERITY_MAP: Dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ── Risk weights by event.category (takes priority — more reliable field) ───────
CATEGORY_RISK: Dict[str, float] = {
    "malware": 1.00,
    "intrusion_detection": 0.90,
    "driver": 0.70,
    "process": 0.60,
    "file": 0.55,
    "authentication": 0.55,
    "network": 0.50,
    "registry": 0.50,
    "dns": 0.40,
    "package": 0.35,
}

# ── Risk weights by event.action (secondary signal) ─────────────────────────────
ACTION_RISK: Dict[str, float] = {
    "malware": 1.00,
    "intrusion_detection": 0.90,
    "process": 0.60,
    "file": 0.55,
    "authentication": 0.55,
    "network": 0.50,
    "registry": 0.50,
    "dns": 0.40,
}

# ── Known-safe process whitelist ─────────────────────────────────────────────────
# Frequently false-positived legitimate system binaries.
# Score reduction is applied only when severity ≤ medium AND no C2 indicator.
_SAFE_PROCESSES: frozenset = frozenset({
    "mpcmdrun.exe",         # Windows Defender CLI
    "msmpeng.exe",          # Windows Defender engine
    "nissrv.exe",           # Defender Network Inspection
    "svchost.exe",          # Windows Service Host
    "lsass.exe",            # Local Security Authority
    "csrss.exe",            # Client/Server Runtime
    "wininit.exe",          # Windows Initialization
    "services.exe",         # Service Control Manager
    "winlogon.exe",         # Windows Logon
    "taskhost.exe",         # Task Scheduler Host
    "taskhostw.exe",
    "dllhost.exe",          # COM Surrogate
    "spoolsv.exe",          # Print Spooler
    "searchindexer.exe",    # Windows Search
    "tiworker.exe",         # Windows Update Worker
    "trustedinstaller.exe", # Windows Modules Installer
    "wuauclt.exe",          # Windows Update
    "msiexec.exe",          # Windows Installer
    "backgroundtaskhost.exe",
    "runtimebroker.exe",
    "sgrmbroker.exe",       # System Guard Runtime Monitor
    "audiodg.exe",
    "dwm.exe",              # Desktop Window Manager
    "sihost.exe",           # Shell Infrastructure Host
    "explorer.exe",         # Windows Explorer (legitimate)
})

# ── Known-dangerous process list ────────────────────────────────────────────────
# Attacker tools and LOLBAS (Living Off the Land Binaries) commonly abused.
# Presence raises the anomaly score by +0.20.
_DANGEROUS_PROCESSES: frozenset = frozenset({
    "mimikatz",
    "meterpreter",
    "vssadmin.exe",         # Shadow copy deletion (ransomware)
    "certutil.exe",         # Downloader / decoder abuse
    "bitsadmin.exe",        # Background Intelligent Transfer abuse
    "regsvr32.exe",         # Script execution bypass
    "mshta.exe",            # HTA file execution
    "wscript.exe",          # Windows Script Host
    "cscript.exe",
    "psexec.exe",           # Lateral movement
    "psexec64.exe",
    "wmic.exe",             # WMI lateral movement
    "rundll32.exe",         # DLL execution bypass
    "nc.exe",               # Netcat
    "ncat.exe",
    "netcat",
    "procdump.exe",         # Credential dumping
    "pwdump",
    "fgdump",
    "pwsspy",
    "lazagne",
    "sharpdump",
    "invoke-mimikatz",
})


# ── Feature extraction ──────────────────────────────────────────────────────────

def _severity_to_int(severity: str) -> int:
    return SEVERITY_MAP.get(str(severity).lower(), 0)


def _event_risk(alert: Dict[str, Any]) -> float:
    """
    Combined event risk from event.category and event.action.
    Takes the maximum to ensure any high-risk signal is captured.
    """
    category = str(alert.get("event.category", "")).lower()
    action = str(alert.get("event.action", "")).lower()

    cat_risk = next((w for k, w in CATEGORY_RISK.items() if k in category), 0.35)
    act_risk = next((w for k, w in ACTION_RISK.items() if k in action), 0.35)

    return max(cat_risk, act_risk)


def _is_safe_process(alert: Dict[str, Any]) -> bool:
    proc = str(alert.get("process.name", "")).lower().strip()
    return bool(proc) and any(safe in proc for safe in _SAFE_PROCESSES)


def _is_dangerous_process(alert: Dict[str, Any]) -> bool:
    proc = str(alert.get("process.name", "")).lower().strip()
    exe = str(alert.get("process.executable", "")).lower().strip()
    combined = f"{proc} {exe}"
    return any(danger in combined for danger in _DANGEROUS_PROCESSES)


# ── Obfuscated / encoded command-line patterns ────────────────────────────────
# These are strong indicators of defense evasion (MITRE T1027, T1059.001)
_ENCODED_CMDLINE_PATTERNS: tuple = (
    "-encodedcommand", "-enc ", " -e ",
    "iex(", "iex (", "invoke-expression",
    "frombase64string", "[convert]::frombase64",
    "downloadstring(", "downloadfile(",
    "net.webclient", "bitstransfer",
    "system.reflection.assembly",
    "-noprofile -", "bypass -", "-windowstyle hidden",
    "hidden -windowstyle", "-w hidden",
)


def _has_encoded_cmdline(alert: Dict[str, Any]) -> bool:
    """
    Detect obfuscated or encoded command-line arguments.
    Covers T1027 (Obfuscated Files), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer).
    """
    cmdline = str(alert.get("process.command_line", "")).lower()
    args_raw = alert.get("process.args", "")
    args = " ".join(args_raw).lower() if isinstance(args_raw, list) else str(args_raw).lower()
    parent_cmd = str(alert.get("process.parent.command_line", "")).lower()
    combined = f"{cmdline} {args} {parent_cmd}"
    return any(pattern in combined for pattern in _ENCODED_CMDLINE_PATTERNS)


def _extract_features(alert: Dict[str, Any]) -> np.ndarray:
    """
    Build an 11-dimensional feature vector from an alert dict.

    Index  Name                  Range  Description
    -----  --------------------  -----  -----------------------------------------------
    [0]    severity_int          0-4    Ordinal: unknown=0 low=1 medium=2 high=3 critical=4
    [1]    event_risk            0-1    Max of event.category and event.action risk weights
    [2]    has_process           0/1    process.name is present
    [3]    has_file              0/1    file.path is present
    [4]    has_dest_ip           0/1    destination.ip is present (C2/lateral-movement)
    [5]    rule_score            0-1    kibana.alert.risk_score / 100
    [6]    is_building_block     0/1    Sub-rule / building-block alert (lower standalone risk)
    [7]    has_source_ip         0/1    source.ip is present (lateral-movement indicator)
    [8]    is_safe_process       0/1    process.name matches known-safe whitelist
    [9]    is_dangerous_proc     0/1    process.name matches known-attacker-tool list
    [10]   has_encoded_cmdline   0/1    Obfuscated/encoded command line detected (T1027/T1059)
    """
    severity = alert.get("kibana.alert.severity") or alert.get("severity", "unknown")
    rule_score = float(alert.get("kibana.alert.risk_score", 0) or 0) / 100.0

    return np.array([
        _severity_to_int(severity),
        _event_risk(alert),
        1.0 if alert.get("process.name") else 0.0,
        1.0 if alert.get("file.path") else 0.0,
        1.0 if alert.get("destination.ip") else 0.0,
        min(rule_score, 1.0),
        1.0 if alert.get("kibana.alert.building_block_type") else 0.0,
        1.0 if alert.get("source.ip") else 0.0,
        1.0 if _is_safe_process(alert) else 0.0,
        1.0 if _is_dangerous_process(alert) else 0.0,
        1.0 if _has_encoded_cmdline(alert) else 0.0,
    ], dtype=float)


def get_feature_vector(alert: Dict[str, Any]) -> Dict[str, float]:
    """
    Return the feature vector as a human-readable dict.
    Useful for logging, debugging, and defense demos.
    """
    vec = _extract_features(alert)
    names = [
        "severity_int", "event_risk", "has_process", "has_file",
        "has_dest_ip", "rule_score", "is_building_block", "has_source_ip",
        "is_safe_process", "is_dangerous_proc", "has_encoded_cmdline",
    ]
    return dict(zip(names, vec.tolist()))


# ── Synthetic training baseline ─────────────────────────────────────────────────
# Represents the "normal" alert distribution for a well-tuned SIEM:
#   severity : 60 % low, 35 % medium, 5 % high
#   event type: 40 % process, 30 % network, 20 % file/auth, 10 % other
#   ~40 % of process alerts are known-safe binaries
#   is_dangerous_proc: always 0 in the normal baseline
#   rule_score: mostly 0.05 – 0.45
# This ensures that:
#   - Benign process events (MpCmdRun, svchost) look normal
#   - High-severity events with malware category look anomalous
#   - Attacker tools (vssadmin, wmic) always look anomalous

_RNG = np.random.default_rng(42)
_N = 1_000

# [0] severity_int — real SIEM baselines have ~15% high-severity alerts that are benign
#     (aggressive rule tuning, noisy vendor signatures, etc.)
_sev = _RNG.choice([1, 1, 2, 2, 2, 3], size=_N)                          # 33% low, 50% med, 17% high

# [1] event_risk — realistic mix of benign event types that a tuned SIEM produces
#     process=0.60 (40%), network=0.50 (30%), file/auth=0.55 (15%), dns=0.40 (10%), other=0.35 (5%)
_ev_risk = _RNG.choice(
    [0.60, 0.50, 0.55, 0.40, 0.35],
    size=_N,
    p=[0.40, 0.30, 0.15, 0.10, 0.05],
)

# [2] has_process: 55 % of alerts include process context
_has_proc = (_RNG.random(_N) < 0.55).astype(float)

# [3] has_file: 25 %
_has_file = (_RNG.random(_N) < 0.25).astype(float)

# [4] has_dest_ip: 35 %
_has_dst = (_RNG.random(_N) < 0.35).astype(float)

# [5] rule_score — skewed low but includes realistic noisy high-severity rules
#     beta(1.5, 3) * 0.85 gives range [0.05, 0.85] with median ~0.25
#     This ensures rule_score=0.73 is NOT automatically treated as anomalous
_rule_sc = _RNG.beta(1.5, 3, _N) * 0.85

# [6] is_building_block: 8 %
_is_bb = (_RNG.random(_N) < 0.08).astype(float)

# [7] has_source_ip: 15 % (normal network monitoring events)
_has_src = (_RNG.random(_N) < 0.15).astype(float)

# [8] is_safe_process: ~40 % of process alerts are known-safe system binaries
_is_safe = (_has_proc * (_RNG.random(_N) < 0.40)).astype(float)

# [9] is_dangerous_proc: ZERO in the normal baseline — always anomalous when present
_is_danger = np.zeros(_N)

# [10] has_encoded_cmdline: ZERO in normal baseline — encoded PS is never routine
_has_enc = np.zeros(_N)

_SYNTHETIC_NORMAL = np.column_stack([
    _sev, _ev_risk, _has_proc, _has_file, _has_dst,
    _rule_sc, _is_bb, _has_src, _is_safe, _is_danger, _has_enc,
]).astype(float)

# ── Train IsolationForest ────────────────────────────────────────────────────────
_ISO_FOREST = IsolationForest(
    n_estimators=200,       # More trees → more stable scores
    contamination=0.04,     # ~4% of production alerts expected anomalous
    max_samples=0.8,        # Subsample 80% per tree to reduce variance
    random_state=42,
)
_ISO_FOREST.fit(_SYNTHETIC_NORMAL)

# ── Calibrate normalization from training distribution ──────────────────────────
# decision_function(X): more negative = more anomalous (opposite of what we want)
# We map [p98 → 0, p2 → 1] so output increases with anomalousness.
_train_df_scores = _ISO_FOREST.decision_function(_SYNTHETIC_NORMAL)
_SCORE_MAX = float(np.percentile(_train_df_scores, 98))  # Very normal → maps to score 0
_SCORE_MIN = float(np.percentile(_train_df_scores, 2))   # Very anomalous → maps to score 1
_SCORE_RANGE = _SCORE_MAX - _SCORE_MIN  # Used for normalization

logger.info(
    "IsolationForest trained on %d synthetic samples. "
    "Calibration: p2=%.4f, p98=%.4f (range=%.4f).",
    _N, _SCORE_MIN, _SCORE_MAX, _SCORE_RANGE,
)


# ── Public scoring API ───────────────────────────────────────────────────────────

def score_alert(alert: Dict[str, Any]) -> Tuple[float, str]:
    """
    Compute anomaly score and risk label for a single alert.

    Returns
    -------
    anomaly_score : float in [0, 1]
        0 = normal baseline pattern
        1 = maximally anomalous / high-risk
    risk_label : str
        "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    """
    features = _extract_features(alert).reshape(1, -1)

    # ── Stage 1: IsolationForest score (data-calibrated normalization) ─────────
    raw = float(_ISO_FOREST.decision_function(features)[0])
    anomaly_score = float(np.clip((_SCORE_MAX - raw) / _SCORE_RANGE, 0.0, 1.0))

    # ── Stage 2: Domain-driven rule adjustments ────────────────────────────────
    severity = alert.get("kibana.alert.severity") or alert.get("severity", "unknown")
    sev_int = _severity_to_int(severity)

    # Floor for high/critical severity — never under-score these
    if sev_int >= 4:
        anomaly_score = max(anomaly_score, 0.85)
    elif sev_int == 3:
        anomaly_score = max(anomaly_score, 0.55)

    # Boost for known-attacker tooling
    if _is_dangerous_process(alert):
        anomaly_score = min(1.0, anomaly_score + 0.20)

    # Boost for encoded/obfuscated command lines (T1027 / T1059.001)
    if _has_encoded_cmdline(alert):
        anomaly_score = min(1.0, anomaly_score + 0.15)

    # Reduction for known-safe processes — only when no C2/lateral-movement indicators
    if _is_safe_process(alert) and sev_int <= 2 and not alert.get("destination.ip"):
        anomaly_score = max(0.08, anomaly_score - 0.25)

    anomaly_score = round(min(anomaly_score, 1.0), 4)

    # ── Stage 3: Label ─────────────────────────────────────────────────────────
    if anomaly_score >= 0.75:
        label = "CRITICAL"
    elif anomaly_score >= 0.50:
        label = "HIGH"
    elif anomaly_score >= 0.25:
        label = "MEDIUM"
    else:
        label = "LOW"

    logger.debug(
        "score_alert: raw_if=%.4f → score=%.4f label=%s | features=%s",
        raw, anomaly_score, label,
        {k: round(v, 3) for k, v in get_feature_vector(alert).items()},
    )
    return anomaly_score, label


def score_batch(alerts: List[Dict[str, Any]]) -> List[Tuple[float, str]]:
    """
    Score a batch of alerts.  Uses vectorised IsolationForest inference
    for the base score; rule adjustments are applied per-alert.
    """
    if not alerts:
        return []

    feature_matrix = np.array([_extract_features(a) for a in alerts])
    raw_scores = _ISO_FOREST.decision_function(feature_matrix)
    base_scores = np.clip((_SCORE_MAX - raw_scores) / _SCORE_RANGE, 0.0, 1.0)

    results = []
    for alert, base in zip(alerts, base_scores):
        severity = alert.get("kibana.alert.severity") or alert.get("severity", "unknown")
        sev_int = _severity_to_int(severity)
        score = float(base)

        if sev_int >= 4:
            score = max(score, 0.85)
        elif sev_int == 3:
            score = max(score, 0.55)

        if _is_dangerous_process(alert):
            score = min(1.0, score + 0.20)

        if _has_encoded_cmdline(alert):
            score = min(1.0, score + 0.15)

        if _is_safe_process(alert) and sev_int <= 2 and not alert.get("destination.ip"):
            score = max(0.08, score - 0.25)

        score = round(min(score, 1.0), 4)
        label = (
            "CRITICAL" if score >= 0.75
            else "HIGH" if score >= 0.50
            else "MEDIUM" if score >= 0.25
            else "LOW"
        )
        results.append((score, label))

    return results


def explain_score(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return the score, label, feature vector, and a list of human-readable
    risk factors for debugging and demo purposes.
    """
    score, label = score_alert(alert)
    features = get_feature_vector(alert)
    severity = alert.get("kibana.alert.severity") or alert.get("severity", "unknown")

    factors: List[str] = []
    if features["severity_int"] >= 4:
        factors.append("Critical severity (rule floor >= 0.85)")
    elif features["severity_int"] == 3:
        factors.append("High severity (rule floor >= 0.55)")

    if features["event_risk"] >= 0.90:
        factors.append(f"Malware/IDS event category (risk={features['event_risk']:.2f})")
    elif features["event_risk"] >= 0.60:
        factors.append(f"High-risk event type (risk={features['event_risk']:.2f})")

    if features["is_dangerous_proc"]:
        factors.append(f"Known attacker tool: {alert.get('process.name', '?')} (score boosted +0.20)")

    if features["has_encoded_cmdline"]:
        factors.append("Obfuscated/encoded command line detected — T1027/T1059 (score boosted +0.15)")

    # Only report safe-process reduction if it was actually applied (same conditions as score_alert)
    severity = alert.get("kibana.alert.severity") or alert.get("severity", "unknown")
    sev_int = _severity_to_int(severity)
    if (features["is_safe_process"]
            and sev_int <= 2
            and not alert.get("destination.ip")):
        factors.append(f"Known-safe process: {alert.get('process.name', '?')} (score reduced -0.20)")
    elif features["is_safe_process"]:
        factors.append(
            f"Known-safe process: {alert.get('process.name', '?')} "
            f"(reduction not applied: severity={severity} or C2 indicator present)"
        )

    if features["has_dest_ip"] and features["has_file"] and features["has_process"]:
        factors.append("All 3 lateral-movement indicators present (process + file + dest IP)")
    elif features["has_dest_ip"]:
        factors.append("Outbound network connection (destination.ip present)")

    if features["has_source_ip"]:
        factors.append("Source IP present (possible lateral movement / internal C2)")

    if features["rule_score"] >= 0.70:
        factors.append(f"High Kibana risk score ({features['rule_score']*100:.0f}/100)")

    if not factors:
        factors.append("Alert matches normal baseline pattern (low anomaly)")

    return {
        "anomaly_score": score,
        "risk_label": label,
        "features": features,
        "risk_factors": factors,
    }


def ml_fallback_verdict(anomaly_score: float) -> Dict[str, Any]:
    """
    Produce a structured triage result when Groq LLM is unavailable.
    Used as a fallback in triage_agent.py.
    """
    if anomaly_score >= 0.75:
        verdict = "ESCALATE"
        threat_type = "Investigation Required"
        explanation = (
            "ML anomaly detector flagged a highly unusual alert pattern "
            "significantly deviating from the normal baseline. "
            "Immediate escalation recommended pending manual analyst review."
        )
        confidence = 0.62
        checklist = [
            "Isolate affected host from the network immediately",
            "Capture memory dump and running process list",
            "Review parent-child process tree in EDR console",
            "Check for lateral movement to adjacent hosts",
            "Escalate to Tier-2 analyst with full context",
        ]
    elif anomaly_score >= 0.45:
        verdict = "OPEN"
        threat_type = "Investigation Required"
        explanation = (
            "Alert shows moderate anomaly indicators above the baseline. "
            "Manual investigation by SOC analyst is recommended before closing."
        )
        confidence = 0.52
        checklist = [
            "Review alert details and raw event data in Kibana",
            "Verify process lineage and command-line arguments",
            "Cross-reference source/destination IPs with threat intel",
            "Check asset criticality and owner",
            "Document findings and close or escalate accordingly",
        ]
    else:
        verdict = "CLOSE"
        threat_type = "False Positive"
        explanation = (
            "Alert pattern closely matches the normal system baseline. "
            "Likely a benign event or recurring false positive; auto-closing."
        )
        confidence = 0.58
        checklist = [
            "Verify this is an expected system operation",
            "Consider tuning the detection rule to reduce noise",
            "Monitor for recurrence over next 24 hours",
        ]

    return {
        "verdict": verdict,
        "threat_type": threat_type,
        "explanation": explanation,
        "confidence": confidence,
        "checklist": checklist,
    }
