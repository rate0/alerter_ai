"""
telegram_notifier.py — Send triage verdicts to a Telegram chat.

Uses python-telegram-bot v20+ (async). A synchronous wrapper is provided
for use in the main polling loop context.

Message layout (MarkdownV2)
---------------------------
  🚨 *ESCALATE*
  Ransomware — Mass File Encryption Detected

  🔴 *CRITICAL*    🤖 AI · 99%    ML: 1.000 CRITICAL

  > LLM explanation in blockquote (2 sentences)

  *Analyst checklist:*
  · Isolate the affected host immediately
  · Capture memory dump before any changes
  · ...
"""

import asyncio
import logging
import os
import re
from typing import List

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

TG_TOKEN = os.getenv("TG_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

# ── Emoji maps ─────────────────────────────────────────────────────────────────
_VERDICT_EMOJI = {
    "CLOSE":   "✅",
    "OPEN":    "🔍",
    "ESCALATE":"🚨",
}
_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "unknown":  "⚪",
}
_SOURCE_TAG = {
    "groq":        "🤖 AI",
    "ml_fallback": "📊 ML",
}


# ── Text helpers ───────────────────────────────────────────────────────────────

def _escape_md(text: str) -> str:
    """Escape all Telegram MarkdownV2 special characters (except inside code/pre)."""
    special = r"\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in special else c for c in str(text))


def _escape_blockquote(text: str) -> str:
    """
    Escape text for use INSIDE a MarkdownV2 blockquote line (> ...).
    Same rules as _escape_md but also escapes newlines to keep on one quote block.
    """
    # Replace newlines so the whole explanation stays inside the blockquote
    cleaned = str(text).replace("\n", " ").strip()
    return _escape_md(cleaned)


# ── Message builder ────────────────────────────────────────────────────────────

def _build_message(
    alert_name: str,
    verdict: str,
    explanation: str,
    confidence: float,
    checklist: List[str],
    severity: str = "unknown",
    anomaly_score: float = 0.0,
    risk_label: str = "LOW",
    source: str = "groq",
) -> str:
    """
    Build a clean Telegram MarkdownV2 triage message.

    Visual structure:
      [emoji] VERDICT · Alert name
      [sev emoji] SEVERITY   [src] CONF   ML score LABEL

      > AI explanation as blockquote

      Checklist:
      · Item 1
      · Item 2
    """
    v_emoji  = _VERDICT_EMOJI.get(verdict, "⚠️")
    s_emoji  = _SEVERITY_EMOJI.get(str(severity).lower(), "⚪")
    src_tag  = _SOURCE_TAG.get(source, "📊 ML")
    conf_pct = f"{confidence * 100:.0f}%"
    score_str = f"{anomaly_score:.3f}"

    # Short alert name for the header line (keep it compact)
    short_name = (alert_name[:45] + "…") if len(alert_name) > 45 else alert_name

    # ── Checklist — bullet points, max 5 items ─────────────────────────────────
    items = checklist[:5] if checklist else ["Review alert manually"]
    cl_lines = "\n".join(f"·  {_escape_md(item)}" for item in items)

    # ── Assemble message ───────────────────────────────────────────────────────
    # Line 1: verdict badge + alert name
    # Line 2: severity · source · ML score  (all on one clean info row)
    # Gap
    # Line: blockquote explanation
    # Gap
    # Checklist header + items
    message = (
        f"{v_emoji} *{_escape_md(verdict)}*  ·  {_escape_md(short_name)}\n"
        f"{s_emoji} *{_escape_md(severity.upper())}*"
        f"   {_escape_md(src_tag)} · *{_escape_md(conf_pct)}*"
        f"   🧠 `{_escape_md(score_str)}` {_escape_md(risk_label)}\n"
        f"\n"
        f">{_escape_blockquote(explanation)}\n"
        f"\n"
        f"*Checklist:*\n"
        f"{cl_lines}"
    )
    return message


# ── Async send ─────────────────────────────────────────────────────────────────

async def _async_send(text: str) -> bool:
    """Async helper — send a Telegram message with plain-text fallback."""
    try:
        from telegram import Bot
        from telegram.error import TelegramError
    except ImportError:
        logger.error("python-telegram-bot not installed. Run: pip install python-telegram-bot")
        return False

    if not TG_TOKEN or not TG_CHAT_ID:
        logger.warning("Telegram token or chat ID not configured. Skipping notification.")
        return False

    bot = Bot(token=TG_TOKEN)

    # Try MarkdownV2 first
    try:
        await bot.send_message(chat_id=TG_CHAT_ID, text=text, parse_mode="MarkdownV2")
        logger.info("Telegram notification sent to chat %s", TG_CHAT_ID)
        return True
    except TelegramError as exc:
        logger.warning("MarkdownV2 send failed (%s), retrying as plain text", exc)

    # Fallback: strip all markdown and send plain text
    try:
        plain = re.sub(r"[\\*_`\[\]()~>#+\-=|{}.!]", "", text)
        plain = plain.replace("━", "—").replace("─", "-")
        await bot.send_message(chat_id=TG_CHAT_ID, text=plain)
        logger.info("Telegram plain-text fallback sent to chat %s", TG_CHAT_ID)
        return True
    except Exception as exc2:
        logger.error("Telegram plain text send also failed: %s", exc2)
        return False


# ── Public API ─────────────────────────────────────────────────────────────────

def send_alert_notification(
    alert_name: str,
    verdict: str,
    explanation: str,
    confidence: float,
    checklist: List[str],
    severity: str = "unknown",
    anomaly_score: float = 0.0,
    risk_label: str = "LOW",
    source: str = "groq",
) -> bool:
    """
    Format and send a triage verdict to Telegram.
    Returns True if the message was delivered (MarkdownV2 or plain-text fallback).
    """
    text = _build_message(
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
    try:
        return asyncio.run(_async_send(text))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_async_send(text))
        finally:
            loop.close()


def send_startup_notification(service_name: str = "SOC AI Triage") -> None:
    """Send a startup banner so the operator knows the service is live."""
    name_esc = _escape_md(service_name)
    text = (
        f"\U0001f7e2 *{name_esc}* — online\n"
        f"\n"
        f">Polling Elasticsearch every 30 s\\. "
        f"Verdicts: ✅ CLOSE · 🔍 OPEN · 🚨 ESCALATE"
    )
    try:
        asyncio.run(_async_send(text))
    except Exception as exc:
        logger.warning("Could not send startup notification: %s", exc)


def send_shutdown_notification(service_name: str = "SOC AI Triage") -> None:
    """Send a clean-shutdown banner."""
    name_esc = _escape_md(service_name)
    text = (
        f"\U0001f534 *{name_esc}* — offline\n"
        f"\n"
        f">Polling stopped\\. Restart: `python main\\.py`"
    )
    try:
        asyncio.run(_async_send(text))
    except Exception as exc:
        logger.warning("Could not send shutdown notification: %s", exc)
