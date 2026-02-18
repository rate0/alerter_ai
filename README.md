# alerter_ai

AI-powered SOC Alert Triage System with ML anomaly detection and LLM analysis.

## Features

- **Hybrid ML + AI Architecture**: IsolationForest for anomaly scoring + Groq LLM for intelligent analysis
- **Real-time Monitoring**: Polls Elasticsearch for new Elastic Defend alerts every 30 seconds
- **Telegram Notifications**: Instant alerts with verdict, explanation, and actionable checklist
- **PII Scrubbing**: Sensitive data sanitized before sending to external LLM
- **Audit Trail**: Every decision logged for compliance

## Architecture

```
Elastic Defend (EDR) → Elasticsearch → Python Service → ML + AI → Telegram
```

## Quick Start

```bash
cd soc-ai-triage
pip install -r requirements.txt
cp .env.example .env  # Configure your API keys
python main.py
```

## Configuration

Copy `.env.example` to `.env` and set:
- `ES_HOST`, `ES_USER`, `ES_PASS` — Elasticsearch connection
- `GROQ_API_KEY` — Groq API key for LLM
- `TG_TOKEN`, `TG_CHAT_ID` — Telegram bot credentials

## Components

| File | Description |
|------|-------------|
| `main.py` | Service entry point, polling loop |
| `ml_classifier.py` | IsolationForest anomaly detection (11 features) |
| `triage_agent.py` | Groq LLM integration with PII scrubbing |
| `telegram_notifier.py` | Telegram notifications |
| `elastic_client.py` | Elasticsearch client |
| `audit_logger.py` | Decision audit trail |

## License

MIT
