"""
elastic_client.py — Elasticsearch connectivity and alert fetching.

Connects to the local ELK stack, queries the security alerts index,
and returns flat dicts of relevant fields for downstream processing.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from elasticsearch import Elasticsearch, exceptions as es_exceptions

load_dotenv()

logger = logging.getLogger(__name__)

ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "changeme")
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"
ALERTS_INDEX = os.getenv("ALERTS_INDEX", ".alerts-security.alerts-default")
MAX_ALERTS_PER_POLL = int(os.getenv("MAX_ALERTS_PER_POLL", "10"))

# Internal Kibana / ECS fields that add noise to LLM context.
# Everything else from the alert document is passed to the LLM.
_LLM_EXCLUDE_PREFIXES: tuple = (
    "kibana.alert.rule.exceptions_list",
    "kibana.alert.rule.meta",
    "kibana.alert.rule.actions",
    "kibana.alert.rule.throttle",
    "kibana.alert.rule.schedule",
    "kibana.alert.rule.created_by",
    "kibana.alert.rule.updated_by",
    "kibana.alert.rule.revision",
    "kibana.alert.rule.execution",
    "kibana.alert.building_block",
    "kibana.space_ids",
    "kibana.version",
    "agent.ephemeral_id",
)

# Fields used by ML classifier — these MUST exist in the flattened alert dict.
# _flatten_source now returns ALL fields, so this list is for documentation only.
ALERT_FIELDS_FOR_ML = [
    "kibana.alert.severity", "kibana.alert.risk_score",
    "kibana.alert.building_block_type", "event.action", "event.category",
    "process.name", "process.executable", "process.command_line", "process.args",
    "process.parent.name", "file.path", "destination.ip", "source.ip",
]


def build_client() -> Elasticsearch:
    """
    Create and return an Elasticsearch client.

    SSL verification is disabled for the local dev stack (self-signed cert).
    In production, set ES_VERIFY_SSL=true and provide a proper CA bundle.
    """
    kwargs: Dict[str, Any] = {
        "hosts": [ES_HOST],
        "basic_auth": (ES_USER, ES_PASS),
        "verify_certs": ES_VERIFY_SSL,
        "ssl_show_warn": False,
    }
    client = Elasticsearch(**kwargs)
    logger.info("Elasticsearch client created for %s (verify_ssl=%s)", ES_HOST, ES_VERIFY_SSL)
    return client


def ping_cluster(client: Elasticsearch) -> bool:
    """Return True if the cluster is reachable."""
    try:
        info = client.info()
        logger.info(
            "Connected to ES cluster '%s' version %s",
            info["cluster_name"],
            info["version"]["number"],
        )
        return True
    except es_exceptions.ConnectionError as exc:
        logger.error("Cannot reach Elasticsearch: %s", exc)
        return False


def fetch_new_alerts(
    client: Elasticsearch,
    after_timestamp: Optional[str] = None,
    processed_ids: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve new, unprocessed security alerts from the alerts index.

    Parameters
    ----------
    client           : Active ES client.
    after_timestamp  : ISO-8601 timestamp; only alerts newer than this are returned.
                       If None, the last 15 minutes are used as the initial window.
    processed_ids    : Set of alert _ids already handled; used as a secondary dedup guard.

    Returns
    -------
    List of flat alert dicts (field names as keys).
    """
    if processed_ids is None:
        processed_ids = set()

    # Default look-back window if no timestamp anchor yet
    if after_timestamp is None:
        after_timestamp = "now-15m"

    query = {
        "size": MAX_ALERTS_PER_POLL,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": after_timestamp}}},
                    # Only open/new alerts — skip already-triaged ones
                    {
                        "bool": {
                            "should": [
                                {"term": {"kibana.alert.workflow_status": "open"}},
                                {"bool": {"must_not": {"exists": {"field": "kibana.alert.workflow_status"}}}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
    }

    try:
        response = client.search(index=ALERTS_INDEX, body=query)
    except es_exceptions.NotFoundError:
        logger.warning("Index %s not found — no alerts yet.", ALERTS_INDEX)
        return []
    except es_exceptions.ConnectionError as exc:
        logger.error("ES connection error during fetch: %s", exc)
        return []
    except es_exceptions.TransportError as exc:
        logger.error("ES transport error during fetch: %s", exc)
        return []

    hits = response.get("hits", {}).get("hits", [])
    alerts: List[Dict[str, Any]] = []

    for hit in hits:
        doc_id = hit["_id"]
        if doc_id in processed_ids:
            continue

        source = hit.get("_source", {})
        flat = _flatten_source(doc_id, source)
        alerts.append(flat)

    logger.info("Fetched %d new alert(s) from ES.", len(alerts))
    return alerts


def _flatten_source(doc_id: str, source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively flatten the COMPLETE ES alert document into a single-level dict
    using dot-notation keys.  Both storage formats are handled:
      - Already-flat:  {"kibana.alert.severity": "high"}  (Elastic Defend / synthetic)
      - Truly nested:  {"kibana": {"alert": {"severity": "high"}}}  (some rule types)

    All fields are included so the LLM receives maximum context.
    Very large arrays (>20 items) and very long strings (>2000 chars) are truncated.
    """
    flat: Dict[str, Any] = {"_id": doc_id}

    def _recurse(d: Any, prefix: str) -> None:
        if not isinstance(d, dict):
            return
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            # Skip known-noisy internal fields
            if any(full_key.startswith(p) for p in _LLM_EXCLUDE_PREFIXES):
                continue
            if isinstance(v, dict):
                _recurse(v, full_key)
            elif isinstance(v, list):
                if len(v) > 20:
                    continue  # Skip huge arrays (e.g., exception lists)
                flat[full_key] = v
            elif isinstance(v, str):
                flat[full_key] = v[:2000] + "…[truncated]" if len(v) > 2000 else v
            elif v is not None:
                flat[full_key] = v

    # Handle both flat and nested source documents
    _recurse(source, "")

    # Ensure @timestamp always present
    if "@timestamp" not in flat:
        flat["@timestamp"] = datetime.now(timezone.utc).isoformat()

    return flat
