"""Check endpoint telemetry presence in Elasticsearch."""
import os, sys, urllib3
urllib3.disable_warnings()
sys.path.insert(0, os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))
from dotenv import load_dotenv; load_dotenv()
from elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=[os.getenv("ES_HOST", "https://localhost:9200")],
    basic_auth=(os.getenv("ES_USER", "elastic"), os.getenv("ES_PASS", "changeme")),
    verify_certs=False, ssl_show_warn=False,
)

print("=== ENDPOINT EVENT INDICES ===")
try:
    resp = es.cat.indices(index="logs-endpoint*", h="index,docs.count,store.size", s="index")
    print(resp or "(none found)")
except Exception as e:
    print(f"Error: {e}")

print()
print("=== RECENT PROCESS EVENTS (last 30m) ===")
try:
    resp2 = es.search(index="logs-endpoint.events.process-*", body={
        "size": 5,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "host.name", "process.name", "process.command_line", "event.action"],
        "query": {"range": {"@timestamp": {"gte": "now-30m"}}},
    }, ignore=[404])
    hits = resp2.get("hits", {}).get("hits", [])
    print(f"Count: {len(hits)}")
    for h in hits:
        s = h["_source"]
        ts = s.get("@timestamp", "?")[:19]
        proc = s.get("process.name") or s.get("process", {}).get("name", "?")
        cmd = str(s.get("process.command_line") or s.get("process", {}).get("command_line", ""))[:80]
        print(f"  {ts}  {proc}  {cmd}")
except Exception as e:
    print(f"Error: {e}")

print()
print("=== SECURITY ALERTS IN LAST 1H ===")
try:
    resp3 = es.search(index=".alerts-security.alerts-default", body={
        "size": 5,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity"],
        "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
    }, ignore=[404])
    hits3 = resp3.get("hits", {}).get("hits", [])
    print(f"Count: {len(hits3)}")
    for h in hits3:
        s = h["_source"]
        ts = s.get("@timestamp", "?")[:19]
        name = s.get("kibana.alert.rule.name") or s.get("kibana", {}).get("alert", {}).get("rule", {}).get("name", "?")
        sev = s.get("kibana.alert.severity", "?")
        print(f"  {ts}  [{sev}]  {name}")
except Exception as e:
    print(f"Error: {e}")

print()
print("=== AGENT STATUS CHECK (endpoint.diagnostic.summary index) ===")
try:
    resp4 = es.search(index="metrics-elastic_agent.*", body={
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "host.name", "elastic_agent.version", "elastic_agent.state"],
        "query": {"range": {"@timestamp": {"gte": "now-10m"}}},
    }, ignore=[404])
    hits4 = resp4.get("hits", {}).get("hits", [])
    print(f"Agent metric events (last 10m): {len(hits4)}")
    for h in hits4:
        s = h["_source"]
        print(f"  host={s.get('host', {}).get('name', '?')}  version={s.get('elastic_agent', {}).get('version', '?')}  state={s.get('elastic_agent', {}).get('state', '?')}")
except Exception as e:
    print(f"Error: {e}")
