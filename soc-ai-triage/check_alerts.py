"""Quick diagnostic: check ES connectivity and list current alerts."""
import sys, os, urllib3, requests, json
from dotenv import load_dotenv
load_dotenv()
urllib3.disable_warnings()

BASE = os.getenv("ES_HOST", "https://localhost:9200")
AUTH = (os.getenv("ES_USER", "elastic"), os.getenv("ES_PASS", "changeme"))

# 1. Cluster health
r = requests.get(f"{BASE}/_cluster/health", auth=AUTH, verify=False)
h = r.json()
print(f"Cluster: {h['cluster_name']}  status={h['status']}  nodes={h['number_of_nodes']}")

# 2. Count alerts
r = requests.post(
    f"{BASE}/.alerts-security.alerts-default/_search",
    auth=AUTH, verify=False,
    headers={"Content-Type": "application/json"},
    json={"size": 20, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"match_all": {}}},
)
data = r.json()
hits = data.get("hits", {})
total = hits.get("total", {}).get("value", 0)
print(f"\nTotal alerts in index: {total}")

for h in hits.get("hits", []):
    s = h["_source"]
    name = s.get("kibana.alert.rule.name") or s.get("rule", {}).get("name", "?")
    sev  = s.get("kibana.alert.severity", "?")
    ts   = str(s.get("@timestamp", "?"))[:19]
    wf   = s.get("kibana.alert.workflow_status", "open")
    doc_id = h["_id"][:16]
    print(f"  [{sev:8}] {name[:55]:55} | {ts} | status={wf} | id={doc_id}")
