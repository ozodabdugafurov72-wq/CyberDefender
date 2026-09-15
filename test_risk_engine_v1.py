from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.attack_graph import AttackGraph
from agent.risk_engine import RiskEngine


def check(label: str, condition: bool) -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


print("CYBERDEFENDER — RISK ENGINE v1 FOCUSED + ADVERSARIAL TEST")
print("=" * 72)

# ------------------------------------------------------------
# Fresh deterministic engine
# ------------------------------------------------------------
engine = RiskEngine(max_incidents=4, max_graph_nodes=20, max_graph_edges=40)
graph = AttackGraph(max_nodes=100, max_edges=200)

check("Fresh RiskEngine HEALTHY", engine.health_check()["status"] == "HEALTHY")
check("Fresh AttackGraph HEALTHY", graph.health_check()["status"] == "HEALTHY")

# ------------------------------------------------------------
# Build trusted graph context around one incident
# ------------------------------------------------------------
incident_id = "INC-TEST-001"
check("Incident node accepted", graph.add_node(f"incident:{incident_id}", "INCIDENT")["accepted"])
check("Credential node accepted", graph.add_node("credential:test", "CREDENTIAL")["accepted"])
check("Threat actor node accepted", graph.add_node("actor:test", "THREAT_ACTOR")["accepted"])
check("Process node accepted", graph.add_node("process:test", "PROCESS")["accepted"])
check("Credential relation accepted", graph.add_edge(f"incident:{incident_id}", "credential:test", "TARGETS")["accepted"])
check("Threat actor relation accepted", graph.add_edge("actor:test", f"incident:{incident_id}", "INDICATES")["accepted"])
check("Process relation accepted", graph.add_edge(f"incident:{incident_id}", "process:test", "OBSERVED_IN")["accepted"])

incident = {
    "incident_id": incident_id,
    "risk_score": 70,
    "severity": "HIGH",
    "event_count": 3,
    "detections": [
        {"type": "HIGH_MEMORY_USAGE"},
        {"type": "SUSPICIOUS_PROCESS"},
    ],
}

result = engine.assess(graph, [incident])
check("Assessment accepted", result.get("accepted", True))
check("One incident assessed", result["incidents_assessed"] == 1)
check("Overall score is bounded", 0 <= result["overall_risk_score"] <= 100)
check("Overall level is valid", result["overall_risk_level"] in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
assessment = result["assessments"][0]
check("Incident ID preserved", assessment["incident_id"] == incident_id)
check("Base score respects severity floor", assessment["base_score"] >= 70)
check("Signal bonus is capped", 0 <= assessment["signal_bonus"] <= 9)
check("Diversity bonus is capped", 0 <= assessment["diversity_bonus"] <= 6)
check("Graph bonus is capped", 0 <= assessment["graph_bonus"] <= 25)
check("Graph context sees credential", assessment["graph_context"].get("CREDENTIAL", 0) == 1)
check("Graph context sees threat actor", assessment["graph_context"].get("THREAT_ACTOR", 0) == 1)
check("Risk score never exceeds 100", assessment["risk_score"] <= 100)
check("Authorization remains NOT_GRANTED", assessment["authorization"] == "NOT_GRANTED")
check("Action remains OBSERVE_ONLY", assessment["action"] == "OBSERVE_ONLY")
check("Confidence is bounded", 0 <= assessment["confidence"] <= 95)

# ------------------------------------------------------------
# Determinism
# ------------------------------------------------------------
result2 = engine.assess(graph, [incident])
check("Repeated assessment is deterministic", result2["assessments"] == result["assessments"])
check("Repeated assessment keeps graph healthy", graph.health_check()["status"] == "HEALTHY")

# ------------------------------------------------------------
# Malformed input must not degrade engine
# ------------------------------------------------------------
malformed = engine.assess(graph, [{"severity": "CRITICAL"}])
check("Malformed incident is rejected", malformed["incidents_rejected"] == 1)
check("Malformed incident does not degrade health", engine.health_check()["status"] == "HEALTHY")
check("Malformed input increments rejection counter", engine.health_check()["incidents_rejected"] >= 1)

invalid_graph = engine.assess({"nodes": "bad", "edges": []}, [incident])
check("Malformed graph is rejected", invalid_graph["accepted"] is False)
check("Malformed graph does not degrade health", engine.health_check()["status"] == "HEALTHY")

# ------------------------------------------------------------
# Resource budget
# ------------------------------------------------------------
budget_engine = RiskEngine(max_graph_nodes=2, max_graph_edges=2)
budget_graph = {"nodes": [{"node_id": "a", "node_type": "DEVICE"},
                            {"node_id": "b", "node_type": "PROCESS"},
                            {"node_id": "c", "node_type": "IP"}],
                 "edges": []}
budget_result = budget_engine.assess(budget_graph, [])
check("Graph node budget enforced", budget_result["accepted"] is False)
check("Budget rejection is fail-safe", budget_engine.health_check()["status"] == "HEALTHY")

# ------------------------------------------------------------
# Incident bound
# ------------------------------------------------------------
bounded_engine = RiskEngine(max_incidents=2)
bounded_graph = AttackGraph()
incidents = [
    {"incident_id": "INC-1", "risk_score": 10, "severity": "LOW"},
    {"incident_id": "INC-2", "risk_score": 20, "severity": "MEDIUM"},
    {"incident_id": "INC-3", "risk_score": 90, "severity": "CRITICAL"},
]
bounded_result = bounded_engine.assess(bounded_graph, incidents)
check("Incident assessment count is bounded", bounded_result["incidents_assessed"] == 2)
check("Bounded assessment remains healthy", bounded_engine.health_check()["status"] == "HEALTHY")

# ------------------------------------------------------------
# Unexpected failure isolation
# ------------------------------------------------------------
failure_engine = RiskEngine()
class BrokenGraph:
    def snapshot(self):
        raise RuntimeError("synthetic failure")

failure_result = failure_engine.assess(BrokenGraph(), [])
check("Unexpected graph failure is contained", failure_result["accepted"] is False)
check("Unexpected failure is observable", failure_engine.health_check()["failed"] == 1)
check("Unexpected failure degrades only RiskEngine", failure_engine.health_check()["status"] == "DEGRADED")

print("\nFINAL STATS")
print(engine.get_stats())
print("\nRESULT: PASS")
