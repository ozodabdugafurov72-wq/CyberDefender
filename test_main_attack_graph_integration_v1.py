from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.config import load_config
from agent.safety import SafetyCore
from agent.main import CyberDefenderRuntime


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def main() -> int:
    print("CYBERDEFENDER — ATTACK GRAPH v1 MAIN INTEGRATION TEST")
    print("=" * 72)

    with tempfile.TemporaryDirectory(prefix="cyberdefender_attack_integration_") as state_dir:
        os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()

        config = load_config()
        runtime = CyberDefenderRuntime(SafetyCore(), config)

        check(runtime.process_graph is not None, "ProcessGraph initialized")
        check(runtime.attack_graph is not None, "AttackGraph initialized")

        # Test-only cryptographic bootstrap. This does not change production bootstrap policy.
        check(runtime.key_manager is not None, "KeyManager initialized")
        # Runtime v2.1 + KeyManager v1.1 performs controlled initial
        # provisioning on a truly fresh state.  Do not rotate/create a
        # second key here; just assert operational readiness.
        check(runtime.key_manager.is_ready(), "Test key bootstrap succeeded")

        process_result = runtime.update_process_graph()
        check(isinstance(process_result, dict), "ProcessGraph runtime update returned dict")
        check(bool(process_result.get("accepted")), "ProcessGraph runtime update accepted")

        attack_result = runtime.update_attack_graph()
        check(isinstance(attack_result, dict), "AttackGraph runtime update returned dict")
        check(bool(attack_result.get("accepted")), "AttackGraph accepted ProcessGraph state")

        graph_health = attack_result.get("graph_health", {})
        check(graph_health.get("status") == "HEALTHY", "AttackGraph health HEALTHY after integration")
        check(graph_health.get("failed") == 0, "AttackGraph failure counter remains zero")
        check(graph_health.get("nodes", 0) > 0, "AttackGraph imported process nodes")

        # Correlation incident ingestion is analysis-only and bounded.
        incident = {
            "event_type": "INCIDENT",
            "source": "CorrelationEngine",
            "incident_id": "integration-incident-001",
            "severity": "HIGH",
            "risk_score": 80.0,
            "event_count": 2,
            "correlation_key": "host-test",
        }
        result = runtime.update_attack_graph(incidents=[incident])
        check(isinstance(result, dict), "AttackGraph accepted incident update call")
        check(result.get("incidents_processed") == 1, "One incident processed")
        check(result.get("incidents_accepted") == 1, "Incident accepted into AttackGraph")

        snapshot = runtime.attack_graph.snapshot()
        incident_ids = {
            node.get("node_id") for node in snapshot.get("nodes", [])
            if node.get("node_type") == "INCIDENT"
        }
        check("incident:integration-incident-001" in incident_ids, "Incident node present in graph")

        # Repeated ingestion must remain bounded and duplicate-safe.
        before = runtime.attack_graph.get_stats()["nodes"]
        runtime.update_attack_graph(incidents=[incident])
        after = runtime.attack_graph.get_stats()["nodes"]
        check(after == before, "Repeated incident ingestion does not grow duplicate nodes")
        check(runtime.attack_graph.get_stats()["failed"] == 0, "Repeated ingestion leaves graph failure-free")

        # Health exposure through the runtime is read-only.
        health = runtime.health_snapshot()
        check("attack_graph" in health, "Runtime health exposes AttackGraph")
        check(health["attack_graph"].get("status") == "HEALTHY", "Runtime reports AttackGraph HEALTHY")
        check(health["runtime"].get("status") == "HEALTHY", "AttackGraph integration does not degrade runtime")

        # Containment test: a bounded graph rejection must not become a runtime security failure.
        from agent.attack_graph import AttackGraph
        bounded = AttackGraph(max_nodes=100, max_edges=100, ttl_seconds=60, max_path_nodes=1)
        for i in range(100):
            bounded.add_node(f"device:{i}", "DEVICE")
        rejection = bounded.add_node("device:overflow", "DEVICE")
        check(rejection.get("accepted") is False, "AttackGraph node limit rejects overflow")
        check(bounded.health_check().get("status") == "HEALTHY", "Bounded rejection keeps graph HEALTHY")
        runtime.close()

    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
