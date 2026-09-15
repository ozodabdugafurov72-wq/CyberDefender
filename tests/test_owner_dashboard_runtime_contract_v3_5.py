from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dashboard_owner import server


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "state").mkdir()
        (root / "logs").mkdir()

        snapshot = {
            "publisher": {"component": "RuntimeStatePublisher", "sequence": 9, "generated_at": time.time()},
            "runtime": {"running": True, "status": "HEALTHY", "cycle_count": 33, "component_failures": 0},
            "health": {
                "runtime": {"status": "HEALTHY"},
                "safety_core": {"status": "SAFE"},
                "resource_guard": {"component": "ResourceGuard", "status": "HEALTHY", "state": "DEGRADED", "version": "2.2"},
                "dashboard_publisher": {"component": "RuntimeStatePublisher", "status": "HEALTHY", "schema_version": "1.0", "publish_count": 8, "publish_failures": 0},
                "data_repository": {"component": "SQLiteDataRepository", "status": "HEALTHY", "version": "1.1", "schema_version": 1, "authoritative": False, "sync_count": 33, "failed": 0, "db_bytes": 4096},
                "risk_engine": {"status": "HEALTHY"},
                "policy_engine": {"status": "HEALTHY"},
                "independent_verifier": {"status": "HEALTHY"},
                "authorization_gate": {"status": "HEALTHY", "dry_run_only": True},
                "action_gateway": {"status": "HEALTHY", "real_world_effect": False},
            },
            "observation": {
                "cpu_percent": 7.5,
                "memory_percent": 90.2,
                "memory_available_mb": 777.29,
                "process_count": 281,
            },
            "incidents": [
                {"incident_id": "INC-RES", "severity": "CRITICAL", "risk_score": 60, "correlation_key": "agent-local:SystemObserver", "detections": [{"type": "HIGH_MEMORY_USAGE", "severity": "CRITICAL"}]},
            ],
        }

        state_file = root / "state" / "dashboard_runtime.json"
        state_file.write_text(json.dumps(snapshot), encoding="utf-8")
        server.STATE_FILE = state_file
        server.LOG_FILE = root / "logs" / "events.jsonl"

        state = server.build_state()

        check(state["schema"] == "cyberdefender.owner-master-control.v3.5", "Owner state schema matches server v3.5")
        check(state["overall_status"] == "HEALTHY", "Runtime operational health remains HEALTHY")
        check(state["resource_posture"] == "DEGRADED", "Resource posture uses ResourceGuard state, not operational status")
        check(state["resource_state"]["available_memory_mb"] == 777.29, "memory_available_mb is normalized for dashboard")
        check(state["incident_summary"]["resource_incidents"] == 1, "Resource incident remains classified as resource")
        check(state["incident_summary"]["security_incidents"] == 0, "Resource incident does not inflate security incident count")
        check(state["incident_summary"]["critical_security_incidents"] == 0, "Critical resource severity does not inflate critical security count")
        check(state["incident_summary"]["critical_resource_incidents"] == 1, "Critical resource severity remains separately visible")

        rows = {row["key"]: row for row in state["components"]}
        check(rows["resource_guard"]["status"] == "DEGRADED", "Component matrix displays ResourceGuard pressure state")
        check(rows["resource_guard"]["operational_status"] == "HEALTHY", "Component matrix preserves ResourceGuard operational health")
        check(rows["dashboard_publisher"]["status"] == "HEALTHY", "Runtime Publisher is no longer UNKNOWN")
        check(rows["data_repository"]["status"] == "HEALTHY", "Data Store is first-class in component matrix")
        check(state["data_store"]["authoritative"] is False, "Dashboard exposes SQL as non-authoritative")
        check(state["data_store"]["sync_count"] == 33, "Dashboard exposes structured data sync telemetry")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
