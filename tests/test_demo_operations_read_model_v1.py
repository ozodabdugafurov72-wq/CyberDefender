from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.data.sqlite_repository import SQLiteDataRepository
from dashboard_owner.read_model import OwnerReadModel


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cd_p08_read_model_") as td:
        db = Path(td) / "state" / "data" / "cyberdefender.db"
        repo = SQLiteDataRepository(db)
        try:
            endpoint = {
                "endpoint_id": "endpoint-local",
                "hostname": "demo-host",
                "scope": "LOCAL_ENDPOINT",
                "runtime_version": "2.4",
                "mode": "OBSERVE",
                "runtime_status": "HEALTHY",
                "resource_state": "NORMAL",
                "cpu_percent": 11.5,
                "memory_percent": 61.2,
                "available_memory_mb": 4096,
                "process_count": 210,
                "last_cycle": 7,
            }
            incidents = [
                {
                    "incident_id": "INC-SEC-001",
                    "correlation_key": "agent-local:SuspiciousProcess",
                    "severity": "HIGH",
                    "risk_score": 78,
                    "event_count": 2,
                    "created_at": 1000.0,
                    "updated_at": 1002.0,
                    "detections": [
                        {"type": "PROCESS_CHAIN_ANOMALY", "severity": "HIGH", "source": "RuleEngine", "timestamp": 1000.0, "message": "synthetic security evidence"},
                        {"type": "PERSISTENCE_SIGNAL", "severity": "HIGH", "source": "RuleEngine", "timestamp": 1002.0, "message": "synthetic persistence evidence"},
                    ],
                },
                {
                    "incident_id": "INC-RES-001",
                    "correlation_key": "agent-local:SystemObserver",
                    "severity": "MEDIUM",
                    "risk_score": 30,
                    "event_count": 1,
                    "created_at": 1001.0,
                    "updated_at": 1001.0,
                    "detections": [
                        {"type": "HIGH_MEMORY_USAGE", "severity": "MEDIUM", "source": "SystemObserver", "timestamp": 1001.0, "message": "memory pressure"},
                    ],
                },
            ]
            repo.sync_cycle(
                endpoint=endpoint,
                incidents=incidents,
                risk={"overall_risk_level": "HIGH", "overall_risk_score": 78},
                policy={"outcome": "OBSERVE_ONLY", "recommendation": "OBSERVE", "authorization": "NOT_GRANTED"},
                verification={"outcome": "VERIFIED", "verified": True, "authorization": "NOT_GRANTED"},
            )
        finally:
            repo.close()

        reader = OwnerReadModel(db)
        health = reader.health_check()
        check(health["status"] == "HEALTHY", "Owner read model opens SQLite in healthy read-only mode")
        check(health["version"] == "1.1", "Owner read model exposes P0.8.1 investigation facets version")
        check(health["read_only"] is True and health["authoritative"] is False, "Owner query surface is explicitly read-only and non-authoritative")

        all_rows = reader.search_incidents(limit=20)
        check(len(all_rows) == 2, "Historical incident query returns structured rows")
        security = reader.search_incidents(incident_class="SECURITY", limit=20)
        resource = reader.search_incidents(incident_class="RESOURCE", limit=20)
        check([x["incident_id"] for x in security] == ["INC-SEC-001"], "Security class filter excludes resource incidents")
        check([x["incident_id"] for x in resource] == ["INC-RES-001"], "Resource class filter excludes security incidents")
        high = reader.search_incidents(severity="HIGH", query="SuspiciousProcess", limit=20)
        check(len(high) == 1 and high[0]["incident_id"] == "INC-SEC-001", "Severity + text search are composable")

        injection = reader.search_incidents(query="%' OR 1=1 --", limit=20)
        check(injection == [], "Search input is treated as data, not SQL syntax")

        detail = reader.get_incident("INC-SEC-001")
        check(detail is not None and len(detail["evidence_timeline"]) == 2, "Incident drill-down exposes bounded evidence timeline")
        check(detail["evidence_timeline"][0]["event_type"] == "PROCESS_CHAIN_ANOMALY", "Evidence timeline remains chronological")
        check(detail["sources"] == ["RuleEngine"], "Incident drill-down exposes contributing sources")
        check(detail["signal_types"] == ["PROCESS_CHAIN_ANOMALY", "PERSISTENCE_SIGNAL"], "Incident drill-down exposes distinct signal types")

        endpoint_detail = reader.endpoint_details()
        check(endpoint_detail is not None and endpoint_detail["hostname"] == "demo-host", "Endpoint details are queryable")
        check(len(endpoint_detail["recent_decisions"]) == 1, "Endpoint detail exposes policy/verification history")
        check(endpoint_detail["recent_decisions"][0]["verification_authorization"] == "NOT_GRANTED", "Historical decision preserves authorization boundary")

        conn = reader._connect()
        try:
            blocked = False
            try:
                conn.execute("DELETE FROM incidents")
            except sqlite3.OperationalError:
                blocked = True
            check(blocked, "SQLite query_only/mode=ro prevents dashboard writes")
        finally:
            conn.close()

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
