from __future__ import annotations

import tempfile
from pathlib import Path

from agent.data.sqlite_repository import SQLiteDataRepository


passes = 0
fails = 0


def check(condition: bool, message: str) -> None:
    global passes, fails
    if condition:
        passes += 1
        print(f"PASS | {message}")
    else:
        fails += 1
        print(f"FAIL | {message}")


with tempfile.TemporaryDirectory(prefix="cd_p07_sqlite_") as tmp:
    db_path = Path(tmp) / "data" / "cyberdefender.db"
    repo = SQLiteDataRepository(db_path)

    health = repo.health_check()
    check(health.get("status") == "HEALTHY", "SQLite repository health is HEALTHY")
    check(health.get("schema_version") == 1, "Schema migration v1 is applied")
    check(health.get("authoritative") is False, "SQL read model is explicitly non-authoritative")

    endpoint = {
        "endpoint_id": "endpoint-test-1",
        "hostname": "TEST-HOST",
        "scope": "LOCAL_ENDPOINT",
        "runtime_version": "2.4",
        "mode": "OBSERVE",
        "runtime_status": "HEALTHY",
        "resource_state": "DEGRADED",
        "cpu_percent": 12.5,
        "memory_percent": 91.0,
        "available_memory_mb": 700.0,
        "process_count": 250,
        "last_cycle": 10,
    }
    detections = [
        {
            "timestamp": 1000.0 + index,
            "type": "HIGH_MEMORY_USAGE",
            "severity": "MEDIUM",
            "source": "RuleEngine",
            "value": 91.0,
            "message": "memory pressure",
        }
        for index in range(3)
    ]
    incident = {
        "incident_id": "INC-P07-1",
        "correlation_key": "agent-local:RuleEngine",
        "severity": "MEDIUM",
        "risk_score": 30,
        "event_count": 75,
        "evidence_count": len(detections),
        "created_at": 1000.0,
        "updated_at": 1002.0,
        "detections": detections,
    }
    risk = {"overall_risk_level": "MEDIUM", "overall_risk_score": 30}
    policy = {
        "policy_outcome": "OBSERVE_ONLY",
        "recommendation": "OBSERVE",
        "authorization": "NOT_GRANTED",
    }
    verification = {
        "verification_outcome": "VERIFIED",
        "verified": True,
        "authorization": "NOT_GRANTED",
    }

    first = repo.sync_cycle(
        endpoint=endpoint,
        incidents=[incident],
        risk=risk,
        policy=policy,
        verification=verification,
    )
    check(first.get("accepted") is True, "First structured cycle is committed")

    endpoint["last_cycle"] = 11
    endpoint["memory_percent"] = 90.5
    second = repo.sync_cycle(
        endpoint=endpoint,
        incidents=[incident],
        risk=risk,
        policy=policy,
        verification=verification,
    )
    check(second.get("accepted") is True, "Repeated structured cycle is committed")

    stored_endpoint = repo.get_endpoint("endpoint-test-1") or {}
    check(stored_endpoint.get("last_cycle") == 11, "Endpoint is updated by stable endpoint_id")
    check(stored_endpoint.get("memory_percent") == 90.5, "Latest endpoint telemetry is queryable")

    stored_incident = repo.get_incident("INC-P07-1") or {}
    check(stored_incident.get("event_count") == 75, "Incident total occurrence count is preserved")
    check(len(stored_incident.get("evidence", [])) == 3, "Bounded incident evidence snapshot is queryable")

    recent_incidents = repo.recent_incidents(limit=10)
    check(len(recent_incidents) == 1, "Incident upsert does not duplicate incident identity")

    decisions = repo.recent_decisions(limit=10)
    check(len(decisions) == 1, "Identical decisions are coalesced by fingerprint")
    check(decisions[0].get("occurrence_count") == 2, "Decision occurrence counter increments without row explosion")

    # Parameterized query regression: hostile-looking identity remains data.
    check(repo.get_endpoint("endpoint-test-1' OR 1=1 --") is None, "Repository queries are parameterized")

    final_health = repo.health_check()
    check(final_health.get("sync_count") == 2, "Repository sync telemetry is accurate")
    check(final_health.get("failed") == 0, "Repository reports zero write failures")

    # Bounded-retention defense in depth.
    bounded_path = Path(tmp) / "data" / "bounded.db"
    bounded = SQLiteDataRepository(bounded_path, max_incidents=2, max_decisions=2)
    many_detections = [
        {
            "timestamp": 2000.0 + index,
            "type": f"TYPE_{index}",
            "severity": "LOW",
            "source": "TEST",
            "value": index,
        }
        for index in range(60)
    ]
    for index in range(3):
        row = {
            "incident_id": f"INC-BOUND-{index}",
            "correlation_key": f"entity:{index}",
            "severity": "LOW",
            "risk_score": 10 + index,
            "event_count": 60,
            "evidence_count": 60,
            "created_at": 2000.0 + index,
            "updated_at": 2000.0 + index,
            "detections": many_detections,
        }
        bounded.sync_cycle(
            endpoint={**endpoint, "last_cycle": 100 + index},
            incidents=[row],
            risk={"overall_risk_level": "LOW", "overall_risk_score": 10 + index},
            policy=policy,
            verification=verification,
        )
    check(len(bounded.recent_incidents(10)) == 2, "Incident history obeys configured retention bound")
    check(len(bounded.recent_decisions(10)) == 2, "Decision history obeys configured retention bound")
    newest = bounded.get_incident("INC-BOUND-2") or {}
    check(len(newest.get("evidence", [])) == 50, "SQL evidence is independently bounded to 50 rows per incident")
    bounded.close()

    repo.close()

print(f"RESULT: PASS={passes} FAIL={fails}")
if fails:
    raise SystemExit(1)
