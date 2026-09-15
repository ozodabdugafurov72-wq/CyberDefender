from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.config import load_config
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


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


tracked = {
    key: os.environ.get(key)
    for key in (
        "CYBERDEFENDER_STATE_DIR",
        "CYBERDEFENDER_LOG_DIR",
        "CYBERDEFENDER_STORAGE_KEY_B64",
        "CYBERDEFENDER_DATA_DB",
        "CYBERDEFENDER_ENDPOINT_ID",
    )
}

runtime = None
try:
    with tempfile.TemporaryDirectory(prefix="cd_p07_runtime_") as tmp:
        root = Path(tmp)
        os.environ["CYBERDEFENDER_STATE_DIR"] = str(root / "state")
        os.environ["CYBERDEFENDER_LOG_DIR"] = str(root / "logs")
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"D" * 32).decode("ascii")
        os.environ["CYBERDEFENDER_ENDPOINT_ID"] = "P07-RUNTIME-ENDPOINT"
        os.environ.pop("CYBERDEFENDER_DATA_DB", None)

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        repo = runtime.data_repository
        check(repo is not None, "Runtime wires SQLiteDataRepository")
        check(runtime.VERSION == "2.4", "Runtime version is P0.7 / 2.4")

        expected_db = (root / "state" / "data" / "cyberdefender.db").resolve()
        health = runtime.health_snapshot()
        data_health = health.get("data_repository", {})
        check(data_health.get("status") == "HEALTHY", "Data repository participates in health snapshot")
        check(Path(data_health.get("db_path", "")).resolve() == expected_db, "Database is owned by configured state root")

        runtime.cycle_count = 7
        runtime.last_resource_result = {
            "state": "DEGRADED",
            "resource": {
                "cpu_percent": 10.0,
                "memory_percent": 90.0,
                "memory_available_mb": 800.0,
            },
        }
        runtime.last_risk_result = {
            "overall_risk_level": "MEDIUM",
            "overall_risk_score": 30,
        }
        runtime.last_policy_result = {
            "policy_outcome": "OBSERVE_ONLY",
            "recommendation": "OBSERVE",
            "authorization": "NOT_GRANTED",
        }
        runtime.last_verification_result = {
            "verification_outcome": "VERIFIED",
            "verified": True,
            "authorization": "NOT_GRANTED",
        }
        incident = {
            "incident_id": "INC-RUNTIME-P07",
            "correlation_key": "agent-local:SystemObserver",
            "severity": "MEDIUM",
            "risk_score": 30,
            "event_count": 4,
            "evidence_count": 1,
            "created_at": 100.0,
            "updated_at": 101.0,
            "detections": [
                {
                    "timestamp": 101.0,
                    "type": "HIGH_MEMORY_USAGE",
                    "severity": "MEDIUM",
                    "source": "SystemObserver",
                    "value": 90.0,
                }
            ],
        }
        observation = {
            "cpu_percent": 11.0,
            "memory_percent": 90.0,
            "memory_available_mb": 790.0,
            "process_count": 260,
        }

        synced = runtime.persist_data_read_model(observation=observation, incidents=[incident])
        check(synced is True, "Runtime synchronizes read model without bypassing security pipeline")
        check(runtime.data_repository_syncs == 1, "Runtime tracks successful SQL sync")

        endpoint = repo.get_endpoint("P07-RUNTIME-ENDPOINT") if repo else None
        check(bool(endpoint) and endpoint.get("last_cycle") == 7, "Runtime endpoint state is queryable")
        stored_incident = repo.get_incident("INC-RUNTIME-P07") if repo else None
        check(bool(stored_incident) and stored_incident.get("event_count") == 4, "Runtime incident state is queryable")

        check(not expected_db.is_relative_to(Path.cwd()), "Configured test database is isolated from repository source")

        runtime.close()
        runtime = None
finally:
    if runtime is not None:
        runtime.close()
    for key, value in tracked.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

print(f"RESULT: PASS={passes} FAIL={fails}")
if fails:
    raise SystemExit(1)
