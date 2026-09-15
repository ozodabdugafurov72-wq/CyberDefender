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


class FailingRepository:
    def sync_cycle(self, **kwargs):
        raise OSError("INTENTIONAL_SQL_FAILURE")

    def health_check(self):
        return {
            "component": "FailingRepository",
            "status": "DEGRADED",
            "authoritative": False,
        }

    def close(self):
        return None


tracked = {
    key: os.environ.get(key)
    for key in (
        "CYBERDEFENDER_STATE_DIR",
        "CYBERDEFENDER_LOG_DIR",
        "CYBERDEFENDER_STORAGE_KEY_B64",
    )
}
runtime = None
try:
    with tempfile.TemporaryDirectory(prefix="cd_p07_failure_") as tmp:
        root = Path(tmp)
        os.environ["CYBERDEFENDER_STATE_DIR"] = str(root / "state")
        os.environ["CYBERDEFENDER_LOG_DIR"] = str(root / "logs")
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"F" * 32).decode("ascii")

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        if runtime.data_repository is not None:
            runtime.data_repository.close()
        runtime.data_repository = FailingRepository()  # type: ignore[assignment]

        before_component_failures = runtime.component_failures
        result = runtime.persist_data_read_model(
            observation={
                "cpu_percent": 1.0,
                "memory_percent": 2.0,
                "memory_available_mb": 1000.0,
                "process_count": 10,
            },
            incidents=[],
        )

        check(result is False, "SQL failure is contained")
        check(runtime.data_repository_failures == 1, "SQL failure counter increments")
        check(runtime.component_failures == before_component_failures + 1, "Failure remains observable")
        check(runtime.degraded is False, "Non-authoritative SQL failure does not degrade core security runtime")

        health = runtime.health_snapshot()
        check(health.get("data_repository", {}).get("status") == "DEGRADED", "SQL component health exposes degradation")
        check(health.get("runtime", {}).get("status") == "HEALTHY", "Core runtime health remains HEALTHY when only read model fails")
        check(health.get("runtime_pipeline", {}).get("status") == "HEALTHY", "Canonical security pipeline remains healthy")
        check(health.get("admission_gateway", {}).get("status") == "HEALTHY", "Crypto/replay admission remains healthy")
        check(health.get("spool", {}).get("status") == "HEALTHY", "Durable spool remains healthy")

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
