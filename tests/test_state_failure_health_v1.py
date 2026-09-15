from __future__ import annotations

import base64
import os
import tempfile

from agent.config import load_config
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_state_health_") as td:
        os.environ["CYBERDEFENDER_STATE_DIR"] = td
        os.environ.pop("CYBERDEFENDER_LOG_DIR", None)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()
        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        try:
            event = SecurityEvent(
                event_type="STATE_FAILURE_TEST",
                severity="WARNING",
                value=1,
                source="test",
                message="state failure",
            )
            original = runtime.state_manager.update
            runtime.state_manager.update = lambda event: (_ for _ in ()).throw(PermissionError("intentional"))
            try:
                runtime.update_state(event)
            finally:
                runtime.state_manager.update = original

            health = runtime.health_snapshot()
            checks = {
                "State failure counter increments": runtime.state_failures == 1,
                "Component failure counter increments": runtime.component_failures >= 1,
                "Runtime enters sticky degraded state": runtime.degraded is True,
                "Health reports DEGRADED": health["runtime"]["status"] == "DEGRADED",
                "Failure reason remains observable": str(runtime.last_error).startswith("state:PermissionError"),
            }
            failures = 0
            for label, ok in checks.items():
                print(("PASS" if ok else "FAIL") + " | " + label)
                failures += 0 if ok else 1
            print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'}")
            return 0 if failures == 0 else 1
        finally:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
