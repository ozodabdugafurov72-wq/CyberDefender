from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.main import build_managed_runtime
from agent.service_runner import ServiceRunner


def main() -> int:
    tracked = {k: os.environ.get(k) for k in (
        "CYBERDEFENDER_STATE_DIR",
        "CYBERDEFENDER_LOG_DIR",
        "CYBERDEFENDER_STORAGE_KEY_B64",
        "CYBERDEFENDER_ENDPOINT_ID",
        "CYBERDEFENDER_DATA_DB",
    )}
    runtime = None
    try:
        with tempfile.TemporaryDirectory(prefix="cd_service_managed_") as td:
            root = Path(td)
            os.environ["CYBERDEFENDER_STATE_DIR"] = str(root / "state")
            os.environ["CYBERDEFENDER_LOG_DIR"] = str(root / "logs")
            os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode("ascii")
            os.environ["CYBERDEFENDER_ENDPOINT_ID"] = "SERVICE-MANAGED-TEST-ENDPOINT"
            os.environ.pop("CYBERDEFENDER_DATA_DB", None)

            runtime = build_managed_runtime()
            checks = []
            checks.append((runtime.VERSION == "2.4", "Canonical managed factory constructs Runtime 2.4"))
            checks.append((runtime.health_snapshot().get("runtime", {}).get("status") == "HEALTHY", "Managed factory preserves initial runtime health gate"))

            runner = ServiceRunner(lambda: runtime, interval_seconds=0.01)
            runner.run(max_cycles=1)
            checks.append((runner.cycles == 1, "ServiceRunner executes one managed runtime cycle"))
            checks.append((runner.failures == 0, "Managed runtime cycle completes without core failure"))
            checks.append((runtime.running is False, "Managed runtime leaves running state on service stop"))
            checks.append(((root / "state" / "dashboard_runtime.json").exists(), "Managed runtime publishes dashboard state"))

            failures = 0
            for ok, label in checks:
                print(("PASS" if ok else "FAIL") + " | " + label)
                failures += 0 if ok else 1
            print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'}")
            runtime = None  # ServiceRunner stop() already closed it deterministically.
            return 0 if failures == 0 else 1
    finally:
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass
        for key, value in tracked.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    raise SystemExit(main())
