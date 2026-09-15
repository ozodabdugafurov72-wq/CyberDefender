from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.config import load_config
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_state_isolation_") as td:
        root = Path(td).resolve()
        os.environ["CYBERDEFENDER_STATE_DIR"] = str(root)
        os.environ.pop("CYBERDEFENDER_LOG_DIR", None)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        try:
            expected_state = root / "state.json"
            expected_log = root / "logs" / "events.jsonl"
            expected_dashboard = root / "dashboard_runtime.json"

            checks = {
                "EventState is owned by configured state root": runtime.state_manager.state_path == expected_state,
                "EventLogger follows configured state root": runtime.logger.log_path == expected_log,
                "Dashboard publisher follows configured state root": runtime.dashboard_publisher.state_file == expected_dashboard,
                "EventState did not import repository state": runtime.state_manager.get_all_states() == {},
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
