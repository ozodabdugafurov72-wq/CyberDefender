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
    with tempfile.TemporaryDirectory(prefix="cd_owner_semantics_") as td:
        root = Path(td)
        (root / "state").mkdir()
        (root / "logs").mkdir()
        snapshot = {
            "publisher": {"sequence": 3, "generated_at": time.time()},
            "runtime": {"running": True, "status": "HEALTHY", "cycle_count": 7, "component_failures": 0},
            "health": {
                "runtime": {"status": "HEALTHY"},
                "safety_core": {"status": "SAFE", "safe_mode": False, "shutdown_requested": False},
                "resource_guard": {"status": "HEALTHY", "state": "NORMAL"},
                "policy_engine": {"status": "HEALTHY"},
                "independent_verifier": {"status": "HEALTHY"},
                "authorization_gate": {"status": "HEALTHY", "dry_run_only": True},
                "action_gateway": {"status": "HEALTHY", "real_world_effect": False},
            },
            "observation": {"cpu_percent": 5.0, "memory_percent": 50.0, "memory_available_mb": 4000, "process_count": 150},
            "incidents": [],
        }
        state_file = root / "state" / "dashboard_runtime.json"
        state_file.write_text(json.dumps(snapshot), encoding="utf-8")
        server.STATE_FILE = state_file
        server.LOG_FILE = root / "logs" / "events.jsonl"
        server.DATA_DB_FILE = root / "state" / "data" / "cyberdefender.db"

        state = server.build_state()
        control = state["master_control"]

        check(state["schema"] == "cyberdefender.owner-master-control.v3.5", "Owner schema is upgraded to v3.5")
        check(control["status"] == "ACTIVE", "Operator session is active while runtime is live")
        check(control["control_surface"] == "AVAILABLE", "Control surface availability is explicit")
        check(control["operator_session"] == "ACTIVE", "Operator session state is explicit")
        check(control["unlocked"] is True and control["unlocked_semantics"] == "CONTROL_SURFACE_ONLY", "Legacy unlocked field is explicitly scoped to UI availability")
        check(control["execution_mode"] == "DRY_RUN_ONLY", "Execution remains dry-run only")
        check(control["privileged_execution"] == "PROTECTED", "Privileged execution is semantically protected, not unlocked")
        check(control["real_world_effect"] is False, "Real-world effect remains blocked")
        check(control["safety_enforced"] is True, "Safety enforcement remains active")

    html = (ROOT / "dashboard_owner" / "static" / "index.html").read_text(encoding="utf-8")
    check("ACTIVE · UNLOCKED" not in html and ">UNLOCKED<" not in html, "Ambiguous UNLOCKED wording is removed from visible UI")
    check("ACTIVE · CONTROL SURFACE" in html, "Sidebar describes active control surface instead of privileged unlock")
    check("PRIVILEGED EXECUTION" in html.upper() or "Privileged execution remains protected" in html, "Visible UI explicitly describes privileged execution as protected")
    check("OWNER MASTER CONTROL v3.5" in html, "Dashboard footer exposes v3.5 semantics")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
