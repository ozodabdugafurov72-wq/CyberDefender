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

        log_file = root / "logs" / "events.jsonl"
        with log_file.open("w", encoding="utf-8") as handle:
            for index in range(5000):
                handle.write(json.dumps({"event_type": "TAIL_TEST", "index": index, "message": "x" * 80}) + "\n")

        server.LOG_FILE = log_file
        rows = server.read_events(limit=5)
        check(len(rows) == 5, "Bounded reader returns requested tail size")
        check([row["index"] for row in rows] == [4999, 4998, 4997, 4996, 4995], "Bounded reader returns newest JSONL rows in reverse chronological order")

        snapshot = {
            "publisher": {"sequence": 1, "generated_at": time.time()},
            "runtime": {"running": True, "status": "HEALTHY"},
            "health": {
                "runtime": {"status": "HEALTHY"},
                "safety_core": {"status": "SAFE"},
                "resource_guard": {"status": "HEALTHY", "state": "NORMAL"},
                "policy_engine": {"status": "HEALTHY"},
                "independent_verifier": {"status": "HEALTHY"},
                "authorization_gate": {"status": "HEALTHY", "dry_run_only": True},
                "action_gateway": {"status": "HEALTHY", "real_world_effect": False},
            },
            "observation": {},
            "incidents": [],
        }
        state_file = root / "state" / "dashboard_runtime.json"
        state_file.write_text(json.dumps(snapshot), encoding="utf-8")
        server.STATE_FILE = state_file

        original = server.read_events
        calls = {"count": 0}

        def counted_read_events(limit=server.MAX_EVENTS):
            calls["count"] += 1
            return original(limit)

        server.read_events = counted_read_events
        try:
            state = server.build_state()
        finally:
            server.read_events = original

        check(calls["count"] == 1, "Owner API reads the evidence log only once per state build")
        check(len(state["events"]) <= server.MAX_EVENTS, "Owner API evidence payload remains line-bounded")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
