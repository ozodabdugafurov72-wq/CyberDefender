from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from dashboard_owner import server


def check(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


with tempfile.TemporaryDirectory(prefix="cd_dashboard_rotated_") as tmp:
    active = Path(tmp) / "events.jsonl"
    backup = active.with_name("events.jsonl.1")

    backup.write_text("".join(json.dumps({"seq": i}) + "\n" for i in range(1, 6)), encoding="utf-8")
    active.write_text("".join(json.dumps({"seq": i}) + "\n" for i in range(6, 9)), encoding="utf-8")

    original = server.LOG_FILE
    previous = os.environ.get("CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT")
    try:
        server.LOG_FILE = active
        os.environ["CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT"] = "2"
        events = server.read_events(6)
    finally:
        server.LOG_FILE = original
        if previous is None:
            os.environ.pop("CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT", None)
        else:
            os.environ["CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT"] = previous

    seq = [item["seq"] for item in events]
    check(seq == [8, 7, 6, 5, 4, 3], "Owner dashboard preserves newest-first continuity across rotation")
    check(len(events) == 6, "Rotated reader fills requested bounded window")

print("RESULT: PASS")
