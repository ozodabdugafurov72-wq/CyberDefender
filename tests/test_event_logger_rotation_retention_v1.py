from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent.logger import EventLogger


class FakeEvent:
    def __init__(self, index: int):
        self.index = index

    def to_dict(self):
        return {
            "event_id": f"evt-{self.index:04d}",
            "event_type": "HIGH_MEMORY_USAGE",
            "severity": "WARNING",
            "value": 88.0 + (self.index / 1000.0),
            "source": "TEST",
            "message": "x" * 90,
        }


def check(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


with tempfile.TemporaryDirectory(prefix="cd_logger_rotation_") as tmp:
    path = Path(tmp) / "logs" / "events.jsonl"
    logger = EventLogger(path, max_bytes=700, backup_count=2)

    for index in range(30):
        logger.log(FakeEvent(index))

    files = [path] + [path.with_name(f"{path.name}.{i}") for i in (1, 2)]
    existing = [p for p in files if p.exists()]

    check(path.exists(), "Active event log exists after rotation")
    check(len(existing) <= 3, "Retention never exceeds active + configured backups")
    check(not path.with_name(f"{path.name}.3").exists(), "No unbounded third backup is created")

    parsed = []
    for file_path in existing:
        raw = file_path.read_bytes()
        check(not raw or raw.endswith(b"\n"), f"{file_path.name} ends on a complete JSONL record")
        for line in raw.splitlines():
            parsed.append(json.loads(line.decode("utf-8")))

    check(all(isinstance(item, dict) for item in parsed), "Every retained record is valid JSON")
    check(logger.get_stats()["logged"] == 30, "Logger accounts for every submitted event")
    check(logger.get_stats()["rotations"] > 0, "Rotation occurred under a tiny test cap")
    check(logger.get_stats()["retained_backups"] <= 2, "Backup count remains bounded")

    newest = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    check(newest[-1]["event_id"] == "evt-0029", "Newest event remains in active log")

    before = {p.name: p.read_bytes() for p in existing}
    health = logger.health_check()
    after = {p.name: p.read_bytes() for p in existing}
    check(health["status"] == "HEALTHY", "Health check reports logger healthy")
    check(before == after, "Health check does not mutate retained audit logs")

print("RESULT: PASS")
