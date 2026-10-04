from __future__ import annotations

"""Harmless temporary-directory ransomware-behavior telemetry simulator.

The simulator writes ordinary plaintext only, renames only files it created,
and never invokes a process, encrypts content, persists, or uses a network.
It is a telemetry fixture, not a response or malware implementation.
"""

import json
import tempfile
import time
import uuid
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable


def simulate_ransomware_behavior(
    consumer: Callable[[dict[str, Any]], None] | None = None,
    *,
    root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Emit the harmless behavior fixture in an owned temporary/rooted area.

    ``root`` is an explicit lab-runner escape hatch.  The default behavior is
    unchanged: the simulator owns and removes its temporary directory.  When
    a caller supplies a root, that directory is created if needed and remains
    caller-owned so a lab pipeline can inspect/quarantine its canary files.
    """
    events: list[dict[str, Any]] = []
    supplied_root = Path(root).expanduser() if root is not None else None
    directory_context = nullcontext(supplied_root) if supplied_root is not None else tempfile.TemporaryDirectory(prefix="CyberDefender-Ransomware-Lab-")
    with directory_context as directory:
        root_path = Path(directory)
        root_path.mkdir(parents=True, exist_ok=True)
        host_id = "simulator-host"
        tenant_id = "simulator-tenant"
        start = time.time()

        def emit(event_type: str, data: dict[str, Any], offset: float) -> None:
            event = {
                "event_type": event_type,
                "event_id": "sim-" + uuid.uuid4().hex,
                "timestamp": start + offset,
                "source": "HarmlessRansomwareSimulator",
                "data": {
                    **data,
                    "host_id": host_id,
                    "tenant_id": tenant_id,
                },
            }
            events.append(event)
            if consumer is not None:
                consumer(event)

        files: list[Path] = []
        for index in range(10):
            path = root_path / f"lab-document-{index}.txt"
            path.write_text("harmless laboratory plaintext\n", encoding="utf-8")
            files.append(path)
            emit("FILE_ACTIVITY", {"operation": "WRITE", "path": str(path)}, index * 0.1)

        for index, path in enumerate(files[:5]):
            renamed = path.with_suffix(".locked")
            path.replace(renamed)
            emit(
                "FILE_ACTIVITY",
                {"operation": "RENAME", "old_path": str(path), "new_path": str(renamed), "path": str(renamed)},
                2.0 + index * 0.1,
            )

        note = root_path / "RECOVER_FILES.txt"
        note.write_text("HARmless lab marker: no encrypted content exists.\n", encoding="utf-8")
        emit("FILE_ACTIVITY", {"operation": "CREATE", "path": str(note)}, 3.0)
    return events


def main() -> int:
    events = simulate_ransomware_behavior()
    print(json.dumps({"status": "SIMULATED_ONLY", "events": len(events), "encryption": False, "network": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
