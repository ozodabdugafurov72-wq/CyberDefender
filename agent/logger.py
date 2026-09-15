from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock


class EventLogger:
    """
    CyberDefender Security Event Logger v1.2.

    Security events are persisted as JSONL. The active file is rotated before
    it can grow without bound. Rotation preserves a bounded local audit
    history instead of suppressing admitted SecurityEvents.

    Properties:
    - logging only performs local persistence
    - rotation is bounded and deterministic
    - no event is intentionally dropped during rotation
    - health_check never mutates or rotates logs
    - runtime telemetry is reported separately
    """

    VERSION = "1.2"
    DEFAULT_MAX_BYTES = 16 * 1024 * 1024
    DEFAULT_BACKUP_COUNT = 6

    def __init__(
        self,
        log_path=None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ):
        if log_path is None:
            log_path = (
                Path(__file__).resolve().parent.parent
                / "logs"
                / "events.jsonl"
            )

        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise TypeError("max_bytes integer bo'lishi kerak")
        if max_bytes <= 0:
            raise ValueError("max_bytes 0 dan katta bo'lishi kerak")
        if isinstance(backup_count, bool) or not isinstance(backup_count, int):
            raise TypeError("backup_count integer bo'lishi kerak")
        if backup_count < 0:
            raise ValueError("backup_count 0 yoki undan katta bo'lishi kerak")

        self.log_path = Path(log_path)
        self.max_bytes = max_bytes
        self.backup_count = backup_count

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = Lock()
        self._logged_count = 0
        self._failed_count = 0
        self._rotation_count = 0
        self._health_checks = 0
        self._health_failures = 0
        self._last_error = None
        self._last_error_component = None

    def _backup_path(self, index: int) -> Path:
        return self.log_path.with_name(f"{self.log_path.name}.{index}")

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        """Rotate before append when the active JSONL file would exceed cap."""
        try:
            current_size = self.log_path.stat().st_size if self.log_path.exists() else 0
        except OSError:
            current_size = 0

        if current_size == 0 or current_size + incoming_bytes <= self.max_bytes:
            return

        if self.backup_count == 0:
            # No retained backups requested. Replace only the active file.
            self.log_path.unlink(missing_ok=True)
            self._rotation_count += 1
            return

        oldest = self._backup_path(self.backup_count)
        oldest.unlink(missing_ok=True)

        for index in range(self.backup_count - 1, 0, -1):
            source = self._backup_path(index)
            if source.exists():
                os.replace(source, self._backup_path(index + 1))

        if self.log_path.exists():
            os.replace(self.log_path, self._backup_path(1))

        self._rotation_count += 1

    def log(self, event):
        """Persist one SecurityEvent as a single UTF-8 JSONL record."""
        try:
            payload = json.dumps(
                event.to_dict(),
                ensure_ascii=False,
                separators=(",", ":"),
            ) + "\n"
            encoded_size = len(payload.encode("utf-8"))

            with self._lock:
                self._rotate_if_needed(encoded_size)
                with self.log_path.open("a", encoding="utf-8", newline="") as file:
                    file.write(payload)
                    file.flush()

            self._logged_count += 1
            self._last_error = None
            self._last_error_component = None

        except Exception as exc:
            self._failed_count += 1
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._last_error_component = "EventLogger.log"
            raise

    def log_many(self, events):
        for event in events:
            self.log(event)

    def _current_bytes(self) -> int:
        try:
            return self.log_path.stat().st_size if self.log_path.exists() else 0
        except OSError:
            return 0

    def _retained_backup_count(self) -> int:
        count = 0
        for index in range(1, self.backup_count + 1):
            if self._backup_path(index).is_file():
                count += 1
        return count

    def health_check(self) -> dict:
        """Read-only health contract; never writes, rotates, or deletes logs."""
        self._health_checks += 1

        try:
            parent = self.log_path.parent
            if not parent.exists():
                raise OSError("Logger parent directory mavjud emas.")
            if not parent.is_dir():
                raise OSError("Logger parent path directory emas.")

            log_exists = self.log_path.exists()
            if log_exists:
                if not self.log_path.is_file():
                    raise OSError("Logger path file emas.")
                with self.log_path.open("rb") as file:
                    file.read(1)

            self._last_error = None
            self._last_error_component = None

            return {
                "component": "EventLogger",
                "status": "HEALTHY",
                "version": self.VERSION,
                "log_path": str(self.log_path),
                "log_exists": log_exists,
                "logged": self._logged_count,
                "failed": self._failed_count,
                "rotations": self._rotation_count,
                "max_bytes": self.max_bytes,
                "backup_count": self.backup_count,
                "retained_backups": self._retained_backup_count(),
                "current_bytes": self._current_bytes(),
                "health_checks": self._health_checks,
                "health_failures": self._health_failures,
                "last_error": None,
                "last_error_component": None,
            }

        except Exception as exc:
            self._health_failures += 1
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._last_error_component = "EventLogger.health_check"

            return {
                "component": "EventLogger",
                "status": "DEGRADED",
                "version": self.VERSION,
                "log_path": str(self.log_path),
                "log_exists": self.log_path.exists() if self.log_path is not None else False,
                "logged": self._logged_count,
                "failed": self._failed_count,
                "rotations": self._rotation_count,
                "max_bytes": self.max_bytes,
                "backup_count": self.backup_count,
                "retained_backups": self._retained_backup_count(),
                "current_bytes": self._current_bytes(),
                "health_checks": self._health_checks,
                "health_failures": self._health_failures,
                "last_error": self._last_error,
                "last_error_component": self._last_error_component,
            }

    def get_stats(self) -> dict:
        return {
            "component": "EventLogger",
            "version": self.VERSION,
            "log_path": str(self.log_path),
            "logged": self._logged_count,
            "failed": self._failed_count,
            "rotations": self._rotation_count,
            "max_bytes": self.max_bytes,
            "backup_count": self.backup_count,
            "retained_backups": self._retained_backup_count(),
            "current_bytes": self._current_bytes(),
            "health_checks": self._health_checks,
            "health_failures": self._health_failures,
            "last_error": self._last_error,
            "last_error_component": self._last_error_component,
        }


__all__ = ["EventLogger"]
