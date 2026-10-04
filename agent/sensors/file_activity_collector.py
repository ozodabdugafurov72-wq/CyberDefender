from __future__ import annotations

"""Bounded, marker-gated Windows filesystem activity observation.

The collector deliberately uses a bounded polling snapshot rather than a
second telemetry subsystem.  It observes only one explicitly approved lab
root and emits normalized ``FILE_ACTIVITY`` records for the existing
ThreatSignalEngine.  It never reads file contents, executes files, or takes a
response action.
"""

from collections import deque
import hashlib
import os
from pathlib import Path
import stat
import time
import uuid
from typing import Any

from agent.quarantine.contracts import (
    CANARY_MARKER as QUARANTINE_CANARY_MARKER,
    CANARY_MARKER_FILENAME as QUARANTINE_CANARY_MARKER_FILENAME,
)

FILE_ACTIVITY_CANARY_MARKER_FILENAME = ".cyberdefender-file-activity-canary"
FILE_ACTIVITY_CANARY_MARKER = "CYBERDEFENDER_FILE_ACTIVITY_CANARY_V1"
LAB_FILE_ACTIVITY_ENABLE_MARKER_FILENAME = ".cyberdefender-lab-file-activity-enabled"
LAB_FILE_ACTIVITY_ENABLE_MARKER = "CYBERDEFENDER_LAB_FILE_ACTIVITY_ENABLED_V1"
LAB_AUTO_QUARANTINE_ENABLE_MARKER_FILENAME = ".cyberdefender-lab-auto-quarantine-enabled"
LAB_AUTO_QUARANTINE_ENABLE_MARKER = "CYBERDEFENDER_LAB_AUTO_QUARANTINE_ENABLED_V1"
DEFAULT_LAB_FILE_ACTIVITY_ROOT = Path(r"C:\CD\LAB\LiveRansomwareTest")


class FileActivityCollectorError(RuntimeError):
    """Fail-closed collector contract error."""


class FileActivityCollector:
    """Observe a single dedicated lab root with bounded polling state."""

    VERSION = "1.0"
    MAX_FILES_DEFAULT = 1024
    MAX_EVENTS_PER_POLL_DEFAULT = 64
    MAX_EVENTS_PER_WINDOW_DEFAULT = 256
    EVENT_WINDOW_SECONDS = 30.0
    MAX_DEPTH = 8
    MAX_PATH_LENGTH = 512

    def __init__(
        self,
        approved_root: str | Path,
        *,
        endpoint_id: str,
        tenant_id: str = "lab-tenant",
        host_id: str | None = None,
        max_files: int = MAX_FILES_DEFAULT,
        max_events_per_poll: int = MAX_EVENTS_PER_POLL_DEFAULT,
        max_events_per_window: int = MAX_EVENTS_PER_WINDOW_DEFAULT,
        require_marker: bool = True,
    ) -> None:
        if not isinstance(endpoint_id, str) or not endpoint_id.strip():
            raise ValueError("endpoint_id is required")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        for name, value, minimum in (
            ("max_files", max_files, 1),
            ("max_events_per_poll", max_events_per_poll, 1),
            ("max_events_per_window", max_events_per_window, 1),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"{name} must be a positive integer")
        try:
            raw_root = Path(approved_root).expanduser()
            if self._has_reparse_component(raw_root):
                raise FileActivityCollectorError("approved root reparse path rejected")
            # Keep the lexical absolute path for identity/prefix checks;
            # resolving here could hide a symlink or junction before the
            # fail-closed reparse check runs.
            root = Path(os.path.abspath(str(raw_root)))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise FileActivityCollectorError("approved root cannot be resolved") from exc
        if not root.is_absolute():
            raise FileActivityCollectorError("approved root must be absolute")
        self.approved_root = root
        self.endpoint_id = endpoint_id.strip()[:128]
        self.tenant_id = tenant_id.strip()[:128]
        self.host_id = (host_id or "").strip()[:128] or None
        self.max_files = max_files
        self.max_events_per_poll = max_events_per_poll
        self.max_events_per_window = max_events_per_window
        self.require_marker = bool(require_marker)
        self._snapshot: dict[str, dict[str, Any]] = {}
        self._initialized = False
        self._event_times: deque[float] = deque(maxlen=max_events_per_window)
        self._dedupe: dict[str, float] = {}
        self._polls = 0
        self._events_emitted = 0
        self._events_dropped = 0
        self._failures = 0
        self._last_error: str | None = None
        self._last_poll_at: float | None = None
        self._last_event_at: float | None = None

    @staticmethod
    def _has_reparse_component(path: Path) -> bool:
        try:
            current = Path(path).absolute()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            while True:
                info = os.lstat(current)
                if current.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & reparse_flag):
                    return True
                if current.parent == current:
                    return False
                current = current.parent
        except (OSError, RuntimeError, ValueError):
            return True

    def _validate_root(self) -> None:
        if self._has_reparse_component(self.approved_root):
            raise FileActivityCollectorError("approved root reparse path rejected")
        if not self.approved_root.is_dir() or self.approved_root.is_symlink():
            raise FileActivityCollectorError("approved root is unavailable")
        if self.require_marker:
            marker = self.approved_root / FILE_ACTIVITY_CANARY_MARKER_FILENAME
            if self._has_reparse_component(marker) or not marker.is_file():
                raise FileActivityCollectorError("file activity canary marker required")
            if marker.read_text(encoding="utf-8") != FILE_ACTIVITY_CANARY_MARKER:
                raise FileActivityCollectorError("file activity canary marker invalid")

    def _normalize_path(self, path: Path) -> str:
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(self.approved_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise FileActivityCollectorError("path outside approved root") from exc
        if self._has_reparse_component(path):
            raise FileActivityCollectorError("file reparse path rejected")
        value = str(resolved)
        if len(value) > self.MAX_PATH_LENGTH:
            raise FileActivityCollectorError("path length limit exceeded")
        return value

    def _scan(self) -> dict[str, dict[str, Any]]:
        self._validate_root()
        result: dict[str, dict[str, Any]] = {}
        pending: list[tuple[Path, int]] = [(self.approved_root, 0)]
        while pending:
            directory, depth = pending.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError as exc:
                raise FileActivityCollectorError("directory scan failed") from exc
            if len(result) > self.max_files:
                raise FileActivityCollectorError("file scan limit exceeded")
            for entry in entries:
                path = Path(entry.path)
                if path.name == FILE_ACTIVITY_CANARY_MARKER_FILENAME:
                    continue
                if self._has_reparse_component(path):
                    raise FileActivityCollectorError("reparse path encountered")
                try:
                    is_directory = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError as exc:
                    raise FileActivityCollectorError("entry type unavailable") from exc
                if is_directory:
                    if depth >= self.MAX_DEPTH:
                        raise FileActivityCollectorError("directory depth limit exceeded")
                    pending.append((path, depth + 1))
                    continue
                if not is_file:
                    continue
                normalized = self._normalize_path(path)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise FileActivityCollectorError("file metadata unavailable") from exc
                # Some Windows directory-entry providers report zero for
                # ``DirEntry.stat().st_ino`` even though the pathname stat
                # exposes the stable file identity.  Fall back to a second
                # no-follow stat before falling back to the path itself;
                # otherwise a rename would be misreported as DELETE+CREATE.
                device = int(getattr(info, "st_dev", 0))
                inode = int(getattr(info, "st_ino", 0))
                if device == 0 and inode == 0:
                    try:
                        path_info = path.stat(follow_symlinks=False)
                        device = int(getattr(path_info, "st_dev", 0))
                        inode = int(getattr(path_info, "st_ino", 0))
                    except OSError as exc:
                        raise FileActivityCollectorError("file identity unavailable") from exc
                identity = f"{device}:{inode}"
                if identity == "0:0":
                    identity = "path:" + normalized.casefold()
                result[identity] = {
                    "identity": identity,
                    "path": normalized,
                    "size": int(getattr(info, "st_size", 0)),
                    "mtime_ns": int(getattr(info, "st_mtime_ns", 0)),
                    "ctime_ns": int(getattr(info, "st_ctime_ns", 0)),
                }
                if len(result) > self.max_files:
                    raise FileActivityCollectorError("file scan limit exceeded")
        return result

    @staticmethod
    def _extension(path: str) -> str:
        return Path(path).suffix.casefold()

    def _event(self, operation: str, current: dict[str, Any], *, old_path: str | None = None) -> dict[str, Any]:
        timestamp = time.time()
        path = current["path"]
        extension_changed = old_path is not None and self._extension(old_path) != self._extension(path)
        data = {
            "operation": operation,
            "path": path,
            "endpoint_id": self.endpoint_id,
            "tenant_id": self.tenant_id,
            "host_id": self.host_id or self.endpoint_id,
            "sensor_id": "FileActivityCollector",
            "approved_root": str(self.approved_root),
            "lab_canary": True,
        }
        if old_path is not None:
            data.update({"old_path": old_path, "new_path": path, "extension_changed": extension_changed})
        return {
            "event_type": "FILE_ACTIVITY",
            "event_id": "file-" + uuid.uuid4().hex,
            "timestamp": timestamp,
            "source": "FileActivityCollector",
            "data": data,
        }

    def _accept_event(self, event: dict[str, Any]) -> bool:
        now = time.time()
        while self._event_times and now - self._event_times[0] > self.EVENT_WINDOW_SECONDS:
            self._event_times.popleft()
        signature = hashlib.sha256(
            "|".join(
                str(event.get("data", {}).get(key, ""))
                for key in ("operation", "path", "old_path", "new_path")
            ).encode("utf-8")
        ).hexdigest()
        prior = self._dedupe.get(signature)
        if prior is not None and now - prior <= 1.0:
            self._events_dropped += 1
            return False
        if len(self._event_times) >= self.max_events_per_window:
            self._events_dropped += 1
            self._last_error = "EVENT_RATE_LIMIT"
            return False
        self._dedupe[signature] = now
        self._event_times.append(now)
        self._events_emitted += 1
        self._last_event_at = now
        return True

    def poll(self) -> list[dict[str, Any]]:
        """Return bounded normalized activity; failures return no events."""
        self._polls += 1
        self._last_poll_at = time.time()
        try:
            current = self._scan()
            if not self._initialized:
                self._snapshot = current
                self._initialized = True
                self._last_error = None
                return []
            events: list[dict[str, Any]] = []
            previous = self._snapshot
            previous_by_path = {row["path"]: row for row in previous.values()}
            current_ids = set(current)
            for identity, old in previous.items():
                if identity not in current_ids:
                    event = self._event("DELETE", old)
                    if self._accept_event(event):
                        events.append(event)
            for identity, row in current.items():
                old = previous.get(identity)
                if old is None:
                    old_at_path = previous_by_path.get(row["path"])
                    event = self._event("CREATE", row)
                    if old_at_path is not None and old_at_path.get("identity") != identity:
                        event = self._event("CREATE", row)
                    if self._accept_event(event):
                        events.append(event)
                elif old["path"] != row["path"]:
                    event = self._event("RENAME", row, old_path=old["path"])
                    if self._accept_event(event):
                        events.append(event)
                elif (old["size"], old["mtime_ns"], old["ctime_ns"]) != (row["size"], row["mtime_ns"], row["ctime_ns"]):
                    event = self._event("MODIFY", row)
                    if self._accept_event(event):
                        events.append(event)
                if len(events) >= self.max_events_per_poll:
                    self._events_dropped += max(0, len(current) - len(events))
                    break
            self._snapshot = current
            self._last_error = None if not self._last_error or self._last_error == "EVENT_RATE_LIMIT" else self._last_error
            return events[: self.max_events_per_poll]
        except (FileActivityCollectorError, OSError, RuntimeError, ValueError):
            self._failures += 1
            self._last_error = "COLLECTOR_FAIL_CLOSED"
            return []

    def health_check(self) -> dict[str, Any]:
        status = "HEALTHY" if self._failures == 0 else "DEGRADED"
        return {
            "component": "FileActivityCollector",
            "version": self.VERSION,
            "status": status,
            "approved_root": str(self.approved_root),
            "marker_required": self.require_marker,
            "initialized": self._initialized,
            "polls": self._polls,
            "events_emitted": self._events_emitted,
            "events_dropped": self._events_dropped,
            "failures": self._failures,
            "last_error": self._last_error,
            "last_poll_at": self._last_poll_at,
            "last_event_at": self._last_event_at,
            "bounded": True,
            "authority": "NONE",
            "authorization": "NOT_GRANTED",
            "response_actions": False,
            "network_access": False,
        }


__all__ = [
    "DEFAULT_LAB_FILE_ACTIVITY_ROOT",
    "FILE_ACTIVITY_CANARY_MARKER",
    "FILE_ACTIVITY_CANARY_MARKER_FILENAME",
    "QUARANTINE_CANARY_MARKER",
    "QUARANTINE_CANARY_MARKER_FILENAME",
    "LAB_AUTO_QUARANTINE_ENABLE_MARKER",
    "LAB_AUTO_QUARANTINE_ENABLE_MARKER_FILENAME",
    "LAB_FILE_ACTIVITY_ENABLE_MARKER",
    "LAB_FILE_ACTIVITY_ENABLE_MARKER_FILENAME",
    "FileActivityCollector",
    "FileActivityCollectorError",
]
