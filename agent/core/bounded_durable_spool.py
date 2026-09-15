"""
CyberDefender Bounded Durable Spool v1.1

Corrected durability/accounting implementation.

Key fixes from v1.0:
    - accepted counter is rolled back when durability fails
    - eviction changes are rolled back if atomic rewrite fails
    - in-memory state never claims a successful durable write after failure
    - append is transactional from the caller's perspective

The spool remains bounded and priority-aware.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple


class SpoolPriority:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    ORDER = {
        LOW: 10,
        MEDIUM: 20,
        HIGH: 30,
        CRITICAL: 40,
    }


@dataclass(frozen=True)
class SpoolPolicy:
    max_events: int = 1000
    max_bytes: int = 10 * 1024 * 1024
    max_event_bytes: int = 64 * 1024
    protect_high: bool = True
    protect_critical: bool = True
    max_recovery_scan_bytes: int = 10 * 1024 * 1024


@dataclass(frozen=True)
class SpoolResult:
    accepted: bool
    event_id: str
    priority: str
    reason: str
    spool_events: int
    spool_bytes: int


class BoundedDurableSpool:
    VERSION = "1.1"

    def __init__(
        self,
        path: str | Path = "state/durable_spool.jsonl",
        policy: SpoolPolicy | None = None,
    ) -> None:
        self.policy = policy or SpoolPolicy()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._events: List[Dict[str, Any]] = []
        self._bytes = 0

        self._accepted = 0
        self._rejected = 0
        self._evicted = 0
        self._recovery_dropped = 0

        self._load()

    @staticmethod
    def _normalize_priority(priority: Any) -> str:
        value = str(priority).strip().upper()
        return value if value in SpoolPriority.ORDER else SpoolPriority.MEDIUM

    @staticmethod
    def _json_bytes(record: Dict[str, Any]) -> bytes:
        return (
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            ) + "\n"
        ).encode("utf-8")

    def _protected(self, priority: str) -> bool:
        return (
            (priority == SpoolPriority.CRITICAL and self.policy.protect_critical)
            or (priority == SpoolPriority.HIGH and self.policy.protect_high)
        )

    def _within_limits(self, event_bytes: int) -> bool:
        return (
            len(self._events) < max(1, int(self.policy.max_events))
            and self._bytes + event_bytes <= max(1, int(self.policy.max_bytes))
        )

    def _select_eviction_index(self) -> int | None:
        candidate: Tuple[int, int, float] | None = None

        for index, record in enumerate(self._events):
            priority = self._normalize_priority(record.get("priority"))

            if self._protected(priority):
                continue

            rank = SpoolPriority.ORDER[priority]

            try:
                timestamp = float(record.get("created_at", 0.0))
            except (TypeError, ValueError):
                timestamp = 0.0

            key = (rank, timestamp, index)

            if candidate is None or key < (
                candidate[1],
                candidate[2],
                candidate[0],
            ):
                candidate = (index, rank, timestamp)

        return None if candidate is None else candidate[0]

    def _write_records_atomic(
        self,
        records: List[Dict[str, Any]],
    ) -> None:
        directory = self.path.parent

        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=directory,
        )

        try:
            with os.fdopen(fd, "wb") as handle:
                for record in records:
                    handle.write(self._json_bytes(record))

                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temporary, self.path)

        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def _rewrite_atomic(self) -> None:
        self._write_records_atomic(self._events)

    def _load(self) -> None:
        if not self.path.exists():
            return

        try:
            if self.path.stat().st_size > max(
                1,
                int(self.policy.max_recovery_scan_bytes),
            ):
                self._recovery_dropped += 1
                return

            lines = self.path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()

        except (OSError, UnicodeError):
            self._recovery_dropped += 1
            return

        recovered: List[Dict[str, Any]] = []

        for line in lines:
            if not line.strip():
                continue

            try:
                record = json.loads(line)

                if not isinstance(record, dict):
                    raise ValueError("record is not an object")

                record["priority"] = self._normalize_priority(
                    record.get("priority")
                )

                if len(self._json_bytes(record)) > max(
                    1,
                    int(self.policy.max_event_bytes),
                ):
                    raise ValueError("event too large")

                recovered.append(record)

                if len(recovered) >= max(
                    1,
                    int(self.policy.max_events),
                ):
                    break

            except (json.JSONDecodeError, TypeError, ValueError):
                self._recovery_dropped += 1

        self._events = recovered
        self._bytes = sum(
            len(self._json_bytes(record))
            for record in self._events
        )

        while self._bytes > max(1, int(self.policy.max_bytes)):
            index = self._select_eviction_index()

            if index is None:
                break

            self._events.pop(index)
            self._bytes = sum(
                len(self._json_bytes(record))
                for record in self._events
            )

    def append(
        self,
        event: Dict[str, Any],
        priority: Any = SpoolPriority.MEDIUM,
    ) -> SpoolResult:
        if not isinstance(event, dict):
            self._rejected += 1
            return SpoolResult(
                False,
                "",
                self._normalize_priority(priority),
                "INVALID_EVENT",
                len(self._events),
                self._bytes,
            )

        normalized_priority = self._normalize_priority(priority)
        record = dict(event)

        event_id = str(
            record.get("event_id") or uuid.uuid4().hex
        )

        record["event_id"] = event_id
        record["priority"] = normalized_priority
        record.setdefault("created_at", time.time())

        event_size = len(self._json_bytes(record))

        with self._lock:
            if event_size > max(
                1,
                int(self.policy.max_event_bytes),
            ):
                self._rejected += 1
                return SpoolResult(
                    False,
                    event_id,
                    normalized_priority,
                    "EVENT_TOO_LARGE",
                    len(self._events),
                    self._bytes,
                )

            # Transaction candidate. Nothing is committed until the
            # complete replacement file has been durably written.
            candidate = list(self._events)
            evicted_count = 0

            while not (
                len(candidate) < max(1, int(self.policy.max_events))
                and sum(
                    len(self._json_bytes(item))
                    for item in candidate
                ) + event_size
                <= max(1, int(self.policy.max_bytes))
            ):
                victim_index = None
                victim_key = None

                for index, item in enumerate(candidate):
                    item_priority = self._normalize_priority(
                        item.get("priority")
                    )

                    if self._protected(item_priority):
                        continue

                    rank = SpoolPriority.ORDER[item_priority]

                    try:
                        timestamp = float(
                            item.get("created_at", 0.0)
                        )
                    except (TypeError, ValueError):
                        timestamp = 0.0

                    key = (rank, timestamp, index)

                    if victim_key is None or key < victim_key:
                        victim_key = key
                        victim_index = index

                if victim_index is None:
                    self._rejected += 1
                    reason = (
                        "PROTECTED_EVIDENCE_SATURATED"
                        if candidate
                        else "SPOOL_CAPACITY_EXCEEDED"
                    )
                    return SpoolResult(
                        False,
                        event_id,
                        normalized_priority,
                        reason,
                        len(self._events),
                        self._bytes,
                    )

                candidate.pop(victim_index)
                evicted_count += 1

            candidate.append(record)

            try:
                self._write_records_atomic(candidate)
            except OSError:
                # Absolutely no logical state is committed.
                self._rejected += 1
                return SpoolResult(
                    False,
                    event_id,
                    normalized_priority,
                    "DURABILITY_WRITE_FAILED",
                    len(self._events),
                    self._bytes,
                )

            # Commit only after successful atomic replacement.
            self._events = candidate
            self._bytes = sum(
                len(self._json_bytes(item))
                for item in self._events
            )
            self._accepted += 1
            self._evicted += evicted_count

            return SpoolResult(
                True,
                event_id,
                normalized_priority,
                "EVENT_SPOOLED",
                len(self._events),
                self._bytes,
            )

    def peek(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            count = max(0, min(int(limit), len(self._events), 1000))
            return [dict(item) for item in self._events[:count]]

    def pop(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            count = max(0, min(int(limit), len(self._events), 1000))

            if count == 0:
                return []

            candidate = self._events[count:]
            removed = self._events[:count]

            try:
                self._write_records_atomic(candidate)
            except OSError:
                return []

            self._events = candidate
            self._bytes = sum(
                len(self._json_bytes(item))
                for item in self._events
            )

            return [dict(item) for item in removed]

    def size(self) -> int:
        with self._lock:
            return len(self._events)

    def bytes_used(self) -> int:
        with self._lock:
            return self._bytes

    def health_check(self) -> Dict[str, Any]:
        return {
            "component": "BoundedDurableSpool",
            "status": "HEALTHY",
            "version": self.VERSION,
            "bounded_events": True,
            "bounded_bytes": True,
            "atomic_rewrite": True,
            "transactional_commit": True,
            "priority_protection": True,
            "path": str(self.path),
        }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "component": "BoundedDurableSpool",
                "version": self.VERSION,
                "events": len(self._events),
                "bytes": self._bytes,
                "max_events": int(self.policy.max_events),
                "max_bytes": int(self.policy.max_bytes),
                "max_event_bytes": int(self.policy.max_event_bytes),
                "accepted": self._accepted,
                "rejected": self._rejected,
                "evicted": self._evicted,
                "recovery_dropped": self._recovery_dropped,
                "protected_records": sum(
                    self._protected(
                        self._normalize_priority(
                            item.get("priority")
                        )
                    )
                    for item in self._events
                ),
            }
