from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from agent.event import SecurityEvent
from agent.quarantine.vault import SecureQuarantineVault


class SpoolError(Exception):
    """
    DurableEventSpool storage-layer exception.

    DurableEventPipeline bilan storage contract
    compatibility uchun ishlatiladi.
    """

    pass


@dataclass(frozen=True)
class DurableSpoolPolicy:
    """Bounded production spool policy.

    The protected reserve is available only to HIGH/CRITICAL events.
    Existing pending evidence is never evicted to make room.
    """

    max_pending_events: int = 8192
    max_pending_bytes: int = 32 * 1024 * 1024
    max_event_bytes: int = 256 * 1024
    protected_reserve_events: int = 1024
    protected_reserve_bytes: int = 4 * 1024 * 1024
    max_recovery_batch: int = 256
    max_recovery_scan_bytes: int = 32 * 1024 * 1024
    compaction_terminal_ops: int = 128
    compaction_min_dead_bytes: int = 1024 * 1024
    max_terminal_records: int = 16384
    max_terminal_state_bytes: int = 4 * 1024 * 1024


@dataclass(frozen=True)
class DurableSpoolAdmissionResult:
    accepted: bool
    durable: bool
    reason: str
    event_id: str | None
    priority: str
    protected: bool
    pending_events: int
    pending_bytes: int
    physical_bytes: int
    capacity_status: str


class DurableEventSpool:
    """
    CyberDefender Durable Event Spool.

    P11.16 Secure Quarantine Integration + P0.3A Durable Resource Contract.

    Resource-safety additions in v2.3:
    - bounded pending event count and bytes
    - bounded per-event serialized size
    - HIGH/CRITICAL protected capacity reserve
    - no eviction of already-pending evidence
    - bounded recovery batches
    - bounded recovery scan surface
    - crash-safe terminal-record compaction
    - bounded O(1) active pending membership/accounting index

    Security lifecycle:

        PENDING
           |
           +----------------------+
           |                      |
           v                      v
         VALID                  INVALID
           |                      |
           v                      v
       CALLBACK              QUARANTINE
           |                      |
           v                      v
      EXACT TRUE              TERMINAL
           |                  QUARANTINED
           v
         ACKED
           |
        TERMINAL


    Invariants:

    - Invalid events are never delivered.
    - Invalid events are never ACKed.
    - Callback failure keeps event PENDING.
    - ACK requires exact True.
    - ACKED cannot become QUARANTINED.
    - QUARANTINED cannot become PENDING.
    - External Vault quarantine is recognized.
    - Vault state is reconciled with Spool state.
    - Valid events are isolated from invalid events.
    - Corrupted records do not block valid records.
    - Duplicate quarantine is idempotent.
    - Pending state survives restart.
    - ACK state survives restart.
    - QUARANTINE state survives restart.
    """

    VERSION = "2.3"

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        spool_dir: Optional[str | Path] = None,
        quarantine_vault: Optional[
            SecureQuarantineVault
        ] = None,
        policy: Optional[DurableSpoolPolicy] = None,
    ):
        if spool_dir is None:
            spool_dir = (
                Path("data")
                / "spool"
            )

        self.spool_dir = Path(
            spool_dir
        )

        self.spool_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.pending_path = (
            self.spool_dir
            / "pending.jsonl"
        )

        self.acked_path = (
            self.spool_dir
            / "acked.jsonl"
        )

        self.quarantined_path = (
            self.spool_dir
            / "quarantined.jsonl"
        )

        # ACK snapshot is the authoritative terminal-state record.
        # acked.jsonl is retained for backward compatibility/audit.
        self.acked_state_path = (
            self.spool_dir
            / "acked_state.json"
        )

        self.quarantine_vault = (
            quarantine_vault
        )

        self.policy = policy or DurableSpoolPolicy()
        self._validate_policy(self.policy)
        self._lock = RLock()
        # Scheduling hint only: never persisted and never admission evidence.
        # Restart begins a new sweep; every recovered record is reverified.
        self._recovery_offset = 0
        self._recovery_identity = None
        self._recovery_discard_line = False
        self.recovery_scan = {"scanned": 0, "bytes": 0, "wrapped": False}

        # Resource-safety telemetry.  These counters are deliberately
        # bounded scalar state; no per-event telemetry list is retained.
        self._capacity_rejected = 0
        self._oversized_rejected = 0
        self._protected_admitted = 0
        self._compactions = 0
        self._compaction_failures = 0
        self._scan_limit_exceeded = 0
        self._terminal_ops_since_compaction = 0
        self._last_admission_reason: str | None = None
        self._last_capacity_status = "NORMAL"
        self._terminal_state_safe = True
        self._terminal_compactions = 0
        self._terminal_compaction_failures = 0

        # -----------------------------------------------------
        # TERMINAL STATE
        # -----------------------------------------------------

        self._acked: set[str] = set()
        self._acked_order: list[str] = []

        self._quarantined: dict[
            str,
            dict[str, Any],
        ] = {}
        self._quarantine_order: list[str] = []

        # -----------------------------------------------------
        # STATS
        # -----------------------------------------------------

        self._spooled = 0
        self._ack_operations = 0
        self._replayed = 0
        self._duplicates = 0
        self._corrupted = 0
        self._integrity_rejected = 0
        self._callback_failed = 0

        # Crash-safe ACK transaction telemetry.
        self._ack_intents = 0
        self._ack_commits = 0
        self._ack_recoveries = 0
        self._ack_failures = 0
        self._ack_rejected = 0

        self._quarantine_operations = 0
        self._quarantine_duplicates = 0
        self._quarantine_failed = 0

        # Health contract telemetry.
        self._health_checks = 0
        self._health_failures = 0

        # Bounded active-pending index.  Only event ids and serialized sizes
        # are retained, capped by max_pending_events.  This keeps normal
        # admission O(1) instead of rescanning pending.jsonl for every event.
        self._pending_sizes: dict[str, int] = {}
        self._pending_active_bytes = 0
        self._pending_index_ready = False

        self._load_state()
        self._rebuild_pending_index()

        # Initial Vault reconciliation is limited to bounded pending ids.
        self._sync_vault_quarantines()

    @staticmethod
    def _validate_policy(policy: DurableSpoolPolicy) -> None:
        integer_fields = (
            "max_pending_events",
            "max_pending_bytes",
            "max_event_bytes",
            "max_recovery_batch",
            "max_recovery_scan_bytes",
            "compaction_terminal_ops",
            "compaction_min_dead_bytes",
            "max_terminal_records",
            "max_terminal_state_bytes",
        )
        for name in integer_fields:
            value = getattr(policy, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

        reserve_fields = (
            "protected_reserve_events",
            "protected_reserve_bytes",
        )
        for name in reserve_fields:
            value = getattr(policy, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

        if policy.protected_reserve_events >= policy.max_pending_events:
            raise ValueError("protected_reserve_events must be smaller than max_pending_events")
        if policy.protected_reserve_bytes >= policy.max_pending_bytes:
            raise ValueError("protected_reserve_bytes must be smaller than max_pending_bytes")
        if policy.max_event_bytes > policy.max_pending_bytes:
            raise ValueError("max_event_bytes cannot exceed max_pending_bytes")
        if policy.max_recovery_batch > policy.max_pending_events:
            raise ValueError("max_recovery_batch cannot exceed max_pending_events")
        if policy.max_recovery_scan_bytes < policy.max_pending_bytes:
            raise ValueError("max_recovery_scan_bytes cannot be smaller than max_pending_bytes")

    # =========================================================
    # CANONICAL JSON
    # =========================================================

    @staticmethod
    def _canonical_json(
        data: dict[str, Any],
    ) -> bytes:

        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
        ).encode("utf-8")

    # =========================================================
    # ATOMIC WRITE
    # =========================================================

    @staticmethod
    def _atomic_write(
        path: Path,
        content: bytes,
    ) -> None:

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, temp_path = tempfile.mkstemp(
            prefix=path.name + ".",
            suffix=".tmp",
            dir=str(path.parent),
        )

        try:

            with os.fdopen(
                fd,
                "wb",
            ) as handle:

                handle.write(
                    content
                )

                handle.flush()

                os.fsync(
                    handle.fileno()
                )

            os.replace(
                temp_path,
                path,
            )

        finally:

            try:

                if os.path.exists(
                    temp_path
                ):
                    os.unlink(
                        temp_path
                    )

            except OSError:
                pass

    # =========================================================
    # JSONL APPEND
    # =========================================================

    def _append_jsonl(
        self,
        path: Path,
        record: dict[str, Any],
    ) -> None:

        payload = (
            self._canonical_json(
                record
            )
            + b"\n"
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with path.open(
            "ab"
        ) as handle:

            handle.write(
                payload
            )

            handle.flush()

            os.fsync(
                handle.fileno()
            )

    # =========================================================
    # JSONL LOAD
    # =========================================================

    def _load_jsonl(
        self,
        path: Path,
        *,
        max_bytes: int | None = None,
        max_records: int | None = None,
    ) -> list[dict[str, Any]]:
        """Read JSONL with explicit memory/scan bounds.

        A file that exceeds max_bytes is not silently treated as complete.
        The caller can observe the condition through health/stats and
        admission fails closed when the authoritative pending file cannot
        be scanned safely.
        """

        if not path.exists():
            return []

        byte_limit = (
            max(1, int(max_bytes))
            if max_bytes is not None
            else max(1, int(self.policy.max_recovery_scan_bytes))
        )
        record_limit = (
            max(1, int(max_records))
            if max_records is not None
            else max(1, int(self.policy.max_pending_events + self.policy.max_terminal_records))
        )

        result: list[dict[str, Any]] = []
        scanned = 0

        try:
            physical = path.stat().st_size
            if physical > byte_limit:
                self._scan_limit_exceeded += 1
                return []

            with path.open("rb") as handle:
                for raw_line in handle:
                    scanned += len(raw_line)
                    if scanned > byte_limit:
                        self._scan_limit_exceeded += 1
                        return []

                    line = raw_line.strip()
                    if not line:
                        continue

                    if len(result) >= record_limit:
                        self._scan_limit_exceeded += 1
                        return []

                    try:
                        record = json.loads(line.decode("utf-8"))
                        if not isinstance(record, dict):
                            self._corrupted += 1
                            continue
                        result.append(record)
                    except Exception:
                        self._corrupted += 1

        except Exception:
            self._corrupted += 1

        return result

    @staticmethod
    def _normalize_priority(event: SecurityEvent) -> str:
        severity = str(getattr(event, "severity", "MEDIUM")).strip().upper()
        if severity == "CRITICAL":
            return "CRITICAL"
        if severity == "HIGH":
            return "HIGH"
        if severity in {"MEDIUM", "WARNING"}:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _is_protected_priority(priority: str) -> bool:
        return priority in {"HIGH", "CRITICAL"}

    def _physical_pending_bytes(self) -> int:
        try:
            return int(self.pending_path.stat().st_size) if self.pending_path.exists() else 0
        except OSError:
            return 0

    def _record_payload(self, event: SecurityEvent, admission: dict | None = None) -> tuple[dict[str, Any], bytes]:
        record = {
            "event_id": event.event_id,
            "event": event.to_dict(),
        }
        if admission is not None:
            record["admission"] = dict(admission)
        payload = self._canonical_json(record) + b"\n"
        return record, payload

    def _pending_metrics(self) -> tuple[int, int]:
        if self._pending_index_ready:
            return len(self._pending_sizes), int(self._pending_active_bytes)

        if self._rebuild_pending_index():
            return len(self._pending_sizes), int(self._pending_active_bytes)

        # Unknown is not silently interpreted as empty.  Returning values at
        # the hard limit forces capacity admission to fail closed.
        return (
            max(1, int(self.policy.max_pending_events)),
            max(1, int(self.policy.max_pending_bytes)),
        )

    def _capacity_status(self, pending_events: int, pending_bytes: int) -> str:
        max_events = max(1, int(self.policy.max_pending_events))
        max_bytes = max(1, int(self.policy.max_pending_bytes))
        if pending_events >= max_events or pending_bytes >= max_bytes:
            return "SATURATED"
        if (pending_events / max_events) >= 0.80 or (pending_bytes / max_bytes) >= 0.80:
            return "PRESSURE"
        return "NORMAL"

    def _general_capacity_allows(self, pending_events: int, pending_bytes: int, event_bytes: int) -> bool:
        general_events = max(0, int(self.policy.max_pending_events) - int(self.policy.protected_reserve_events))
        general_bytes = max(0, int(self.policy.max_pending_bytes) - int(self.policy.protected_reserve_bytes))
        return (
            pending_events + 1 <= general_events
            and pending_bytes + event_bytes <= general_bytes
        )

    def _total_capacity_allows(self, pending_events: int, pending_bytes: int, event_bytes: int) -> bool:
        return (
            pending_events + 1 <= max(1, int(self.policy.max_pending_events))
            and pending_bytes + event_bytes <= max(1, int(self.policy.max_pending_bytes))
        )

    def _terminal_file_safe(self, path: Path) -> bool:
        try:
            return (
                not path.exists()
                or path.stat().st_size <= max(1, int(self.policy.max_terminal_state_bytes))
            )
        except OSError:
            return False

    def _rewrite_jsonl(self, path: Path, records: list[dict[str, Any]]) -> None:
        content = b"".join(self._canonical_json(record) + b"\n" for record in records)
        if len(content) > max(1, int(self.policy.max_terminal_state_bytes)):
            raise SpoolError(f"terminal journal exceeds bound: {path.name}")
        self._atomic_write(path, content)

    @staticmethod
    def _bounded_unique_order(order: list[str], valid: set[str], limit: int) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for event_id in order:
            if event_id in valid and event_id not in seen:
                seen.add(event_id)
                result.append(event_id)
        # Snapshot-only ids may not exist in the compatibility journal.
        for event_id in sorted(valid):
            if event_id not in seen:
                seen.add(event_id)
                result.append(event_id)
        return result[-max(1, int(limit)):]

    def _compact_terminal_state(self) -> bool:
        """Bound local terminal tombstones after pending compaction.

        This method is called only after pending.jsonl has been rewritten to
        active records.  Therefore pruning old tombstones cannot resurrect
        a record from the pending file.  External quarantine evidence remains
        authoritative in SecureQuarantineVault when configured.
        """
        try:
            limit = max(1, int(self.policy.max_terminal_records))

            ack_order = self._bounded_unique_order(self._acked_order, self._acked, limit)
            ack_set = set(ack_order)
            self._persist_ack_state(ack_set)
            self._rewrite_jsonl(
                self.acked_path,
                [{"event_id": event_id} for event_id in ack_order],
            )

            q_order = self._bounded_unique_order(
                self._quarantine_order, set(self._quarantined), limit
            )
            q_records = [
                self._quarantined[event_id]
                for event_id in q_order
                if event_id in self._quarantined
            ]
            self._rewrite_jsonl(self.quarantined_path, q_records)

            self._acked = ack_set
            self._acked_order = ack_order
            self._quarantined = {
                record["event_id"]: record
                for record in q_records
                if isinstance(record.get("event_id"), str)
            }
            self._quarantine_order = [
                event_id for event_id in q_order if event_id in self._quarantined
            ]
            self._terminal_state_safe = True
            self._terminal_compactions += 1
            return True
        except Exception:
            self._terminal_state_safe = False
            self._terminal_compaction_failures += 1
            return False

    def _should_compact(self) -> bool:
        if (
            len(self._acked) > max(1, int(self.policy.max_terminal_records))
            or len(self._quarantined) > max(1, int(self.policy.max_terminal_records))
        ):
            return True
        physical = self._physical_pending_bytes()
        if physical <= 0:
            return False
        if physical > max(1, int(self.policy.max_pending_bytes)):
            return True
        if self._terminal_ops_since_compaction >= max(1, int(self.policy.compaction_terminal_ops)):
            return True
        try:
            _, active_bytes = self._pending_metrics()
        except Exception:
            return False
        dead = max(0, physical - active_bytes)
        return dead >= max(1, int(self.policy.compaction_min_dead_bytes))

    def compact(self) -> bool:
        """Crash-safe pending-file compaction.

        Terminal state is committed before this method is called.  The
        rewrite only removes records already hidden by ACK/quarantine, so a
        compaction failure can leave extra bytes but cannot resurrect or lose
        an event.
        """
        with self._lock:
            try:
                physical = self._physical_pending_bytes()
                if physical > max(1, int(self.policy.max_recovery_scan_bytes)):
                    self._scan_limit_exceeded += 1
                    self._compaction_failures += 1
                    return False

                records = self._read_pending_records()
                content = b"".join(self._canonical_json(record) + b"\n" for record in records)
                if len(records) > max(1, int(self.policy.max_pending_events)):
                    self._compaction_failures += 1
                    return False
                if len(content) > max(1, int(self.policy.max_pending_bytes)):
                    self._compaction_failures += 1
                    return False

                self._atomic_write(self.pending_path, content)
                self._terminal_ops_since_compaction = 0
                self._compactions += 1
                # Rebuild from the compacted file to prove accounting matches
                # durable bytes rather than trusting pre-rewrite memory.
                if not self._rebuild_pending_index():
                    self._compaction_failures += 1
                    return False
                if not self._compact_terminal_state():
                    self._compaction_failures += 1
                    return False
                return True
            except Exception:
                self._compaction_failures += 1
                return False

    def _maybe_compact(self) -> None:
        try:
            if self._should_compact():
                self.compact()
        except Exception:
            self._compaction_failures += 1

    def _rebuild_pending_index(self) -> bool:
        """Rebuild bounded O(1) pending membership/accounting state."""
        with self._lock:
            physical = self._physical_pending_bytes()
            if physical > max(1, int(self.policy.max_recovery_scan_bytes)):
                self._pending_sizes = {}
                self._pending_active_bytes = 0
                self._pending_index_ready = False
                self._scan_limit_exceeded += 1
                return False

            records = self._read_pending_records()
            if len(records) > max(1, int(self.policy.max_pending_events)):
                self._pending_sizes = {}
                self._pending_active_bytes = 0
                self._pending_index_ready = False
                self._scan_limit_exceeded += 1
                return False

            sizes: dict[str, int] = {}
            total = 0
            for record in records:
                event_id = record.get("event_id")
                if not isinstance(event_id, str):
                    continue
                event_id = event_id.strip()
                if not event_id or event_id in sizes:
                    continue
                size = len(self._canonical_json(record)) + 1
                sizes[event_id] = size
                total += size

            if total > max(1, int(self.policy.max_pending_bytes)):
                self._pending_sizes = {}
                self._pending_active_bytes = 0
                self._pending_index_ready = False
                self._scan_limit_exceeded += 1
                return False

            self._pending_sizes = sizes
            self._pending_active_bytes = total
            self._pending_index_ready = True
            return True

    def _mark_pending_terminal(self, event_id: str) -> None:
        size = self._pending_sizes.pop(event_id, None)
        if size is not None:
            self._pending_active_bytes = max(0, self._pending_active_bytes - int(size))

    # =========================================================
    # ACK STATE
    # =========================================================

    def _read_ack_ids(
        self,
    ) -> set[str]:
        # The atomic snapshot is authoritative, but it must itself remain
        # within the bounded terminal-state contract.
        snapshot_ids: set[str] = set()

        if self.acked_state_path.exists():
            try:
                if not self._terminal_file_safe(self.acked_state_path):
                    self._terminal_state_safe = False
                    return set()
                raw = self.acked_state_path.read_bytes()
                state = json.loads(raw.decode("utf-8"))
                if isinstance(state, dict):
                    ids = state.get("acked_ids", [])
                    if isinstance(ids, list):
                        if len(ids) > max(1, int(self.policy.max_terminal_records)):
                            self._terminal_state_safe = False
                            return set()
                        for event_id in ids:
                            if isinstance(event_id, str):
                                event_id = event_id.strip()
                                if event_id:
                                    snapshot_ids.add(event_id)
                        self._acked_order = sorted(snapshot_ids)
                        return snapshot_ids
            except Exception:
                self._corrupted += 1
                self._terminal_state_safe = False
                return set()

        if not self._terminal_file_safe(self.acked_path):
            self._terminal_state_safe = False
            return set()

        result: set[str] = set()
        order: list[str] = []
        for record in self._load_jsonl(
            self.acked_path,
            max_bytes=self.policy.max_terminal_state_bytes,
            max_records=self.policy.max_terminal_records,
        ):
            event_id = record.get("event_id")
            if not isinstance(event_id, str):
                continue
            event_id = event_id.strip()
            if event_id and event_id not in result:
                result.add(event_id)
                order.append(event_id)
        self._acked_order = order
        return result

    def _persist_ack_state(
        self,
        acked_ids: set[str],
    ) -> None:
        """
        Atomically persist the complete ACK terminal-state set.

        Ordering:
            1. Build canonical snapshot.
            2. Write temp file.
            3. flush + fsync file.
            4. os.replace() atomic rename.
            5. fsync parent directory where supported.

        A process crash before os.replace() leaves the previous valid
        snapshot intact. A crash after os.replace() leaves the new snapshot.
        """

        normalized = sorted(
            event_id.strip()
            for event_id in acked_ids
            if isinstance(event_id, str)
            and event_id.strip()
        )
        if len(normalized) > max(1, int(self.policy.max_terminal_records)) + 1:
            raise SpoolError("ACK terminal state exceeds bounded record limit")

        state = {
            "schema_version": "1",
            "status": "ACKED",
            "acked_ids": normalized,
        }

        payload = self._canonical_json(state)
        if len(payload) > max(1, int(self.policy.max_terminal_state_bytes)):
            raise SpoolError("ACK terminal state exceeds bounded byte limit")
        self._atomic_write(
            self.acked_state_path,
            payload,
        )

        # Best-effort directory durability.
        try:
            flags = getattr(os, "O_DIRECTORY", 0)

            fd = os.open(
                str(self.spool_dir),
                os.O_RDONLY | flags,
            )

            try:
                os.fsync(fd)
            finally:
                os.close(fd)

        except (OSError, ValueError):
            pass

    def _recover_ack_state(self) -> None:
        """
        Reconcile ACK snapshot with the legacy ACK journal.

        This is deliberately conservative: existing ACKs are retained,
        never guessed, and never inferred from pending delivery.
        """

        snapshot_ids = self._read_ack_ids()

        if not self._terminal_state_safe:
            self._acked = set()
            self._acked_order = []
            return

        if snapshot_ids:
            self._acked = snapshot_ids
            if not self._acked_order:
                self._acked_order = sorted(snapshot_ids)
            return

        # Empty snapshot is valid and authoritative if it exists.
        if self.acked_state_path.exists():
            self._acked = set()
            self._acked_order = []
            return

        legacy_ids = set()

        for record in self._load_jsonl(
            self.acked_path
        ):
            event_id = record.get("event_id")

            if isinstance(event_id, str):
                event_id = event_id.strip()
                if event_id:
                    legacy_ids.add(event_id)

        self._acked = legacy_ids
        if not self._acked_order:
            self._acked_order = sorted(legacy_ids)

        if legacy_ids:
            try:
                self._persist_ack_state(
                    legacy_ids
                )
                self._ack_recoveries += 1
            except Exception:
                # Legacy state remains usable in-memory.
                pass

    # =========================================================
    # QUARANTINE STATE
    # =========================================================

    def _read_quarantined_records(
        self,
    ) -> dict[
        str,
        dict[str, Any],
    ]:

        result: dict[
            str,
            dict[str, Any],
        ] = {}

        if not self._terminal_file_safe(self.quarantined_path):
            self._terminal_state_safe = False
            return {}

        order: list[str] = []
        for record in self._load_jsonl(
            self.quarantined_path,
            max_bytes=self.policy.max_terminal_state_bytes,
            max_records=self.policy.max_terminal_records,
        ):

            event_id = record.get(
                "event_id"
            )

            if not isinstance(
                event_id,
                str,
            ):
                continue

            event_id = event_id.strip()

            if not event_id:
                continue

            if (
                record.get(
                    "status"
                )
                != "QUARANTINED"
            ):
                continue

            if event_id not in result:
                order.append(event_id)
            result[event_id] = record

        self._quarantine_order = order
        return result

    # =========================================================
    # LOAD STATE
    # =========================================================

    def _load_state(
        self,
    ) -> None:

        self._recover_ack_state()

        self._quarantined = (
            self._read_quarantined_records()
        )

    # =========================================================
    # FIND VAULT RECORD
    # =========================================================

    def _find_vault_record(
        self,
        event_id: str,
    ) -> Optional[dict[str, Any]]:
        """Bounded-memory lookup of one quarantine record by event id."""
        if self.quarantine_vault is None:
            return None

        records_dir = getattr(self.quarantine_vault, "records_dir", None)
        if isinstance(records_dir, Path):
            scanned = 0
            try:
                for path in records_dir.glob("*.json"):
                    scanned += 1
                    if scanned > max(1, int(self.policy.max_terminal_records)):
                        # We cannot prove absence within the configured bound.
                        self._terminal_state_safe = False
                        return None
                    try:
                        if path.stat().st_size > max(1, int(self.policy.max_terminal_state_bytes)):
                            self._terminal_state_safe = False
                            return None
                        metadata = json.loads(path.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if not isinstance(metadata, dict):
                        continue
                    if metadata.get("status") != "QUARANTINED":
                        continue
                    candidate_id = metadata.get("event_id")
                    if isinstance(candidate_id, str) and candidate_id.strip() == event_id:
                        return metadata
                return None
            except Exception:
                return None

        # Compatibility fallback for alternate vault implementations.
        try:
            records = self.quarantine_vault.list_records()
        except Exception:
            return None
        if not isinstance(records, list):
            return None
        if len(records) > max(1, int(self.policy.max_terminal_records)):
            self._terminal_state_safe = False
            return None
        for metadata in records:
            if not isinstance(metadata, dict) or metadata.get("status") != "QUARANTINED":
                continue
            candidate_id = metadata.get("event_id")
            if isinstance(candidate_id, str) and candidate_id.strip() == event_id:
                return metadata
        return None

    # =========================================================
    # PERSIST QUARANTINE STATE
    # =========================================================

    def _persist_quarantine_state(
        self,
        event_id: str,
        metadata: dict[str, Any],
    ) -> bool:

        # -----------------------------------------------------
        # Security rule:
        #
        # ACKED is stronger terminal state.
        # -----------------------------------------------------

        if event_id in self._acked:
            return False

        # -----------------------------------------------------
        # Already synchronized.
        # -----------------------------------------------------

        if (
            event_id
            in self._quarantined
        ):
            return True

        quarantine_id = metadata.get(
            "quarantine_id"
        )

        # -----------------------------------------------------
        # Some Vault implementations may return incomplete
        # metadata. Generate deterministic local terminal
        # record instead of failing the security transition.
        # -----------------------------------------------------

        if not isinstance(
            quarantine_id,
            str,
        ):

            quarantine_id = (
                "external-"
                + event_id
            )

        terminal_record = {
            "event_id":
                event_id,

            "quarantine_id":
                quarantine_id,

            "status":
                "QUARANTINED",

            "failure_type":
                metadata.get(
                    "failure_type",
                    "UNKNOWN",
                ),

            "reason":
                metadata.get(
                    "reason",
                    "UNKNOWN",
                ),

            "raw_sha256":
                metadata.get(
                    "raw_sha256"
                ),

            "source":
                metadata.get(
                    "source",
                    "SecureQuarantineVault",
                ),
        }

        # -----------------------------------------------------
        # Persist terminal state.
        # -----------------------------------------------------

        try:

            self._append_jsonl(
                self.quarantined_path,
                terminal_record,
            )

        except Exception:

            return False

        self._quarantined[
            event_id
        ] = terminal_record
        if event_id not in self._quarantine_order:
            self._quarantine_order.append(event_id)
        self._mark_pending_terminal(event_id)
        self._terminal_ops_since_compaction += 1

        return True

    # =========================================================
    # FORCE RECONCILIATION
    # =========================================================

    def _reconcile_event_with_vault(
        self,
        event_id: str,
    ) -> bool:
        """
        Authoritative Vault reconciliation.

        Returns True when the event is known to be
        QUARANTINED.

        This method is deliberately stronger than the
        previous implementation.

        External state:

            Vault(event_id) = QUARANTINED

        automatically means:

            Spool(event_id) = QUARANTINED

        """

        if event_id in self._acked:
            return False

        if (
            event_id
            in self._quarantined
        ):
            return True

        metadata = (
            self._find_vault_record(
                event_id
            )
        )

        if metadata is None:
            return False

        # -----------------------------------------------------
        # Vault is authoritative for quarantine.
        # -----------------------------------------------------

        persisted = (
            self._persist_quarantine_state(
                event_id,
                metadata,
            )
        )

        if persisted:
            return True

        # -----------------------------------------------------
        # Extremely important fallback:
        #
        # If Vault already says QUARANTINED but local
        # terminal-state persistence fails, we still keep the
        # event out of delivery for this process.
        #
        # Do NOT count this as successful durable persistence.
        # -----------------------------------------------------

        self._quarantined[
            event_id
        ] = {
            "event_id":
                event_id,

            "quarantine_id":
                metadata.get(
                    "quarantine_id"
                ),

            "status":
                "QUARANTINED",

            "failure_type":
                metadata.get(
                    "failure_type",
                    "UNKNOWN",
                ),

            "reason":
                metadata.get(
                    "reason",
                    "UNKNOWN",
                ),

            "raw_sha256":
                metadata.get(
                    "raw_sha256"
                ),

            "source":
                metadata.get(
                    "source",
                    "SecureQuarantineVault",
                ),
        }
        if event_id not in self._quarantine_order:
            self._quarantine_order.append(event_id)
        self._mark_pending_terminal(event_id)

        return True

    # =========================================================
    # SYNCHRONIZE ALL VAULT QUARANTINES
    # =========================================================

    def _sync_vault_quarantines(
        self,
    ) -> int:
        """Reconcile only bounded active pending ids with the external vault.

        The previous implementation materialized every vault record.  That
        made spool startup memory proportional to total quarantine history.
        v2.3 keeps this boundary proportional to max_pending_events.
        """
        if self.quarantine_vault is None or not self._pending_index_ready:
            return 0

        synchronized = 0
        for event_id in tuple(self._pending_sizes.keys()):
            if event_id in self._acked or event_id in self._quarantined:
                continue
            metadata = self._find_vault_record(event_id)
            if metadata is None:
                continue
            if self._persist_quarantine_state(event_id, metadata):
                synchronized += 1
            else:
                # Vault remains authoritative for this process even when the
                # compatibility journal cannot be updated.
                self._quarantined[event_id] = {
                    "event_id": event_id,
                    "quarantine_id": metadata.get("quarantine_id"),
                    "status": "QUARANTINED",
                    "failure_type": metadata.get("failure_type", "UNKNOWN"),
                    "reason": metadata.get("reason", "UNKNOWN"),
                    "raw_sha256": metadata.get("raw_sha256"),
                    "source": metadata.get("source", "SecureQuarantineVault"),
                }
                if event_id not in self._quarantine_order:
                    self._quarantine_order.append(event_id)
                self._mark_pending_terminal(event_id)
                synchronized += 1
        return synchronized

    # =========================================================
    # PENDING RAW RECORDS
    # =========================================================

    def _read_pending_records(
        self,
    ) -> list[dict[str, Any]]:

        records = self._load_jsonl(
            self.pending_path
        )

        result: list[
            dict[str, Any]
        ] = []

        seen: set[str] = set()

        for record in records:

            event_id = record.get(
                "event_id"
            )

            if not isinstance(
                event_id,
                str,
            ):

                self._corrupted += 1
                continue

            event_id = event_id.strip()

            if not event_id:

                self._corrupted += 1
                continue

            if event_id in seen:

                self._duplicates += 1
                continue

            seen.add(
                event_id
            )

            # -------------------------------------------------
            # ACKED terminal state.
            # -------------------------------------------------

            if event_id in self._acked:
                continue

            # -------------------------------------------------
            # QUARANTINE terminal state.
            # -------------------------------------------------

            if (
                event_id
                in self._quarantined
            ):
                continue

            result.append(
                record
            )

        return result

    # =========================================================
    # PUBLIC PENDING RECORDS
    # =========================================================

    def pending_records(
        self,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return a bounded pending snapshot.

        Compatibility callers that omit limit still receive every event that
        can exist under max_pending_events.  Recovery callers should prefer
        pending_batch().
        """
        self._sync_vault_quarantines()
        records = self._read_pending_records()
        if limit is None:
            limit = max(1, int(self.policy.max_pending_events))
        else:
            limit = max(0, min(int(limit), max(1, int(self.policy.max_pending_events))))
        return records[:limit]

    def pending_batch(
        self,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        batch_limit = (
            max(1, int(self.policy.max_recovery_batch))
            if limit is None
            else max(1, min(int(limit), int(self.policy.max_recovery_batch)))
        )
        return self.pending_records(limit=batch_limit)

    def iter_recovery_records(self, *, max_scan: int, max_bytes: int):
        """Incrementally read one bounded sweep, including invalid physical rows.

        The caller must close this iterator when it stops early. The cursor
        advances only over bytes actually inspected, so a publication limit
        cannot repeatedly skip the unused tail of a page. No evidence is
        rewritten. Oversized lines are drained in bounded chunks, never parsed
        as independent JSON suffixes. File replacement restarts the sweep.
        """
        scan_limit = max(0, min(int(max_scan), self.policy.max_recovery_batch))
        byte_limit = max(0, min(int(max_bytes), 1024 * 1024,
                                self.policy.max_recovery_scan_bytes))
        stats = {"scanned": 0, "bytes": 0, "wrapped": False}
        self.recovery_scan = stats
        if not scan_limit or not byte_limit:
            return
        with self._lock:
            if not self._terminal_state_safe:
                raise SpoolError("terminal state unavailable")
            if not self.pending_path.exists():
                stats["wrapped"] = True
                return
            handle = self.pending_path.open("rb")
            physical = os.fstat(handle.fileno())
            identity = (physical.st_dev, physical.st_ino)
            if identity != self._recovery_identity or physical.st_size < self._recovery_offset:
                self._recovery_offset = 0
                self._recovery_discard_line = False
            self._recovery_identity = identity
            handle.seek(self._recovery_offset)
        try:
            while stats["scanned"] < scan_limit and stats["bytes"] < byte_limit:
                with self._lock:
                    remaining = byte_limit - stats["bytes"]
                    raw = handle.readline(min(self.policy.max_event_bytes + 1, remaining))
                    stats["bytes"] += len(raw)
                    if not raw:
                        self._recovery_offset = 0
                        self._recovery_discard_line = False
                        stats["wrapped"] = True
                        break
                    # A partial read caused only by this call's byte budget
                    # is retried on the next call; do not reject a valid row.
                    if (not raw.endswith(b"\n") and len(raw) == remaining
                            and remaining <= self.policy.max_event_bytes
                            and not self._recovery_discard_line):
                        break
                    stats["scanned"] += 1
                    self._recovery_offset = handle.tell()
                    discard = self._recovery_discard_line
                    self._recovery_discard_line = not raw.endswith(b"\n")
                    record, reason = None, "INVALID_RECORD"
                    if not discard and len(raw) <= self.policy.max_event_bytes and raw.endswith(b"\n"):
                        try:
                            candidate = json.loads(raw)
                            event_id = candidate.get("event_id") if isinstance(candidate, dict) else None
                            if isinstance(event_id, str) and event_id.strip():
                                event_id = event_id.strip()
                                if event_id in self._acked or event_id in self._quarantined:
                                    reason = "TERMINAL"
                                elif self.quarantine_vault is not None and self._find_vault_record(event_id) is not None:
                                    reason = "TERMINAL"
                                else:
                                    if not self._terminal_state_safe:
                                        raise SpoolError("terminal state unavailable")
                                    record, reason = candidate, "PENDING"
                        except (ValueError, UnicodeError, RecursionError):
                            pass
                    if reason == "INVALID_RECORD":
                        self._corrupted += 1
                yield record, reason
        finally:
            handle.close()

    # =========================================================
    # PENDING IDS
    # =========================================================

    def _read_pending_ids(
        self,
    ) -> set[str]:
        if self._pending_index_ready:
            return set(self._pending_sizes)

        if self._rebuild_pending_index():
            return set(self._pending_sizes)

        return set()

    # =========================================================
    # EVENT ID
    # =========================================================

    @staticmethod
    def _event_id(
        event: SecurityEvent,
    ) -> Optional[str]:

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        if not isinstance(
            event_id,
            str,
        ):
            return None

        event_id = event_id.strip()

        if not event_id:
            return None

        return event_id

    # =========================================================
    # EVENT VALIDATION
    # =========================================================

    def _validate_event(
        self,
        event: SecurityEvent,
    ) -> bool:

        if not isinstance(
            event,
            SecurityEvent,
        ):
            return False

        event_id = self._event_id(
            event
        )

        if event_id is None:
            return False

        try:

            return bool(
                event.verify_integrity()
            )

        except Exception:

            return False

    # =========================================================
    # APPEND
    # =========================================================

    def append_with_result(
        self,
        event: SecurityEvent,
        *, admission: dict | None = None,
    ) -> DurableSpoolAdmissionResult:
        """Bounded durable admission with protected HIGH/CRITICAL reserve."""
        with self._lock:
            if not self._validate_event(event):
                self._last_admission_reason = "INVALID_EVENT"
                return DurableSpoolAdmissionResult(
                    False, False, "INVALID_EVENT", None, "LOW", False,
                    0, 0, self._physical_pending_bytes(), "DEGRADED",
                )

            event_id = self._event_id(event)
            if event_id is None:
                self._last_admission_reason = "INVALID_EVENT_ID"
                return DurableSpoolAdmissionResult(
                    False, False, "INVALID_EVENT_ID", None, "LOW", False,
                    0, 0, self._physical_pending_bytes(), "DEGRADED",
                )

            self._sync_vault_quarantines()

            if not self._terminal_state_safe:
                self._capacity_rejected += 1
                self._last_capacity_status = "TERMINAL_STATE_UNSAFE"
                self._last_admission_reason = "TERMINAL_STATE_UNSAFE"
                return DurableSpoolAdmissionResult(
                    False, False, "TERMINAL_STATE_UNSAFE", event_id,
                    self._normalize_priority(event),
                    self._is_protected_priority(self._normalize_priority(event)),
                    0, 0, self._physical_pending_bytes(), "TERMINAL_STATE_UNSAFE",
                )

            if self._reconcile_event_with_vault(event_id):
                self._duplicates += 1
                self._last_admission_reason = "DUPLICATE_QUARANTINED"
                pending_events, pending_bytes = self._pending_metrics()
                return DurableSpoolAdmissionResult(
                    False, False, "DUPLICATE_QUARANTINED", event_id,
                    self._normalize_priority(event), True,
                    pending_events, pending_bytes, self._physical_pending_bytes(),
                    self._capacity_status(pending_events, pending_bytes),
                )

            if event_id in self._acked or event_id in self._quarantined:
                self._duplicates += 1
                self._last_admission_reason = "DUPLICATE_TERMINAL"
                pending_events, pending_bytes = self._pending_metrics()
                return DurableSpoolAdmissionResult(
                    False, False, "DUPLICATE_TERMINAL", event_id,
                    self._normalize_priority(event),
                    self._is_protected_priority(self._normalize_priority(event)),
                    pending_events, pending_bytes, self._physical_pending_bytes(),
                    self._capacity_status(pending_events, pending_bytes),
                )

            if event_id in self._read_pending_ids():
                self._duplicates += 1
                self._last_admission_reason = "DUPLICATE_PENDING"
                pending_events, pending_bytes = self._pending_metrics()
                return DurableSpoolAdmissionResult(
                    False, False, "DUPLICATE_PENDING", event_id,
                    self._normalize_priority(event),
                    self._is_protected_priority(self._normalize_priority(event)),
                    pending_events, pending_bytes, self._physical_pending_bytes(),
                    self._capacity_status(pending_events, pending_bytes),
                )

            record, payload = self._record_payload(event, admission)
            priority = self._normalize_priority(event)
            protected = self._is_protected_priority(priority)

            if len(payload) > max(1, int(self.policy.max_event_bytes)):
                self._oversized_rejected += 1
                self._last_admission_reason = "EVENT_TOO_LARGE"
                pending_events, pending_bytes = self._pending_metrics()
                return DurableSpoolAdmissionResult(
                    False, False, "EVENT_TOO_LARGE", event_id, priority, protected,
                    pending_events, pending_bytes, self._physical_pending_bytes(),
                    self._capacity_status(pending_events, pending_bytes),
                )

            # Reclaim only already-terminal bytes.  Pending evidence is never
            # evicted to make room for a newer event.
            if self._physical_pending_bytes() + len(payload) > max(1, int(self.policy.max_pending_bytes)):
                self.compact()

            physical = self._physical_pending_bytes()
            if physical > max(1, int(self.policy.max_recovery_scan_bytes)):
                self._scan_limit_exceeded += 1
                self._capacity_rejected += 1
                self._last_capacity_status = "RECOVERY_LIMIT_EXCEEDED"
                self._last_admission_reason = "RECOVERY_SCAN_LIMIT_EXCEEDED"
                return DurableSpoolAdmissionResult(
                    False, False, "RECOVERY_SCAN_LIMIT_EXCEEDED", event_id, priority, protected,
                    0, 0, physical, "RECOVERY_LIMIT_EXCEEDED",
                )

            pending_events, pending_bytes = self._pending_metrics()
            allow = (
                self._total_capacity_allows(pending_events, pending_bytes, len(payload))
                if protected
                else self._general_capacity_allows(pending_events, pending_bytes, len(payload))
            )

            if not allow:
                self._capacity_rejected += 1
                status = self._capacity_status(pending_events, pending_bytes)
                if protected:
                    status = "SATURATED"
                    reason = "TOTAL_CAPACITY_EXHAUSTED"
                else:
                    status = "PRESSURE" if self._total_capacity_allows(pending_events, pending_bytes, len(payload)) else "SATURATED"
                    reason = "PROTECTED_RESERVE" if status == "PRESSURE" else "TOTAL_CAPACITY_EXHAUSTED"
                self._last_capacity_status = status
                self._last_admission_reason = reason
                return DurableSpoolAdmissionResult(
                    False, False, reason, event_id, priority, protected,
                    pending_events, pending_bytes, physical, status,
                )

            try:
                self._append_jsonl(self.pending_path, record)
                self._pending_sizes[event_id] = len(payload)
                self._pending_active_bytes += len(payload)
                self._pending_index_ready = True
                self._spooled += 1
                if protected:
                    self._protected_admitted += 1
                pending_events += 1
                pending_bytes += len(payload)
                status = self._capacity_status(pending_events, pending_bytes)
                self._last_capacity_status = status
                self._last_admission_reason = "ADMITTED"
                return DurableSpoolAdmissionResult(
                    True, True, "ADMITTED", event_id, priority, protected,
                    pending_events, pending_bytes, self._physical_pending_bytes(), status,
                )
            except Exception:
                self._last_admission_reason = "DURABLE_WRITE_FAILED"
                return DurableSpoolAdmissionResult(
                    False, False, "DURABLE_WRITE_FAILED", event_id, priority, protected,
                    pending_events, pending_bytes, self._physical_pending_bytes(),
                    self._capacity_status(pending_events, pending_bytes),
                )

    def append(
        self,
        event: SecurityEvent,
    ) -> bool:
        return self.append_with_result(event).accepted

    # =========================================================
    # PENDING EVENTS
    # =========================================================

    def pending_events(
        self,
    ) -> list[SecurityEvent]:

        result: list[
            SecurityEvent
        ] = []

        for record in (
            self.pending_records()
        ):

            event_data = record.get(
                "event"
            )

            if not isinstance(
                event_data,
                dict,
            ):
                continue

            try:

                event = (
                    SecurityEvent.from_dict(
                        event_data
                    )
                )

                if (
                    event.event_id
                    != record.get(
                        "event_id"
                    )
                ):
                    continue

                if not event.verify_integrity():
                    continue

                result.append(
                    event
                )

            except Exception:

                continue

        return result

    # =========================================================
    # ACK
    # =========================================================

    def ack(
        self,
        event_id: str,
    ) -> bool:

        if not isinstance(
            event_id,
            str,
        ):
            self._ack_rejected += 1
            return False

        event_id = event_id.strip()

        if not event_id:
            self._ack_rejected += 1
            return False

        # Terminal-state precedence.
        if event_id in self._acked:
            self._ack_rejected += 1
            return False

        if event_id in self._quarantined:
            self._ack_rejected += 1
            return False

        pending_ids = self._read_pending_ids()

        if event_id not in pending_ids:
            self._ack_rejected += 1
            return False

        # ---------------------------------------------------------
        # ACK TRANSACTION
        #
        # The snapshot is the authoritative terminal state.
        # We never remove the pending record physically here.
        # PENDING visibility is derived from ACK/QUARANTINE state.
        #
        # Therefore:
        #
        #   crash before snapshot replace -> still PENDING
        #   crash after snapshot replace  -> ACKED
        #
        # There is no destructive "remove pending then write ACK" gap.
        # ---------------------------------------------------------

        self._ack_intents += 1

        next_acked = set(self._acked)
        next_acked.add(event_id)

        try:
            # Atomic durable commit.
            self._persist_ack_state(
                next_acked
            )

        except Exception:
            self._ack_failures += 1
            return False

        # Only after durable snapshot commit do we update memory.
        self._acked = next_acked
        if event_id not in self._acked_order:
            self._acked_order.append(event_id)
        self._mark_pending_terminal(event_id)

        # Compatibility/audit journal. Failure here must NOT roll back the
        # already committed terminal state.
        try:
            self._append_jsonl(
                self.acked_path,
                {
                    "event_id": event_id,
                },
            )
        except Exception:
            # The atomic snapshot remains authoritative.
            pass

        self._ack_operations += 1
        self._ack_commits += 1
        self._terminal_ops_since_compaction += 1
        self._maybe_compact()

        return True

    # =========================================================
    # QUARANTINE RECORD
    # =========================================================

    def _quarantine_record(
        self,
        record: dict[str, Any],
        reason: str,
        failure_type: str,
    ) -> bool:

        event_id = record.get(
            "event_id"
        )

        if not isinstance(
            event_id,
            str,
        ):

            self._corrupted += 1
            return False

        event_id = event_id.strip()

        if not event_id:
            return False

        if event_id in self._acked:
            return False

        # -----------------------------------------------------
        # First check existing Vault state.
        # -----------------------------------------------------

        if (
            self._reconcile_event_with_vault(
                event_id
            )
        ):

            self._quarantine_duplicates += 1

            return True

        # -----------------------------------------------------
        # Vault unavailable.
        # -----------------------------------------------------

        if (
            self.quarantine_vault
            is None
        ):

            self._quarantine_failed += 1

            return False

        # -----------------------------------------------------
        # Exact raw evidence.
        # -----------------------------------------------------

        try:

            raw_record = (
                self._canonical_json(
                    record
                )
            )

        except Exception:

            self._quarantine_failed += 1

            return False

        # -----------------------------------------------------
        # Create Vault evidence.
        # -----------------------------------------------------

        try:

            metadata = (
                self.quarantine_vault.quarantine(
                    raw_record=raw_record,
                    reason=reason,
                    source="DurableEventSpool",
                    event_id=event_id,
                    failure_type=failure_type,
                )
            )

        except Exception:

            # -------------------------------------------------
            # Race-safe authoritative re-check.
            # -------------------------------------------------

            if (
                self._reconcile_event_with_vault(
                    event_id
                )
            ):

                self._quarantine_duplicates += 1

                return True

            self._quarantine_failed += 1

            return False

        if not isinstance(
            metadata,
            dict,
        ):

            # -------------------------------------------------
            # Re-check Vault in case quarantine succeeded but
            # response was malformed.
            # -------------------------------------------------

            if (
                self._reconcile_event_with_vault(
                    event_id
                )
            ):

                return True

            self._quarantine_failed += 1

            return False

        # -----------------------------------------------------
        # Persist terminal state.
        # -----------------------------------------------------

        if (
            self._persist_quarantine_state(
                event_id,
                metadata,
            )
        ):

            self._quarantine_operations += 1

            return True

        # -----------------------------------------------------
        # Vault is authoritative.
        # -----------------------------------------------------

        if (
            self._reconcile_event_with_vault(
                event_id
            )
        ):

            return True

        self._quarantine_failed += 1

        return False

    # =========================================================
    # REPLAY
    # =========================================================

    def replay(
        self,
        callback,
    ) -> int:

        if not callable(
            callback
        ):

            raise TypeError(
                "callback callable bo'lishi kerak"
            )

        # -----------------------------------------------------
        # External quarantine reconciliation.
        # -----------------------------------------------------

        self._sync_vault_quarantines()

        records = self.pending_batch()

        processed = 0

        for record in records:

            event_id = record.get(
                "event_id"
            )

            event_data = record.get(
                "event"
            )

            # -------------------------------------------------
            # STRUCTURE
            # -------------------------------------------------

            if not isinstance(
                event_id,
                str,
            ):

                self._corrupted += 1

                self._quarantine_record(
                    record,
                    "INVALID_RECORD_STRUCTURE",
                    "INVALID_SPOOL_RECORD",
                )

                continue

            event_id = event_id.strip()

            if not event_id:

                self._corrupted += 1

                self._quarantine_record(
                    record,
                    "INVALID_RECORD_STRUCTURE",
                    "INVALID_SPOOL_RECORD",
                )

                continue

            # -------------------------------------------------
            # Last-minute Vault reconciliation.
            # -------------------------------------------------

            if (
                self._reconcile_event_with_vault(
                    event_id
                )
            ):

                continue

            # -------------------------------------------------
            # DESERIALIZATION
            # -------------------------------------------------

            if not isinstance(
                event_data,
                dict,
            ):

                self._integrity_rejected += 1

                self._quarantine_record(
                    record,
                    "SECURITY_EVENT_DESERIALIZATION_FAILURE",
                    "INVALID_SECURITY_EVENT",
                )

                continue

            try:

                event = (
                    SecurityEvent.from_dict(
                        event_data
                    )
                )

            except Exception:

                self._integrity_rejected += 1

                self._quarantine_record(
                    record,
                    "SECURITY_EVENT_DESERIALIZATION_FAILURE",
                    "INVALID_SECURITY_EVENT",
                )

                continue

            # -------------------------------------------------
            # ID BINDING
            # -------------------------------------------------

            if (
                event.event_id
                != event_id
            ):

                self._integrity_rejected += 1

                self._quarantine_record(
                    record,
                    "EVENT_ID_BINDING_FAILURE",
                    "EVENT_ID_MISMATCH",
                )

                continue

            # -------------------------------------------------
            # INTEGRITY
            # -------------------------------------------------

            try:

                valid = bool(
                    event.verify_integrity()
                )

            except Exception:

                valid = False

            if not valid:

                self._integrity_rejected += 1

                self._quarantine_record(
                    record,
                    "SECURITY_EVENT_INTEGRITY_FAILURE",
                    "INVALID_EVENT_INTEGRITY",
                )

                continue

            # -------------------------------------------------
            # CALLBACK
            # -------------------------------------------------

            try:

                result = callback(
                    event
                )

            except Exception:

                self._callback_failed += 1

                # PENDING remains.

                continue

            # -------------------------------------------------
            # EXACT TRUE ONLY
            # -------------------------------------------------

            if result is not True:

                self._callback_failed += 1

                continue

            # -------------------------------------------------
            # FINAL PRE-ACK SAFETY RECHECK
            #
            # The callback is outside the spool transaction boundary.
            # Before terminal ACK, reconcile external quarantine state and
            # verify that this event is still durably pending.
            #
            # This narrows the crash/race window. It cannot provide
            # exactly-once external side effects by itself; consumers must
            # use an idempotency key when side effects are non-repeatable.
            # -------------------------------------------------

            self._sync_vault_quarantines()

            if event_id in self._acked:
                continue

            if event_id in self._quarantined:
                continue

            if event_id not in self._read_pending_ids():
                self._ack_rejected += 1
                continue

            # -------------------------------------------------
            # ACK
            #
            # ACK is an atomic durable terminal-state transition.
            # Any failure MUST remain local to this event and MUST NOT
            # crash the recovery loop.
            # -------------------------------------------------

            try:
                acked = self.ack(
                    event_id
                )
            except Exception:
                self._ack_failures += 1
                continue

            if acked is True:
                processed += 1

        self._replayed += processed
        if processed:
            self._maybe_compact()

        return processed

    # =========================================================
    # COMPATIBILITY
    # =========================================================

    def replay_events(
        self,
        callback,
    ) -> int:

        try:
            return self.replay(
                callback
            )
        except Exception:
            # Security-first containment: unexpected recovery exceptions
            # do not propagate into the agent supervisor.
            self._callback_failed += 1
            return 0


    # =========================================================
    # HEALTH CONTRACT
    # =========================================================

    def health_check(self) -> dict[str, Any]:
        """
        DurableEventSpool health contract.

        Security-first qoidalar:
        - Health check storage holatini kuzatadi.
        - Event yaratmaydi.
        - Event o'chirmaydi.
        - ACK qilmaydi.
        - Quarantine transition qilmaydi.
        - Exceptionni tashqariga chiqarmaydi.
        """

        self._health_checks += 1

        try:
            # -------------------------------------------------
            # 01. Spool directory
            # -------------------------------------------------

            if not self.spool_dir.exists():
                raise SpoolError(
                    "Spool directory mavjud emas"
                )

            if not self.spool_dir.is_dir():
                raise SpoolError(
                    "Spool path directory emas"
                )

            # -------------------------------------------------
            # 02. Required storage paths
            # -------------------------------------------------

            required_paths = (
                self.pending_path,
                self.acked_path,
                self.quarantined_path,
                self.acked_state_path,
            )

            for path in required_paths:
                if path.exists() and not path.is_file():
                    raise SpoolError(
                        f"Storage path file emas: {path.name}"
                    )

            # -------------------------------------------------
            # 03. Existing files must be readable
            # -------------------------------------------------

            for path in required_paths:
                if path.exists():
                    with path.open("rb") as handle:
                        handle.read(1)

            # -------------------------------------------------
            # 04. Internal state sanity
            # -------------------------------------------------

            if not isinstance(
                self._acked,
                set,
            ):
                raise SpoolError(
                    "ACK state invalid"
                )

            if not isinstance(
                self._quarantined,
                dict,
            ):
                raise SpoolError(
                    "Quarantine state invalid"
                )

            # -------------------------------------------------
            # HEALTHY
            # -------------------------------------------------

            pending_events, pending_active_bytes = self._pending_metrics()
            physical_bytes = self._physical_pending_bytes()
            capacity_status = self._capacity_status(
                pending_events, pending_active_bytes
            )
            if physical_bytes > max(1, int(self.policy.max_recovery_scan_bytes)):
                capacity_status = "RECOVERY_LIMIT_EXCEEDED"
            if not self._terminal_state_safe:
                capacity_status = "TERMINAL_STATE_UNSAFE"
            status = "HEALTHY" if capacity_status in {"NORMAL", "PRESSURE"} else "DEGRADED"

            return {
                "component": "DurableEventSpool",
                "status": status,
                "version": self.VERSION,
                "bounded": True,
                "capacity_status": capacity_status,
                "spool_dir": str(self.spool_dir),
                "pending_path": self.pending_path.name,
                "acked_state_path": self.acked_state_path.name,
                "quarantined_path": self.quarantined_path.name,
                "pending": pending_events,
                "pending_active_bytes": pending_active_bytes,
                "pending_index_ready": self._pending_index_ready,
                "pending_physical_bytes": physical_bytes,
                "max_pending_events": int(self.policy.max_pending_events),
                "max_pending_bytes": int(self.policy.max_pending_bytes),
                "max_event_bytes": int(self.policy.max_event_bytes),
                "max_recovery_batch": int(self.policy.max_recovery_batch),
                "max_terminal_records": int(self.policy.max_terminal_records),
                "max_terminal_state_bytes": int(self.policy.max_terminal_state_bytes),
                "terminal_state_safe": self._terminal_state_safe,
                "protected_reserve_events": int(self.policy.protected_reserve_events),
                "protected_reserve_bytes": int(self.policy.protected_reserve_bytes),
                "acked": len(
                    self._acked
                ),
                "quarantined": len(
                    self._quarantined
                ),
                "health_checks": self._health_checks,
                "health_failures": self._health_failures,
                "last_error": None,
                "last_error_component": None,
            }

        except Exception as exc:
            self._health_failures += 1

            return {
                "component": "DurableEventSpool",
                "status": "DEGRADED",
                "version": self.VERSION,
                "bounded": True,
                "capacity_status": "DEGRADED",
                "spool_dir": str(self.spool_dir),
                "pending_path": self.pending_path.name,
                "acked_state_path": self.acked_state_path.name,
                "quarantined_path": self.quarantined_path.name,
                "pending": None,
                "terminal_state_safe": self._terminal_state_safe,
                "acked": None,
                "quarantined": None,
                "health_checks": self._health_checks,
                "health_failures": self._health_failures,
                "last_error": (
                    f"{type(exc).__name__}: {exc}"
                ),
                "last_error_component":
                    "DurableEventSpool",
            }
    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict[str, Any]:

        self._sync_vault_quarantines()

        return {
            "spool":
                "DurableEventSpool",

            "version":
                self.VERSION,

            "bounded": True,
            "capacity_status": self._last_capacity_status,
            "last_admission_reason": self._last_admission_reason,
            "max_pending_events": int(self.policy.max_pending_events),
            "max_pending_bytes": int(self.policy.max_pending_bytes),
            "max_event_bytes": int(self.policy.max_event_bytes),
            "max_recovery_batch": int(self.policy.max_recovery_batch),
            "max_terminal_records": int(self.policy.max_terminal_records),
            "max_terminal_state_bytes": int(self.policy.max_terminal_state_bytes),
            "terminal_state_safe": self._terminal_state_safe,
            "protected_reserve_events": int(self.policy.protected_reserve_events),
            "protected_reserve_bytes": int(self.policy.protected_reserve_bytes),
            "pending_physical_bytes": self._physical_pending_bytes(),

            "pending":
                self._pending_metrics()[0],

            "pending_active_bytes":
                self._pending_metrics()[1],

            "pending_index_ready":
                self._pending_index_ready,

            "acked":
                len(
                    self._acked
                ),

            "quarantined":
                len(
                    self._quarantined
                ),

            "appended":
                self._spooled,

            "ack_operations":
                self._ack_operations,

            "replayed":
                self._replayed,

            "duplicates":
                self._duplicates,

            "corrupted":
                self._corrupted,

            "integrity_rejected":
                self._integrity_rejected,

            "callback_failed":
                self._callback_failed,

            "ack_intents":
                self._ack_intents,

            "ack_commits":
                self._ack_commits,

            "ack_recoveries":
                self._ack_recoveries,

            "ack_failures":
                self._ack_failures,

            "ack_rejected":
                self._ack_rejected,

            "ack_state_file":
                str(self.acked_state_path.name),

            "quarantine_operations":
                self._quarantine_operations,

            "quarantine_duplicates":
                self._quarantine_duplicates,

            "quarantine_failed":
                self._quarantine_failed,

            "capacity_rejected": self._capacity_rejected,
            "oversized_rejected": self._oversized_rejected,
            "protected_admitted": self._protected_admitted,
            "compactions": self._compactions,
            "compaction_failures": self._compaction_failures,
            "scan_limit_exceeded": self._scan_limit_exceeded,
            "terminal_compactions": self._terminal_compactions,
            "terminal_compaction_failures": self._terminal_compaction_failures,
        }

