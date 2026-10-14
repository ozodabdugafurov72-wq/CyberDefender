"""Bounded, authenticated durable incident outbox storage.

This module is deliberately not wired into the runtime yet.  It owns only the
durable hand-off from correlation to a future incident dispatcher.  The journal
is append-only: state transitions add records and never delete evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable


class IncidentOutboxError(Exception):
    """Base error for fail-closed outbox operations."""


class IncidentOutboxConflict(IncidentOutboxError):
    """An idempotency key was reused with conflicting identity or payload."""


class IncidentOutboxIntegrityError(IncidentOutboxError):
    """The journal cannot be trusted."""


class IncidentOutboxCapacityError(IncidentOutboxError):
    """A bounded record or byte limit would be exceeded."""


@dataclass(frozen=True)
class IncidentOutboxPolicy:
    max_records: int = 4096
    max_bytes: int = 16 * 1024 * 1024
    max_record_bytes: int = 256 * 1024
    # Every identity/state lookup must be able to inspect the complete bounded
    # journal.  Smaller defaults make valid data above the scan threshold
    # permanently unreadable even though it is still below the storage limit.
    max_scan_records: int = 4096
    max_scan_bytes: int = 16 * 1024 * 1024
    lease_seconds: float = 30.0
    max_attempts: int = 8


class DurableIncidentOutbox:
    """Append-only authenticated incident outbox.

    A record is trusted only after its HMAC and payload digest verify.  The
    integrity key is supplied by a protected caller and is never persisted or
    returned in diagnostics.
    """

    SCHEMA_VERSION = "incident-outbox.v1"
    STATES = frozenset({"PENDING", "DISPATCHING", "DELIVERED", "REVIEW_REQUIRED", "CORRUPT"})
    _SAFE_ERROR = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")

    def __init__(
        self,
        outbox_dir: str | Path,
        integrity_key: bytes,
        *,
        policy: IncidentOutboxPolicy | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(integrity_key, (bytes, bytearray)) or len(integrity_key) < 16:
            raise ValueError("integrity_key must be at least 16 bytes")
        self.outbox_dir = Path(outbox_dir)
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        self.journal_path = self.outbox_dir / "incident_outbox.jsonl"
        self.policy = policy or IncidentOutboxPolicy()
        self._validate_policy(self.policy)
        self._key = bytes(integrity_key)
        self._clock = clock or __import__("time").time
        self._lock = RLock()
        self._corrupt_records = 0
        self._scan_limit_exceeded = 0
        self._integrity_rejected = 0
        self._last_error = None
        self._verified_cache: list[dict[str, Any]] | None = None
        self._verified_cache_signature: tuple[int, int, int, int] | None = None

    @staticmethod
    def _validate_policy(policy: IncidentOutboxPolicy) -> None:
        if not isinstance(policy.max_records, int) or policy.max_records <= 0:
            raise ValueError("max_records must be positive")
        if not isinstance(policy.max_bytes, int) or policy.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if not isinstance(policy.max_record_bytes, int) or policy.max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        if policy.max_record_bytes > policy.max_bytes:
            raise ValueError("max_record_bytes exceeds max_bytes")
        if not isinstance(policy.max_scan_records, int) or policy.max_scan_records <= 0:
            raise ValueError("max_scan_records must be positive")
        if not isinstance(policy.max_scan_bytes, int) or policy.max_scan_bytes <= 0:
            raise ValueError("max_scan_bytes must be positive")
        if policy.max_scan_bytes > policy.max_bytes:
            raise ValueError("max_scan_bytes exceeds max_bytes")
        if policy.lease_seconds <= 0 or policy.max_attempts <= 0:
            raise ValueError("lease_seconds and max_attempts must be positive")

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _required_text(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
        return value.strip()

    def _payload_hash(self, payload: Any) -> str:
        try:
            return hashlib.sha256(self._canonical(payload)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise ValueError("incident payload must be JSON serializable") from exc

    def _mac(self, record: dict[str, Any]) -> str:
        unsigned = dict(record)
        unsigned.pop("integrity", None)
        return hmac.new(self._key, self._canonical(unsigned), hashlib.sha256).hexdigest()

    def _signed(self, record: dict[str, Any]) -> dict[str, Any]:
        result = dict(record)
        result["integrity"] = {"algorithm": "HMAC-SHA256", "mac": self._mac(result)}
        return result

    def _verify(self, record: Any) -> dict[str, Any]:
        if not isinstance(record, dict) or record.get("schema_version") != self.SCHEMA_VERSION:
            raise IncidentOutboxIntegrityError("SCHEMA_INVALID")
        integrity = record.get("integrity")
        if not isinstance(integrity, dict) or integrity.get("algorithm") != "HMAC-SHA256":
            raise IncidentOutboxIntegrityError("INTEGRITY_METADATA_INVALID")
        supplied = integrity.get("mac")
        expected = self._mac(record)
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
            raise IncidentOutboxIntegrityError("INTEGRITY_MAC_INVALID")
        payload_hash = record.get("payload_sha256")
        if payload_hash != self._payload_hash(record.get("incident_payload")):
            raise IncidentOutboxIntegrityError("PAYLOAD_DIGEST_INVALID")
        if record.get("state") not in self.STATES:
            raise IncidentOutboxIntegrityError("STATE_INVALID")
        return dict(record)

    def _append(self, record: dict[str, Any]) -> None:
        encoded = self._canonical(record) + b"\n"
        if len(encoded) > self.policy.max_record_bytes:
            raise IncidentOutboxCapacityError("RECORD_LIMIT_EXCEEDED")
        with self._lock:
            signature_before = self._journal_signature()
            cache_current = (
                self._verified_cache is not None
                and self._verified_cache_signature == signature_before
            )
            current_bytes = self.journal_path.stat().st_size if self.journal_path.exists() else 0
            current_records = (
                len(self._verified_cache)
                if cache_current
                else self._physical_record_count()
            )
            if current_records >= self.policy.max_records or current_bytes + len(encoded) > self.policy.max_bytes:
                raise IncidentOutboxCapacityError("OUTBOX_CAPACITY_EXHAUSTED")
            self.outbox_dir.mkdir(parents=True, exist_ok=True)
            with self.journal_path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            if cache_current:
                self._verified_cache.append(dict(record))
                self._verified_cache_signature = self._journal_signature()
            else:
                self._verified_cache = None
                self._verified_cache_signature = None

    def _journal_signature(self) -> tuple[int, int, int, int] | None:
        if not self.journal_path.exists():
            return None
        stat_result = self.journal_path.stat()
        return (
            int(stat_result.st_dev),
            int(stat_result.st_ino),
            int(stat_result.st_size),
            int(stat_result.st_mtime_ns),
        )

    def _physical_record_count(self) -> int:
        if not self.journal_path.exists():
            return 0
        signature = self._journal_signature()
        if (
            self._verified_cache is not None
            and self._verified_cache_signature == signature
        ):
            return len(self._verified_cache)
        count = 0
        scanned_bytes = 0
        with self.journal_path.open("rb") as handle:
            for raw in handle:
                count += 1
                scanned_bytes += len(raw)
                if count > self.policy.max_records or scanned_bytes > self.policy.max_bytes:
                    return max(count, self.policy.max_records + 1)
        return count

    def _scan(self, *, max_records: int | None = None, max_bytes: int | None = None) -> list[dict[str, Any]]:
        record_limit = min(max_records or self.policy.max_scan_records, self.policy.max_scan_records)
        byte_limit = min(max_bytes or self.policy.max_scan_bytes, self.policy.max_scan_bytes)
        use_default_bounds = max_records is None and max_bytes is None
        signature = self._journal_signature()
        if use_default_bounds and self._verified_cache is not None and self._verified_cache_signature == signature:
            return list(self._verified_cache)
        if signature is None:
            if use_default_bounds:
                self._verified_cache = []
                self._verified_cache_signature = None
            return []
        if signature[2] > self.policy.max_bytes:
            self._scan_limit_exceeded += 1
            raise IncidentOutboxCapacityError("OUTBOX_BYTES_LIMIT_EXCEEDED")
        result: list[dict[str, Any]] = []
        scanned = 0
        scanned_bytes = 0
        corruption_before = self._corrupt_records
        integrity_before = self._integrity_rejected
        with self.journal_path.open("rb") as handle:
            for raw in handle:
                scanned += 1
                scanned_bytes += len(raw)
                if scanned > record_limit or scanned_bytes > byte_limit:
                    self._scan_limit_exceeded += 1
                    raise IncidentOutboxCapacityError("SCAN_LIMIT_EXCEEDED")
                if len(raw) > self.policy.max_record_bytes:
                    self._corrupt_records += 1
                    continue
                try:
                    result.append(self._verify(json.loads(raw.decode("utf-8"))))
                except (ValueError, UnicodeError, json.JSONDecodeError, IncidentOutboxIntegrityError):
                    self._corrupt_records += 1
                    self._integrity_rejected += 1
        if (
            use_default_bounds
            and self._corrupt_records == corruption_before
            and self._integrity_rejected == integrity_before
            and self._journal_signature() == signature
        ):
            self._verified_cache = list(result)
            self._verified_cache_signature = signature
        else:
            self._verified_cache = None
            self._verified_cache_signature = None
        return result

    @staticmethod
    def _identity(record: dict[str, Any]) -> tuple[str, str]:
        return str(record["tenant_id"]), str(record["idempotency_key"])

    def _latest(self, records: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        for record in records:
            key = self._identity(record)
            prior = latest.get(key)
            if prior is None or int(record.get("sequence", 0)) > int(prior.get("sequence", 0)):
                latest[key] = record
        return latest

    def put_if_absent(
        self,
        *,
        tenant_id: str,
        source_event_id: str,
        incident_id: str,
        idempotency_key: str,
        incident_payload: dict[str, Any],
        created_at: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        tenant_id = self._required_text(tenant_id, "tenant_id")
        source_event_id = self._required_text(source_event_id, "source_event_id")
        incident_id = self._required_text(incident_id, "incident_id")
        idempotency_key = self._required_text(idempotency_key, "idempotency_key")
        payload_hash = self._payload_hash(incident_payload)
        try:
            canonical_payload = json.loads(self._canonical(incident_payload).decode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError("incident payload must be JSON serializable") from exc
        with self._lock:
            prior_corrupt = self._corrupt_records
            prior_integrity_rejected = self._integrity_rejected
            records = self._scan()
            if (
                self._corrupt_records > prior_corrupt
                or self._integrity_rejected > prior_integrity_rejected
            ):
                raise IncidentOutboxIntegrityError("CORRUPT_RECORD_PRESENT")
            latest = self._latest(records)
            matching = [r for r in records if r.get("idempotency_key") == idempotency_key]
            for existing in matching:
                if existing.get("tenant_id") != tenant_id:
                    raise IncidentOutboxConflict("TENANT_CONFLICT")
            existing = latest.get((tenant_id, idempotency_key))
            if existing is not None:
                if (existing.get("source_event_id"), existing.get("incident_id"), existing.get("payload_sha256")) != (source_event_id, incident_id, payload_hash):
                    raise IncidentOutboxConflict("IDENTITY_OR_PAYLOAD_CONFLICT")
                if existing.get("state") == "CORRUPT":
                    raise IncidentOutboxIntegrityError("CORRUPT_RECORD")
                return dict(existing), True
            sequence = max((int(r.get("sequence", 0)) for r in records), default=0) + 1
            record = self._signed({
                "schema_version": self.SCHEMA_VERSION,
                "sequence": sequence,
                "outbox_id": f"OUTBOX-{uuid.uuid4().hex.upper()}",
                "tenant_id": tenant_id,
                "source_event_id": source_event_id,
                "incident_id": incident_id,
                "idempotency_key": idempotency_key,
                "incident_payload": canonical_payload,
                "payload_sha256": payload_hash,
                "created_at": created_at or self._now_iso(),
                "state": "PENDING",
                "attempt_count": 0,
                "last_attempt_at": None,
                "next_attempt_at": None,
                "lease_until": None,
                "last_error": None,
                "delivered_at": None,
            })
            self._append(record)
            return dict(record), False

    def scan(self, *, max_records: int | None = None, max_bytes: int | None = None) -> list[dict[str, Any]]:
        """Return only the latest trusted record for each tenant/idempotency key."""
        with self._lock:
            return list(self._latest(self._scan(max_records=max_records, max_bytes=max_bytes)).values())

    def claim_due(self, *, max_records: int | None = None, now: float | None = None) -> list[dict[str, Any]]:
        now = self._clock() if now is None else float(now)
        claimed: list[dict[str, Any]] = []
        with self._lock:
            records = self._scan(max_records=max_records)
            latest = self._latest(records)
            for current in list(latest.values()):
                if len(claimed) >= min(max_records or self.policy.max_scan_records, self.policy.max_scan_records):
                    break
                state = current.get("state")
                lease_until = current.get("lease_until")
                due = state == "PENDING" or (state == "DISPATCHING" and isinstance(lease_until, (int, float)) and lease_until <= now)
                if not due or (current.get("next_attempt_at") is not None and float(current["next_attempt_at"]) > now):
                    continue
                attempts = int(current.get("attempt_count", 0))
                if attempts >= self.policy.max_attempts:
                    updated = self._transition(current, "REVIEW_REQUIRED", now=now, error="ATTEMPT_LIMIT")
                    self._append(updated)
                    continue
                updated = self._transition(current, "DISPATCHING", now=now, attempt_count=attempts + 1, lease_until=now + self.policy.lease_seconds)
                self._append(updated)
                claimed.append(updated)
        return claimed

    def _transition(self, current: dict[str, Any], state: str, *, now: float, attempt_count: int | None = None, lease_until: float | None = None, error: str | None = None) -> dict[str, Any]:
        if state not in self.STATES or state == "CORRUPT":
            raise IncidentOutboxError("INVALID_TRANSITION")
        prior = current.get("state")
        allowed = {"PENDING": {"DISPATCHING", "REVIEW_REQUIRED"}, "DISPATCHING": {"DISPATCHING", "PENDING", "DELIVERED", "REVIEW_REQUIRED"}, "DELIVERED": set(), "REVIEW_REQUIRED": set(), "CORRUPT": set()}
        if state not in allowed.get(prior, set()):
            raise IncidentOutboxError("INVALID_TRANSITION")
        updated = dict(current)
        updated["sequence"] = int(current.get("sequence", 0)) + 1
        updated["state"] = state
        updated["attempt_count"] = int(current.get("attempt_count", 0) if attempt_count is None else attempt_count)
        updated["last_attempt_at"] = self._now_iso() if state == "DISPATCHING" else current.get("last_attempt_at")
        updated["lease_until"] = lease_until
        updated["next_attempt_at"] = None
        updated["last_error"] = error
        updated["delivered_at"] = self._now_iso() if state == "DELIVERED" else current.get("delivered_at")
        return self._signed(updated)

    def mark_delivered(self, outbox_id: str, *, now: float | None = None) -> dict[str, Any]:
        with self._lock:
            current = next((r for r in self.scan() if r.get("outbox_id") == outbox_id), None)
            if current is None:
                raise IncidentOutboxError("OUTBOX_RECORD_NOT_FOUND")
            updated = self._transition(current, "DELIVERED", now=self._clock() if now is None else now)
            self._append(updated)
            return updated

    def fail_dispatch(self, outbox_id: str, *, error: str, now: float | None = None) -> dict[str, Any]:
        error = self._required_text(error, "error")
        if not self._SAFE_ERROR.fullmatch(error):
            raise ValueError("error must be a sanitized error code")
        now = self._clock() if now is None else float(now)
        with self._lock:
            current = next((r for r in self.scan() if r.get("outbox_id") == outbox_id), None)
            if current is None:
                raise IncidentOutboxError("OUTBOX_RECORD_NOT_FOUND")
            attempts = int(current.get("attempt_count", 0))
            state = "REVIEW_REQUIRED" if attempts >= self.policy.max_attempts else "PENDING"
            updated = self._transition(current, state, now=now, lease_until=None, error=error)
            if state == "PENDING":
                updated["next_attempt_at"] = now + min(60.0, 5.0 * (2 ** max(0, attempts - 1)))
                updated = self._signed(updated)
            self._append(updated)
            return updated

    def health_snapshot(self) -> dict[str, Any]:
        with self._lock:
            physical_bytes = self.journal_path.stat().st_size if self.journal_path.exists() else 0
            return {
                "component": "DurableIncidentOutbox",
                "schema_version": self.SCHEMA_VERSION,
                "status": "DEGRADED" if self._corrupt_records or self._scan_limit_exceeded else "HEALTHY",
                "bounded": True,
                "physical_records": self._physical_record_count(),
                "physical_bytes": physical_bytes,
                "corrupt_records": self._corrupt_records,
                "integrity_rejected": self._integrity_rejected,
                "scan_limit_exceeded": self._scan_limit_exceeded,
                "last_error": self._last_error,
                "key_material_export": False,
            }
