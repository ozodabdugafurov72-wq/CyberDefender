from __future__ import annotations

"""Bounded, append-preserving storage for Quarantine v2 canary records."""

import hashlib
import hmac
import json
import os
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from agent.quarantine.vault import SecureQuarantineVault


class QuarantineVaultError(Exception):
    """Fail-closed vault/storage error."""


class BoundedQuarantineVault:
    VERSION = "2.0"
    SCHEMA = "cd.quarantine.record.v2"
    MAX_RECORDS_DEFAULT = 64
    MAX_BYTES_DEFAULT = 16 * 1024 * 1024
    MAX_TARGET_BYTES_DEFAULT = 2 * 1024 * 1024

    def __init__(self, vault_dir: str | Path, *, max_records: int = MAX_RECORDS_DEFAULT,
                 max_bytes: int = MAX_BYTES_DEFAULT, max_target_bytes: int = MAX_TARGET_BYTES_DEFAULT) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be >= 1")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError("max_bytes must be >= 1")
        if isinstance(max_target_bytes, bool) or not isinstance(max_target_bytes, int) or max_target_bytes < 1:
            raise ValueError("max_target_bytes must be >= 1")
        self.root = Path(vault_dir).expanduser().resolve()
        self.records_dir = self.root / "v2-records"
        self.objects_dir = self.root / "v2-objects"
        self.receipts_dir = self.root / "v2-receipts"
        self.evidence_vault = SecureQuarantineVault(self.root / "v2-evidence")
        for path in (self.records_dir, self.objects_dir, self.receipts_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.max_target_bytes = max_target_bytes
        self._lock = RLock()
        self._integrity_failures = 0
        self._failed = 0

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _sha256(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            except OSError:
                pass

    def _record_payload(self, record: dict[str, Any]) -> bytes:
        unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
        return self._canonical(unsigned)

    def _write_record(self, record: dict[str, Any]) -> dict[str, Any]:
        unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
        record = dict(unsigned, record_sha256=self._sha256(self._canonical(unsigned)))
        self._atomic_write(self.records_dir / f"{record['quarantine_id']}.json", self._canonical(record))
        return record

    def _read_record(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or value.get("schema") != self.SCHEMA:
                raise ValueError("invalid schema")
            supplied = value.get("record_sha256")
            expected = self._sha256(self._record_payload(value))
            if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
                raise ValueError("record integrity failure")
            return value
        except Exception as exc:
            self._integrity_failures += 1
            raise QuarantineVaultError("record integrity failure") from exc

    def _records(self) -> list[dict[str, Any]]:
        paths = sorted(self.records_dir.glob("*.json"))
        if len(paths) > self.max_records:
            raise QuarantineVaultError("bounded record scan exceeded")
        total = 0
        result = []
        for path in paths:
            total += path.stat().st_size
            if total > self.max_bytes:
                raise QuarantineVaultError("bounded record scan bytes exceeded")
            result.append(self._read_record(path))
        return result

    @staticmethod
    def _has_reparse_component(path: Path) -> bool:
        """Reject symlink/reparse components; uncertainty is fail-closed."""
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
            raise QuarantineVaultError("path identity unavailable")

    @classmethod
    def file_identity(cls, path: Path) -> dict[str, int]:
        if cls._has_reparse_component(path):
            raise QuarantineVaultError("reparse or symlink path denied")
        try:
            info = os.stat(path, follow_symlinks=False)
            return {
                "st_dev": int(getattr(info, "st_dev", 0)),
                "st_ino": int(getattr(info, "st_ino", 0)),
                "st_size": int(info.st_size),
                "st_mtime_ns": int(getattr(info, "st_mtime_ns", 0)),
                "st_ctime_ns": int(getattr(info, "st_ctime_ns", 0)),
                "st_mode": int(info.st_mode),
                "st_file_attributes": int(getattr(info, "st_file_attributes", 0)),
            }
        except (OSError, TypeError, ValueError) as exc:
            raise QuarantineVaultError("file identity unavailable") from exc

    @classmethod
    def source_identity_matches(cls, record: dict[str, Any], source: Path) -> bool:
        try:
            if cls._has_reparse_component(source):
                return False
            expected = record.get("source_identity")
            current = cls.file_identity(source)
            return isinstance(expected, dict) and all(current.get(key) == expected.get(key) for key in current)
        except (QuarantineVaultError, OSError, RuntimeError, ValueError):
            return False

    def find_by_idempotency(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            matches = [row for row in self._records() if row.get("idempotency_key") == key]
            if len(matches) > 1:
                raise QuarantineVaultError("duplicate idempotency records")
            return matches[0] if matches else None

    def ensure_capacity(self, additional_bytes: int) -> None:
        if isinstance(additional_bytes, bool) or not isinstance(additional_bytes, int) or additional_bytes < 0:
            raise QuarantineVaultError("invalid capacity request")
        with self._lock:
            records = self._records()
            if len(records) >= self.max_records:
                raise QuarantineVaultError("quarantine record capacity exhausted")
            used = self._bounded_used_bytes()
            if used + additional_bytes > self.max_bytes:
                raise QuarantineVaultError("quarantine byte capacity exhausted")

    def _bounded_used_bytes(self) -> int:
        """Count storage with a fixed scan budget; never walk unbounded data."""
        total = 0
        scanned = 0
        for directory in (self.records_dir, self.objects_dir, self.receipts_dir, self.evidence_vault.vault_dir):
            for path in directory.rglob("*"):
                if not path.is_file():
                    continue
                scanned += 1
                if scanned > self.max_records * 8:
                    raise QuarantineVaultError("bounded storage scan exceeded")
                total += path.stat().st_size
                if total > self.max_bytes:
                    return total
        return total

    def capture_evidence(self, raw: bytes, *, reason: str, source: str, event_id: str) -> dict[str, Any]:
        if not isinstance(raw, bytes) or len(raw) > self.max_target_bytes:
            raise QuarantineVaultError("target exceeds bounded evidence size")
        try:
            metadata = self.evidence_vault.quarantine(raw, reason=reason, source=source, event_id=event_id)
            quarantine_id = metadata.get("quarantine_id")
            if not isinstance(quarantine_id, str) or not self.evidence_vault.verify_evidence(quarantine_id):
                raise QuarantineVaultError("evidence integrity verification failed")
            return metadata
        except QuarantineVaultError:
            raise
        except Exception as exc:
            raise QuarantineVaultError("evidence capture failed") from exc

    def begin(self, *, incident_id: str, requested_action: str, idempotency_key: str, original_path: str, approved_root: str,
              target_sha256: str, target_size: int, requester: str, evidence: dict[str, Any],
              source_identity: dict[str, int], evidence_ref: str, decision_digest: str,
              capability_id: str, scope_digest: str) -> dict[str, Any]:
        self.ensure_capacity(target_size)
        quarantine_id = "qv2-" + uuid.uuid4().hex
        object_path = self.objects_dir / quarantine_id / Path(original_path).name
        record = {
            "schema": self.SCHEMA, "version": self.VERSION, "quarantine_id": quarantine_id,
            "incident_id": incident_id, "requested_action": requested_action, "idempotency_key": idempotency_key,
            "original_path": original_path, "approved_root": approved_root,
            "target_sha256": target_sha256, "target_size": target_size, "requester": requester,
            "evidence_quarantine_id": evidence["quarantine_id"], "object_path": str(object_path),
            "source_identity": dict(source_identity),
            "evidence_ref": evidence_ref, "decision_digest": decision_digest,
            "capability_id": capability_id, "scope_digest": scope_digest,
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
            "state": "EVIDENCE_CAPTURED", "created_at": self._now(),
        }
        return self._write_record(record)

    def contain(self, record: dict[str, Any], source: Path) -> dict[str, Any]:
        destination = Path(record["object_path"])
        moved = False
        try:
            if not self.source_identity_matches(record, source):
                return self._write_pre_effect_failure(record, "SOURCE_CHANGED_BEFORE_CONTAINMENT")
            current_raw = source.read_bytes()
            if (len(current_raw) != record.get("target_size")
                    or self._sha256(current_raw) != record.get("target_sha256")):
                return self._write_pre_effect_failure(record, "SOURCE_CONTENT_CHANGED_BEFORE_CONTAINMENT")
            destination.parent.mkdir(parents=True, exist_ok=False)
            os.replace(str(source), str(destination))
            moved = True
            raw = destination.read_bytes()
            if self._sha256(raw) != record["target_sha256"] or len(raw) != record["target_size"]:
                return self._write_after_effect_failure(record, "CONTAINED_HASH_MISMATCH")
            receipt_unsigned = {
                "schema": "cd.quarantine.receipt.v2", "quarantine_id": record["quarantine_id"],
                "state": "QUARANTINED", "target_sha256": record["target_sha256"],
                "object_sha256": self._sha256(raw), "created_at": self._now(),
                "incident_id": record["incident_id"], "requested_action": record["requested_action"],
                "evidence_ref": record["evidence_ref"],
                "decision_digest": record["decision_digest"], "capability_id": record["capability_id"],
                "scope_digest": record["scope_digest"],
                "production_authorization": record["production_authorization"],
                "lab_authorization": record["lab_authorization"],
            }
            receipt = dict(receipt_unsigned, receipt_sha256=self._sha256(self._canonical(receipt_unsigned)))
            self._atomic_write(self.receipts_dir / f"{record['quarantine_id']}.json", self._canonical(receipt))
            return self._write_record(dict(record, state="QUARANTINED", contained_at=self._now(),
                                            receipt_sha256=receipt["receipt_sha256"], real_world_effect=True,
                                            recovery_required=False))
        except Exception:
            self._failed += 1
            if moved:
                return self._write_after_effect_failure(record, "CONTAINMENT_POST_EFFECT_FAILURE")
            return self._write_pre_effect_failure(record, "CONTAINMENT_FAILED")

    def _write_pre_effect_failure(self, record: dict[str, Any], code: str) -> dict[str, Any]:
        self._failed += 1
        failed = dict(record, state="FAILED", failure_code=code, real_world_effect=False, recovery_required=False)
        try:
            return self._write_record(failed)
        except Exception:
            return failed

    def _write_after_effect_failure(self, record: dict[str, Any], code: str) -> dict[str, Any]:
        self._failed += 1
        failed = dict(record, state="FAILED_AFTER_EFFECT", failure_code=code,
                      real_world_effect=True, recovery_required=True)
        try:
            return self._write_record(failed)
        except Exception:
            return dict(failed, state="UNKNOWN_AFTER_EFFECT", failure_code="PERSISTENCE_FAILURE_AFTER_EFFECT",
                        real_world_effect=True, recovery_required=True)

    def mark_after_effect_failure(self, quarantine_id: str, code: str) -> dict[str, Any]:
        try:
            record = self.get_verified_record(quarantine_id)
            if not isinstance(record, dict):
                return {
                    "quarantine_id": quarantine_id, "state": "UNKNOWN_AFTER_EFFECT",
                    "failure_code": "RECORD_UNAVAILABLE_AFTER_EFFECT",
                    "real_world_effect": True, "recovery_required": True,
                }
            return self._write_after_effect_failure(record, code)
        except Exception:
            return {
                "quarantine_id": quarantine_id, "state": "UNKNOWN_AFTER_EFFECT",
                "failure_code": "PERSISTENCE_FAILURE_AFTER_EFFECT",
                "real_world_effect": True, "recovery_required": True,
            }

    def get_verified_record(self, quarantine_id: str) -> dict[str, Any] | None:
        with self._lock:
            path = self.records_dir / f"{quarantine_id}.json"
            if not path.exists():
                return None
            return self._read_record(path)

    def verify_receipt(self, quarantine_id: str, record: dict[str, Any]) -> bool:
        try:
            value = json.loads((self.receipts_dir / f"{quarantine_id}.json").read_text(encoding="utf-8"))
            unsigned = {key: item for key, item in value.items() if key != "receipt_sha256"}
            linked = all(
                value.get(field) == record.get(field)
                for field in (
                    "incident_id", "requested_action", "evidence_ref", "decision_digest", "capability_id", "scope_digest",
                    "production_authorization", "lab_authorization",
                )
            )
            return (
                value.get("receipt_sha256") == self._sha256(self._canonical(unsigned))
                and value.get("state") == "QUARANTINED"
                and value.get("target_sha256") == record.get("target_sha256")
                and linked
            )
        except Exception:
            return False

    def verify_object(self, record: dict[str, Any]) -> bool:
        try:
            object_path = Path(record["object_path"])
            if object_path.parent.parent.resolve() != self.objects_dir.resolve():
                return False
            if self._has_reparse_component(object_path):
                return False
            raw = object_path.read_bytes()
            return len(raw) == record.get("target_size") and self._sha256(raw) == record.get("target_sha256")
        except Exception:
            return False

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            try:
                records = self._records()
                count = len(records)
                review_states = {"FAILED", "FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT", "EVIDENCE_CAPTURED"}
                review_required = sum(1 for row in records if row.get("state") in review_states)
            except (QuarantineVaultError, OSError):
                count = -1
                review_required = -1
            return {
                "component": "BoundedQuarantineVault", "version": self.VERSION,
                "status": "HEALTHY" if self._integrity_failures == 0 and self._failed == 0 and count >= 0 and review_required == 0 else "DEGRADED",
                "records": count, "review_required": review_required,
                "integrity_failures": self._integrity_failures, "failed": self._failed,
                "max_records": self.max_records, "max_bytes": self.max_bytes,
                "fail_closed": True, "secrets_exported": False,
            }
