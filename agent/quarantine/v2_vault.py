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
from agent.quarantine.crypto_vault import ImmutableFileCapture, VaultCipher, VaultCipherError


class QuarantineVaultError(Exception):
    """Fail-closed vault/storage error."""


class BoundedQuarantineVault:
    VERSION = "2.0"
    SCHEMA = "cd.quarantine.record.v2"
    MAX_RECORDS_DEFAULT = 64
    MAX_BYTES_DEFAULT = 16 * 1024 * 1024
    MAX_TARGET_BYTES_DEFAULT = 2 * 1024 * 1024
    ATTRIBUTION_FIELDS = (
        "event_id", "endpoint_id", "tenant_id", "detection_types", "detection_count",
        "detection_confidence", "risk_score", "risk_level", "policy_outcome",
        "policy_reason", "verifier_outcome",
    )

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
        self.restore_receipts_dir = self.root / "v2-restore-receipts"
        self.evidence_vault = SecureQuarantineVault(self.root / "v2-evidence")
        self.object_cipher = VaultCipher(self.root, key_name=".objects-aes256.key")
        for path in (self.records_dir, self.objects_dir, self.receipts_dir, self.restore_receipts_dir):
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
        for directory in (
            self.records_dir, self.objects_dir, self.receipts_dir,
            self.restore_receipts_dir, self.evidence_vault.vault_dir,
        ):
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

    def begin(self, *, incident_id: str, requested_action: str, idempotency_key: str,
              original_path: str, approved_root: str, target_sha256: str,
              target_size: int, requester: str, evidence: dict[str, Any],
              source_identity: dict[str, int], evidence_ref: str, decision_digest: str,
              capability_id: str, scope_digest: str, attribution: dict[str, Any] | None = None,
              production_authorization: str = "NOT_GRANTED",
              lab_authorization: str = "QUARANTINE_CAPABILITY_CONSUMED",
              authorization_policy_id: str | None = None) -> dict[str, Any]:
        if (production_authorization, lab_authorization) not in {
            ("NOT_GRANTED", "QUARANTINE_CAPABILITY_CONSUMED"),
            ("SIGNED_POLICY_CAPABILITY_CONSUMED", "NOT_APPLICABLE"),
        }:
            raise QuarantineVaultError("invalid quarantine authorization audit")
        if production_authorization == "SIGNED_POLICY_CAPABILITY_CONSUMED":
            if not isinstance(authorization_policy_id, str) or not authorization_policy_id:
                raise QuarantineVaultError("production authorization policy id required")
        self.ensure_capacity(target_size)
        quarantine_id = "qv2-" + uuid.uuid4().hex
        object_path = self.objects_dir / quarantine_id / (Path(original_path).name + ".cdq")
        record = {
            "schema": self.SCHEMA, "version": self.VERSION, "quarantine_id": quarantine_id,
            "incident_id": incident_id, "requested_action": requested_action, "idempotency_key": idempotency_key,
            "original_path": original_path, "approved_root": approved_root,
            "target_sha256": target_sha256, "target_size": target_size, "requester": requester,
            "evidence_quarantine_id": evidence["quarantine_id"], "object_path": str(object_path),
            "source_identity": dict(source_identity),
            "evidence_ref": evidence_ref, "decision_digest": decision_digest,
            "capability_id": capability_id, "scope_digest": scope_digest,
            "production_authorization": production_authorization,
            "lab_authorization": lab_authorization,
            "object_encryption": "AES-256-GCM",
            "state": "EVIDENCE_CAPTURED", "created_at": self._now(),
        }
        if authorization_policy_id is not None:
            record["authorization_policy_id"] = authorization_policy_id
        if isinstance(attribution, dict):
            for field in self.ATTRIBUTION_FIELDS:
                value = attribution.get(field)
                if value is None or value == []:
                    continue
                if field == "detection_types":
                    if not isinstance(value, (list, tuple)):
                        raise QuarantineVaultError("invalid detection_types attribution")
                    value = [str(item)[:128] for item in list(value)[:64] if isinstance(item, str) and item.strip()]
                    if not value:
                        continue
                record[field] = value
        return self._write_record(record)

    def contain(self, record: dict[str, Any], source: Path) -> dict[str, Any]:
        destination = Path(record["object_path"])
        encrypted_written = False
        source_deleted = False
        try:
            if not self.source_identity_matches(record, source):
                return self._write_pre_effect_failure(record, "SOURCE_CHANGED_BEFORE_CONTAINMENT")
            with ImmutableFileCapture(source, max_bytes=self.max_target_bytes) as capture:
                current_raw = capture.raw
                if (len(current_raw) != record.get("target_size")
                        or self._sha256(current_raw) != record.get("target_sha256")):
                    return self._write_pre_effect_failure(record, "SOURCE_CONTENT_CHANGED_BEFORE_CONTAINMENT")
                aad = (record["quarantine_id"] + ":" + record["target_sha256"]).encode("ascii")
                encrypted = self.object_cipher.encrypt(current_raw, aad=aad)
                destination.parent.mkdir(parents=True, exist_ok=False)
                self._atomic_write(destination, encrypted)
                encrypted_written = True
                verified_raw = self.object_cipher.decrypt(destination.read_bytes(), aad=aad)
                if (
                    len(verified_raw) != record["target_size"]
                    or self._sha256(verified_raw) != record["target_sha256"]
                ):
                    return self._write_after_effect_failure(record, "CONTAINED_HASH_MISMATCH")
                capture.delete_exact()
                source_deleted = True
            ciphertext_sha256 = self._sha256(destination.read_bytes())
            record = dict(record, object_ciphertext_sha256=ciphertext_sha256)
            receipt_unsigned = {
                "schema": "cd.quarantine.receipt.v2", "quarantine_id": record["quarantine_id"],
                "state": "QUARANTINED", "target_sha256": record["target_sha256"],
                "object_sha256": record["target_sha256"], "created_at": self._now(),
                "object_encryption": "AES-256-GCM",
                "object_ciphertext_sha256": ciphertext_sha256,
                "authorization_policy_id": record.get("authorization_policy_id"),
                "incident_id": record["incident_id"], "requested_action": record["requested_action"],
                "evidence_ref": record["evidence_ref"],
                "decision_digest": record["decision_digest"], "capability_id": record["capability_id"],
                "scope_digest": record["scope_digest"],
                "production_authorization": record["production_authorization"],
                "lab_authorization": record["lab_authorization"],
            }
            for field in self.ATTRIBUTION_FIELDS:
                if field in record:
                    receipt_unsigned[field] = record[field]
            receipt = dict(receipt_unsigned, receipt_sha256=self._sha256(self._canonical(receipt_unsigned)))
            self._atomic_write(self.receipts_dir / f"{record['quarantine_id']}.json", self._canonical(receipt))
            return self._write_record(dict(record, state="QUARANTINED", contained_at=self._now(),
                                            receipt_sha256=receipt["receipt_sha256"], real_world_effect=True,
                                            recovery_required=False))
        except Exception:
            self._failed += 1
            if encrypted_written or source_deleted:
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

    def _write_restore_pre_effect_failure(self, record: dict[str, Any], code: str) -> dict[str, Any]:
        """Record a denied restore without corrupting the true quarantine state."""
        preserved = dict(
            record,
            state="QUARANTINED",
            last_restore_failure_code=code,
            last_restore_failed_at=self._now(),
            recovery_required=False,
        )
        try:
            return self._write_record(preserved)
        except Exception:
            return preserved

    def mark_verified(self, quarantine_id: str, *, verification_outcome: str, verified_at: str | None = None,
                      execution_started_at: float | None = None, execution_completed_at: float | None = None,
                      execution_latency_ms: float | None = None) -> dict[str, Any]:
        """Persist post-action verification without rewriting the object/receipt."""
        with self._lock:
            record = self.get_verified_record(quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "QUARANTINED":
                raise QuarantineVaultError("record is not quarantined")
            if not isinstance(verification_outcome, str) or not verification_outcome.strip():
                raise QuarantineVaultError("verification outcome required")
            metrics: dict[str, Any] = {}
            for field, value in (
                ("execution_started_at", execution_started_at),
                ("execution_completed_at", execution_completed_at),
                ("execution_latency_ms", execution_latency_ms),
            ):
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                    metrics[field] = round(float(value), 3)
            updated = dict(
                record,
                verification_outcome=verification_outcome.strip()[:64],
                verified_at=verified_at or self._now(),
                post_action_verification=True,
                **metrics,
            )
            return self._write_record(updated)

    def mark_response_metrics(self, quarantine_id: str, *, response_started_at: float,
                              response_completed_at: float, response_latency_ms: float,
                              detection_to_response_ms: float | None = None) -> dict[str, Any]:
        """Persist measured latency after the coordinator completes its real gates."""
        values = (response_started_at, response_completed_at, response_latency_ms)
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 for value in values):
            raise QuarantineVaultError("invalid response metrics")
        metrics: dict[str, Any] = {
            "response_started_at": round(float(response_started_at), 6),
            "response_completed_at": round(float(response_completed_at), 6),
            "response_latency_ms": round(float(response_latency_ms), 3),
        }
        if (
            isinstance(detection_to_response_ms, (int, float))
            and not isinstance(detection_to_response_ms, bool)
            and detection_to_response_ms >= 0
        ):
            metrics["detection_to_response_ms"] = round(float(detection_to_response_ms), 3)
        with self._lock:
            record = self.get_verified_record(quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "QUARANTINED":
                raise QuarantineVaultError("record is not quarantined")
            return self._write_record(dict(record, **metrics))

    def restore(self, record: dict[str, Any], destination: Path, *, capability_id: str,
                scope_digest: str, requester: str, restore_reason: str) -> dict[str, Any]:
        """Restore one verified lab object without overwriting any destination."""
        with self._lock:
            return self._restore_locked(
                record,
                destination,
                capability_id=capability_id,
                scope_digest=scope_digest,
                requester=requester,
                restore_reason=restore_reason,
            )

    def _restore_locked(self, record: dict[str, Any], destination: Path, *, capability_id: str,
                        scope_digest: str, requester: str, restore_reason: str) -> dict[str, Any]:
        created = False
        object_removed = False
        try:
            current = self.get_verified_record(str(record.get("quarantine_id", "")))
            if not isinstance(current, dict) or current != record or current.get("state") != "QUARANTINED":
                raise QuarantineVaultError("restore record changed")
            if not self.verify_object(current) or not self.verify_receipt(current["quarantine_id"], current):
                raise QuarantineVaultError("restore source integrity failure")
            object_path = Path(current["object_path"])
            identity_before = self.file_identity(object_path)
            stored = object_path.read_bytes()
            identity_after = self.file_identity(object_path)
            if identity_before != identity_after:
                raise QuarantineVaultError("restore source changed during capture")
            if current.get("object_encryption") == "AES-256-GCM":
                ciphertext_sha256 = current.get("object_ciphertext_sha256")
                if not isinstance(ciphertext_sha256, str) or self._sha256(stored) != ciphertext_sha256:
                    raise QuarantineVaultError("restore ciphertext integrity failure")
                aad = (current["quarantine_id"] + ":" + current["target_sha256"]).encode("ascii")
                raw = self.object_cipher.decrypt(stored, aad=aad)
            elif current.get("object_encryption") in (None, "NONE"):
                raw = stored
            else:
                raise QuarantineVaultError("restore encryption scheme rejected")
            if len(raw) != current.get("target_size") or self._sha256(raw) != current.get("target_sha256"):
                raise QuarantineVaultError("restore source hash mismatch")

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(str(destination), flags, 0o600)
            created = True
            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    if written <= 0:
                        raise OSError("restore write failed")
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
            restored = destination.read_bytes()
            if len(restored) != len(raw) or self._sha256(restored) != current["target_sha256"]:
                raise QuarantineVaultError("restored target hash mismatch")

            object_path.unlink()
            object_removed = True
            receipt_unsigned = {
                "schema": "cd.quarantine.restore-receipt.v1",
                "quarantine_id": current["quarantine_id"],
                "incident_id": current["incident_id"],
                "state": "RESTORED",
                "target": str(destination),
                "target_sha256": current["target_sha256"],
                "target_size": current["target_size"],
                "object_encryption": current.get("object_encryption", "NONE"),
                "object_ciphertext_sha256": current.get("object_ciphertext_sha256"),
                "restore_capability_id": capability_id,
                "restore_scope_digest": scope_digest,
                "requester": requester,
                "restore_reason": restore_reason,
                "containment_receipt_sha256": current.get("receipt_sha256"),
                "created_at": self._now(),
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "RESTORE_CAPABILITY_CONSUMED",
            }
            receipt = dict(
                receipt_unsigned,
                receipt_sha256=self._sha256(self._canonical(receipt_unsigned)),
            )
            self._atomic_write(
                self.restore_receipts_dir / f"{current['quarantine_id']}.json",
                self._canonical(receipt),
            )
            return self._write_record(dict(
                current,
                state="RESTORED",
                restored_at=self._now(),
                restored_path=str(destination),
                restore_capability_id=capability_id,
                restore_scope_digest=scope_digest,
                restore_reason=restore_reason,
                restore_receipt_sha256=receipt["receipt_sha256"],
                restore_verification_outcome="PENDING",
                post_restore_verification=False,
                real_world_effect=True,
                recovery_required=False,
            ))
        except Exception:
            self._failed += 1
            if created or object_removed:
                failed = dict(
                    record,
                    state="UNKNOWN_AFTER_RESTORE",
                    failure_code="RESTORE_POST_EFFECT_FAILURE",
                    restored_path=str(destination),
                    real_world_effect=True,
                    recovery_required=True,
                )
                try:
                    return self._write_record(failed)
                except Exception:
                    return failed
            return self._write_restore_pre_effect_failure(record, "RESTORE_FAILED")

    def verify_restore_receipt(self, quarantine_id: str, record: dict[str, Any]) -> bool:
        try:
            value = json.loads(
                (self.restore_receipts_dir / f"{quarantine_id}.json").read_text(encoding="utf-8")
            )
            unsigned = {key: item for key, item in value.items() if key != "receipt_sha256"}
            return bool(
                value.get("receipt_sha256") == self._sha256(self._canonical(unsigned))
                and value.get("state") == "RESTORED"
                and value.get("quarantine_id") == record.get("quarantine_id")
                and value.get("incident_id") == record.get("incident_id")
                and value.get("target") == record.get("restored_path")
                and value.get("target_sha256") == record.get("target_sha256")
                and value.get("target_size") == record.get("target_size")
                and value.get("restore_capability_id") == record.get("restore_capability_id")
                and value.get("restore_scope_digest") == record.get("restore_scope_digest")
                and value.get("restore_reason") == record.get("restore_reason")
                and value.get("containment_receipt_sha256") == record.get("receipt_sha256")
                and value.get("object_encryption") == record.get("object_encryption", "NONE")
                and value.get("object_ciphertext_sha256") == record.get("object_ciphertext_sha256")
                and value.get("production_authorization") == "NOT_GRANTED"
                and value.get("lab_authorization") == "RESTORE_CAPABILITY_CONSUMED"
            )
        except Exception:
            return False

    def verify_restored_target(self, record: dict[str, Any]) -> bool:
        try:
            target = Path(str(record.get("restored_path", "")))
            root = Path(str(record.get("approved_root", ""))).resolve(strict=True)
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
            if self._has_reparse_component(resolved):
                return False
            raw = resolved.read_bytes()
            return (
                len(raw) == record.get("target_size")
                and self._sha256(raw) == record.get("target_sha256")
                and not Path(str(record.get("object_path", ""))).exists()
            )
        except Exception:
            return False

    def mark_restore_verified(self, quarantine_id: str, *, verification_outcome: str,
                              restore_latency_ms: float) -> dict[str, Any]:
        with self._lock:
            record = self.get_verified_record(quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "RESTORED":
                raise QuarantineVaultError("record is not restored")
            if verification_outcome != "RESTORED_VERIFIED":
                raise QuarantineVaultError("invalid restore verification outcome")
            if isinstance(restore_latency_ms, bool) or not isinstance(restore_latency_ms, (int, float)) or restore_latency_ms < 0:
                raise QuarantineVaultError("invalid restore latency")
            return self._write_record(dict(
                record,
                restore_verification_outcome=verification_outcome,
                restore_verified_at=self._now(),
                restore_latency_ms=round(float(restore_latency_ms), 3),
                post_restore_verification=True,
                recovery_required=False,
            ))

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
                    "production_authorization", "lab_authorization", "object_encryption",
                    "object_ciphertext_sha256", "authorization_policy_id",
                )
            )
            attribution_linked = all(
                not (field in record and field not in value) and
                (field not in record or field not in value or value.get(field) == record.get(field))
                for field in self.ATTRIBUTION_FIELDS
            )
            return (
                value.get("receipt_sha256") == self._sha256(self._canonical(unsigned))
                and value.get("state") == "QUARANTINED"
                and value.get("target_sha256") == record.get("target_sha256")
                and linked
                and attribution_linked
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
            stored = object_path.read_bytes()
            if record.get("object_encryption") == "AES-256-GCM":
                if self._sha256(stored) != record.get("object_ciphertext_sha256"):
                    return False
                aad = (record["quarantine_id"] + ":" + record["target_sha256"]).encode("ascii")
                raw = self.object_cipher.decrypt(stored, aad=aad)
            elif record.get("object_encryption") in (None, "NONE"):
                raw = stored
            else:
                return False
            return len(raw) == record.get("target_size") and self._sha256(raw) == record.get("target_sha256")
        except Exception:
            return False

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            try:
                records = self._records()
                count = len(records)
                review_states = {
                    "FAILED", "FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT",
                    "UNKNOWN_AFTER_RESTORE", "EVIDENCE_CAPTURED",
                }
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
