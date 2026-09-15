from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================
# P11.15 SECURE QUARANTINE VAULT
# ============================================================

class SecureQuarantineVault:

    VERSION = "1.0"
    SCHEMA_VERSION = "1"

    STATUS_HEALTHY = "HEALTHY"
    STATUS_DEGRADED = "DEGRADED"

    def __init__(
        self,
        vault_dir: str | Path,
    ):
        self.vault_dir = Path(vault_dir)

        self.records_dir = (
            self.vault_dir / "records"
        )

        self.evidence_dir = (
            self.vault_dir / "evidence"
        )

        self.records_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.evidence_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._quarantined = 0
        self._integrity_failures = 0
        self._duplicate_attempts = 0
        self._read_failures = 0

    # ========================================================
    # CANONICAL JSON
    # ========================================================

    @staticmethod
    def _canonical_json(
        data: dict[str, Any],
    ) -> bytes:

        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    # ========================================================
    # SHA-256
    # ========================================================

    @staticmethod
    def _sha256(
        raw: bytes,
    ) -> str:

        return hashlib.sha256(
            raw
        ).hexdigest()

    # ========================================================
    # UTC TIME
    # ========================================================

    @staticmethod
    def _now() -> str:

        return (
            datetime.now(
                timezone.utc
            )
            .isoformat()
        )

    # ========================================================
    # QUARANTINE
    # ========================================================

    def quarantine(
        self,
        raw_record: bytes,
        reason: str,
        source: str,
        event_id: Optional[str] = None,
        failure_type: str = "UNKNOWN",
    ) -> dict[str, Any]:

        if not isinstance(
            raw_record,
            bytes,
        ):
            raise TypeError(
                "raw_record bytes bo'lishi kerak"
            )

        if not isinstance(
            reason,
            str,
        ) or not reason:

            raise ValueError(
                "reason kerak"
            )

        if not isinstance(
            source,
            str,
        ) or not source:

            raise ValueError(
                "source kerak"
            )

        raw_hash = self._sha256(
            raw_record
        )

        quarantine_id = (
            "q-"
            + uuid.uuid4().hex
        )

        evidence_filename = (
            quarantine_id
            + ".raw"
        )

        metadata_filename = (
            quarantine_id
            + ".json"
        )

        evidence_path = (
            self.evidence_dir
            / evidence_filename
        )

        metadata_path = (
            self.records_dir
            / metadata_filename
        )

        # ----------------------------------------------------
        # Never overwrite an existing quarantine object.
        # ----------------------------------------------------

        if (
            evidence_path.exists()
            or metadata_path.exists()
        ):

            self._duplicate_attempts += 1

            raise FileExistsError(
                "Quarantine collision"
            )

        # ----------------------------------------------------
        # Preserve exact raw bytes.
        # ----------------------------------------------------

        evidence_path.write_bytes(
            raw_record
        )

        evidence_size = (
            evidence_path.stat().st_size
        )

        if evidence_size != len(
            raw_record
        ):

            self._read_failures += 1

            raise IOError(
                "Evidence size verification failed"
            )

        # ----------------------------------------------------
        # Verify evidence immediately.
        # ----------------------------------------------------

        stored_raw = (
            evidence_path.read_bytes()
        )

        stored_hash = self._sha256(
            stored_raw
        )

        if stored_hash != raw_hash:

            self._integrity_failures += 1

            raise IOError(
                "Evidence hash verification failed"
            )

        # ----------------------------------------------------
        # Evidence metadata.
        # ----------------------------------------------------

        metadata = {
            "schema_version":
                self.SCHEMA_VERSION,

            "quarantine_id":
                quarantine_id,

            "event_id":
                event_id,

            "reason":
                reason,

            "failure_type":
                failure_type,

            "source":
                source,

            "detected_at":
                self._now(),

            "algorithm":
                "SHA-256",

            "raw_sha256":
                raw_hash,

            "raw_size":
                len(raw_record),

            "evidence_file":
                evidence_filename,

            "restore_allowed":
                False,

            "status":
                "QUARANTINED",
        }

        metadata_bytes = (
            self._canonical_json(
                metadata
            )
        )

        metadata_path.write_bytes(
            metadata_bytes
        )

        # ----------------------------------------------------
        # Verify metadata after persistence.
        # ----------------------------------------------------

        loaded_metadata = json.loads(
            metadata_path.read_text(
                encoding="utf-8"
            )
        )

        if (
            loaded_metadata
            != metadata
        ):

            self._integrity_failures += 1

            raise IOError(
                "Quarantine metadata verification failed"
            )

        self._quarantined += 1

        return metadata

    # ========================================================
    # GET RECORD
    # ========================================================

    def get_record(
        self,
        quarantine_id: str,
    ) -> Optional[dict[str, Any]]:

        if not isinstance(
            quarantine_id,
            str,
        ):
            return None

        metadata_path = (
            self.records_dir
            / (
                quarantine_id
                + ".json"
            )
        )

        if not metadata_path.exists():
            return None

        try:

            metadata = json.loads(
                metadata_path.read_text(
                    encoding="utf-8"
                )
            )

            return metadata

        except Exception:

            self._read_failures += 1

            return None

    # ========================================================
    # VERIFY EVIDENCE
    # ========================================================

    def verify_evidence(
        self,
        quarantine_id: str,
    ) -> bool:

        metadata = self.get_record(
            quarantine_id
        )

        if not metadata:
            return False

        evidence_file = (
            metadata.get(
                "evidence_file"
            )
        )

        expected_hash = (
            metadata.get(
                "raw_sha256"
            )
        )

        if not isinstance(
            evidence_file,
            str,
        ):
            return False

        if not isinstance(
            expected_hash,
            str,
        ):
            return False

        evidence_path = (
            self.evidence_dir
            / evidence_file
        )

        if not evidence_path.exists():
            return False

        try:

            raw = (
                evidence_path.read_bytes()
            )

            actual_hash = (
                self._sha256(raw)
            )

            return (
                actual_hash
                == expected_hash
            )

        except Exception:

            self._read_failures += 1

            return False

    # ========================================================
    # RESTORE IS INTENTIONALLY BLOCKED
    # ========================================================

    def restore(
        self,
        quarantine_id: str,
        authorized: bool = False,
        policy_valid: bool = False,
        clean_verified: bool = False,
    ) -> bool:

        # ----------------------------------------------------
        # No implicit restoration.
        # ----------------------------------------------------

        if not authorized:
            return False

        if not policy_valid:
            return False

        if not clean_verified:
            return False

        metadata = self.get_record(
            quarantine_id
        )

        if not metadata:
            return False

        if not self.verify_evidence(
            quarantine_id
        ):
            return False

        # ----------------------------------------------------
        # P11.15 deliberately does NOT perform the actual
        # filesystem restoration.
        #
        # A future Recovery Engine must perform restoration
        # through:
        #
        # Policy
        # Authorization
        # Safety Core
        # Independent Verification
        #
        # This vault only verifies that all gates are present.
        # ----------------------------------------------------

        return True

    # ========================================================
    # LIST
    # ========================================================

    def list_records(
        self,
    ) -> list[dict[str, Any]]:

        result = []

        for path in sorted(
            self.records_dir.glob(
                "*.json"
            )
        ):

            try:

                data = json.loads(
                    path.read_text(
                        encoding="utf-8"
                    )
                )

                result.append(
                    data
                )

            except Exception:

                self._read_failures += 1

        return result

    # ========================================================
    # STATS
    # ========================================================

    def get_stats(self) -> dict[str, Any]:

        return {
            "component":
                "SecureQuarantineVault",

            "version":
                self.VERSION,

            "status":
                self.STATUS_HEALTHY,

            "quarantined":
                self._quarantined,

            "integrity_failures":
                self._integrity_failures,

            "duplicate_attempts":
                self._duplicate_attempts,

            "read_failures":
                self._read_failures,

            "records":
                len(
                    list(
                        self.records_dir.glob(
                            "*.json"
                        )
                    )
                ),
        }

    # ========================================================
    # HEALTH
    # ========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:

        stats = self.get_stats()

        degraded = (
            stats["integrity_failures"] > 0
            or stats["read_failures"] > 0
        )

        return {
            "component":
                "SecureQuarantineVault",

            "status":
                (
                    self.STATUS_DEGRADED
                    if degraded
                    else self.STATUS_HEALTHY
                ),

            "version":
                self.VERSION,

            "evidence_preservation":
                True,

            "restore_by_default":
                False,

            "cryptographic_hash":
                "SHA-256",
        }


# ============================================================
# P11.15 TEST
# ============================================================

ROOT = Path(
    "state/test_p11_15_quarantine"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

vault = SecureQuarantineVault(
    ROOT / "vault"
)


print(
    "=== P11.15-01 CREATE RAW EVIDENCE ==="
)

raw_event = (
    b'{"event_id":"event-p11-15",'
    b'"type":"MALICIOUS_RECORD",'
    b'"message":"suspicious payload"}'
)

raw_hash = hashlib.sha256(
    raw_event
).hexdigest()

print(
    "RAW_SIZE=",
    len(raw_event),
)

print(
    "RAW_SHA256=",
    raw_hash,
)


print()
print(
    "=== P11.15-02 QUARANTINE ==="
)

metadata = vault.quarantine(
    raw_record=raw_event,
    reason="STORAGE_CORRUPTION",
    source="DurableEventSpool",
    event_id="event-p11-15",
    failure_type="INVALID_JSON_RECORD",
)

print(
    "QUARANTINED=",
    True,
)

print(
    "QUARANTINE_ID=",
    metadata["quarantine_id"],
)

print(
    "EVENT_ID=",
    metadata["event_id"],
)

print(
    "RAW_SHA256=",
    metadata["raw_sha256"],
)

print(
    "RESTORE_ALLOWED=",
    metadata["restore_allowed"],
)


print()
print(
    "=== P11.15-03 VERIFY EVIDENCE ==="
)

verified = vault.verify_evidence(
    metadata["quarantine_id"]
)

print(
    "EVIDENCE_VERIFY=",
    verified,
)


print()
print(
    "=== P11.15-04 READ METADATA ==="
)

record = vault.get_record(
    metadata["quarantine_id"]
)

print(
    "RECORD_PRESENT=",
    record is not None,
)

print(
    "STATUS=",
    record["status"],
)

print(
    "FAILURE_TYPE=",
    record["failure_type"],
)


print()
print(
    "=== P11.15-05 UNAUTHORIZED RESTORE ==="
)

unauthorized_restore = vault.restore(
    metadata["quarantine_id"]
)

print(
    "UNAUTHORIZED_RESTORE=",
    unauthorized_restore,
)


print()
print(
    "=== P11.15-06 INCOMPLETE AUTHORIZATION ==="
)

incomplete_restore = vault.restore(
    metadata["quarantine_id"],
    authorized=True,
    policy_valid=True,
    clean_verified=False,
)

print(
    "INCOMPLETE_RESTORE=",
    incomplete_restore,
)


print()
print(
    "=== P11.15-07 COMPLETE GATE CHECK ==="
)

complete_gate = vault.restore(
    metadata["quarantine_id"],
    authorized=True,
    policy_valid=True,
    clean_verified=True,
)

print(
    "COMPLETE_GATE=",
    complete_gate,
)

print(
    "NOTE=",
    "No filesystem restore performed.",
)


print()
print(
    "=== P11.15-08 TAMPER QUARANTINE EVIDENCE ==="
)

evidence_path = (
    vault.evidence_dir
    / metadata["evidence_file"]
)

evidence_path.write_bytes(
    b"ATTACKER MODIFIED QUARANTINE EVIDENCE"
)

tampered_verify = vault.verify_evidence(
    metadata["quarantine_id"]
)

print(
    "TAMPERED_EVIDENCE_VERIFY=",
    tampered_verify,
)


print()
print(
    "=== P11.15-09 HEALTH ==="
)

print(
    "HEALTH=",
    vault.health_check()
)

print(
    "STATS=",
    vault.get_stats()
)


print()
print(
    "=== P11.15-10 FINAL ASSERTIONS ==="
)

assert metadata["quarantine_id"]

assert metadata["event_id"] == (
    "event-p11-15"
)

assert metadata["algorithm"] == (
    "SHA-256"
)

assert metadata["raw_sha256"] == (
    raw_hash
)

assert metadata["status"] == (
    "QUARANTINED"
)

assert metadata["restore_allowed"] is False

assert verified is True

assert record is not None

assert record["quarantine_id"] == (
    metadata["quarantine_id"]
)

assert unauthorized_restore is False

assert incomplete_restore is False

assert complete_gate is True

assert tampered_verify is False

stats = vault.get_stats()

assert stats["quarantined"] == 1

assert stats["records"] == 1

assert stats["integrity_failures"] == 0

print(
    "RAW_EVIDENCE_PRESERVED=True"
)

print(
    "SHA256_VERIFIED=True"
)

print(
    "QUARANTINE_METADATA_PRESERVED=True"
)

print(
    "UNAUTHORIZED_RESTORE_BLOCKED=True"
)

print(
    "INCOMPLETE_RESTORE_BLOCKED=True"
)

print(
    "AUTHORIZED_GATE_VALIDATED=True"
)

print(
    "QUARANTINE_TAMPER_DETECTED=True"
)

print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)
