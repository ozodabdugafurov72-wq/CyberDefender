from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import uuid


class SecureQuarantineVault:

    VERSION = "1.1"
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
        self._already_quarantined = 0
        self._integrity_failures = 0
        self._duplicate_attempts = 0
        self._read_failures = 0

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

    @staticmethod
    def sha256(
        raw: bytes,
    ) -> str:

        return hashlib.sha256(
            raw
        ).hexdigest()

    @staticmethod
    def _now() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()

    def _existing_by_hash(
        self,
        raw_hash: str,
    ) -> Optional[dict[str, Any]]:

        for path in self.records_dir.glob(
            "*.json"
        ):

            try:

                metadata = json.loads(
                    path.read_text(
                        encoding="utf-8"
                    )
                )

                if (
                    metadata.get(
                        "raw_sha256"
                    )
                    == raw_hash
                ):
                    return metadata

            except Exception:

                self._read_failures += 1

        return None

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

        raw_hash = self.sha256(
            raw_record
        )

        existing = self._existing_by_hash(
            raw_hash
        )

        if existing is not None:

            self._already_quarantined += 1

            return existing

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

        evidence_path.write_bytes(
            raw_record
        )

        stored = (
            evidence_path.read_bytes()
        )

        if self.sha256(
            stored
        ) != raw_hash:

            self._integrity_failures += 1

            raise IOError(
                "Quarantine evidence integrity failed"
            )

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

        metadata_path.write_bytes(
            self._canonical_json(
                metadata
            )
        )

        self._quarantined += 1

        return metadata

    def get_record(
        self,
        quarantine_id: str,
    ) -> Optional[dict[str, Any]]:

        path = (
            self.records_dir
            / (
                quarantine_id
                + ".json"
            )
        )

        if not path.exists():
            return None

        try:

            return json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

        except Exception:

            self._read_failures += 1

            return None

    def verify_evidence(
        self,
        quarantine_id: str,
    ) -> bool:

        metadata = self.get_record(
            quarantine_id
        )

        if metadata is None:
            return False

        path = (
            self.evidence_dir
            / metadata[
                "evidence_file"
            ]
        )

        if not path.exists():
            return False

        try:

            actual = self.sha256(
                path.read_bytes()
            )

            expected = metadata[
                "raw_sha256"
            ]

            if actual != expected:

                self._integrity_failures += 1

                return False

            return True

        except Exception:

            self._read_failures += 1

            return False

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

                result.append(
                    json.loads(
                        path.read_text(
                            encoding="utf-8"
                        )
                    )
                )

            except Exception:

                self._read_failures += 1

        return result

    def restore(
        self,
        quarantine_id: str,
        authorized: bool = False,
        policy_valid: bool = False,
        clean_verified: bool = False,
    ) -> bool:

        if not authorized:
            return False

        if not policy_valid:
            return False

        if not clean_verified:
            return False

        return self.verify_evidence(
            quarantine_id
        )

    def get_stats(
        self,
    ) -> dict[str, Any]:

        return {
            "component":
                "SecureQuarantineVault",

            "version":
                self.VERSION,

            "status":
                self.STATUS_HEALTHY,

            "quarantined":
                self._quarantined,

            "already_quarantined":
                self._already_quarantined,

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
