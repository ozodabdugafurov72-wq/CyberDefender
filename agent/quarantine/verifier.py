from __future__ import annotations

"""Independent post-containment verification for the lab canary executor."""

from pathlib import Path
from typing import Any

from agent.quarantine.v2_vault import BoundedQuarantineVault, QuarantineVaultError


class QuarantineIndependentVerifier:
    VERSION = "2.0"

    def __init__(self, vault: BoundedQuarantineVault) -> None:
        self.vault = vault

    def verify(self, quarantine_id: str, *, original_path: str, approved_root: str, target_sha256: str,
               evidence_ref: str | None = None, decision_digest: str | None = None) -> dict[str, Any]:
        try:
            record = self.vault.get_verified_record(quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "QUARANTINED":
                return self._fail("RECORD_NOT_QUARANTINED")
            if record.get("target_sha256") != target_sha256:
                return self._fail("TARGET_HASH_MISMATCH")
            if record.get("requested_action") != "QUARANTINE":
                return self._fail("ACTION_SCOPE_MISMATCH")
            if evidence_ref is not None and record.get("evidence_ref") != evidence_ref:
                return self._fail("EVIDENCE_SCOPE_MISMATCH")
            if decision_digest is not None and record.get("decision_digest") != decision_digest:
                return self._fail("DECISION_SCOPE_MISMATCH")
            if not isinstance(record.get("capability_id"), str) or not record.get("capability_id"):
                return self._fail("CAPABILITY_AUDIT_MISSING")
            if not isinstance(record.get("scope_digest"), str) or len(record["scope_digest"]) != 64:
                return self._fail("CAPABILITY_SCOPE_AUDIT_MISSING")
            if record.get("production_authorization") != "NOT_GRANTED":
                return self._fail("PRODUCTION_AUTHORIZATION_INVALID")
            if record.get("lab_authorization") != "QUARANTINE_CAPABILITY_CONSUMED":
                return self._fail("LAB_AUTHORIZATION_AUDIT_INVALID")
            if Path(record.get("original_path", "")).expanduser().resolve() != Path(original_path).expanduser().resolve():
                return self._fail("ORIGINAL_PATH_MISMATCH")
            if Path(record.get("approved_root", "")).expanduser().resolve() != Path(approved_root).expanduser().resolve():
                return self._fail("APPROVED_ROOT_MISMATCH")
            if self.vault._has_reparse_component(Path(original_path).parent):
                return self._fail("ORIGINAL_PARENT_REPARSE")
            if Path(original_path).exists() or Path(original_path).is_symlink():
                return self._fail("ORIGINAL_STILL_ACCESSIBLE")
            evidence_id = record.get("evidence_quarantine_id")
            if not isinstance(evidence_id, str) or not self.vault.evidence_vault.verify_evidence(evidence_id):
                return self._fail("EVIDENCE_NOT_VERIFIED")
            if not self.vault.verify_object(record):
                return self._fail("CONTAINED_OBJECT_NOT_VERIFIED")
            if not self.vault.verify_receipt(quarantine_id, record):
                return self._fail("RECEIPT_NOT_VERIFIED")
            return {
                "component": "QuarantineIndependentVerifier", "version": self.VERSION,
                "accepted": True, "verified": True, "verification_outcome": "QUARANTINED_VERIFIED",
                "quarantine_id": quarantine_id, "incident_id": record["incident_id"],
                "requested_action": record["requested_action"],
                "evidence_ref": record["evidence_ref"], "decision_digest": record["decision_digest"],
                "capability_id": record["capability_id"], "scope_digest": record["scope_digest"],
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
                "authorization": "NOT_GRANTED",
                "real_world_effect_observed": True, "fail_closed": True,
            }
        except (QuarantineVaultError, OSError, TypeError, ValueError):
            return self._fail("VERIFICATION_ERROR")

    @staticmethod
    def _fail(reason: str) -> dict[str, Any]:
        return {
            "component": "QuarantineIndependentVerifier", "version": QuarantineIndependentVerifier.VERSION,
            "accepted": False, "verified": False, "verification_outcome": "UNVERIFIED",
            "reason": reason, "authorization": "NOT_GRANTED", "real_world_effect_observed": None,
            "fail_closed": True, "recovery_required": True,
        }
