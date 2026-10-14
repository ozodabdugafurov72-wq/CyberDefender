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
            authorization_pair = (
                record.get("production_authorization"), record.get("lab_authorization")
            )
            if authorization_pair not in {
                ("NOT_GRANTED", "QUARANTINE_CAPABILITY_CONSUMED"),
                ("SIGNED_POLICY_CAPABILITY_CONSUMED", "NOT_APPLICABLE"),
            }:
                return self._fail("AUTHORIZATION_AUDIT_INVALID")
            if (
                authorization_pair[0] == "SIGNED_POLICY_CAPABILITY_CONSUMED"
                and not isinstance(record.get("authorization_policy_id"), str)
            ):
                return self._fail("AUTHORIZATION_POLICY_AUDIT_MISSING")
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
            result = {
                "component": "QuarantineIndependentVerifier", "version": self.VERSION,
                "accepted": True, "verified": True, "verification_outcome": "QUARANTINED_VERIFIED",
                "quarantine_id": quarantine_id, "incident_id": record["incident_id"],
                "requested_action": record["requested_action"],
                "evidence_ref": record["evidence_ref"], "decision_digest": record["decision_digest"],
                "capability_id": record["capability_id"], "scope_digest": record["scope_digest"],
                "production_authorization": record.get("production_authorization"),
                "lab_authorization": record.get("lab_authorization"),
                "authorization_policy_id": record.get("authorization_policy_id"),
                "authorization": (
                    "SIGNED_POLICY_CAPABILITY_CONSUMED"
                    if record.get("production_authorization") == "SIGNED_POLICY_CAPABILITY_CONSUMED"
                    else "NOT_GRANTED"
                ),
                "real_world_effect_observed": True, "fail_closed": True,
            }
            for field in (
                "event_id", "endpoint_id", "tenant_id", "detection_types", "detection_count",
                "detection_confidence", "risk_score", "risk_level", "policy_outcome",
                "policy_reason", "verifier_outcome", "verification_outcome", "verified_at",
            ):
                if field in record:
                    result[field] = record[field]
            return result
        except (QuarantineVaultError, OSError, TypeError, ValueError):
            return self._fail("VERIFICATION_ERROR")

    def verify_restore_eligibility(self, quarantine_id: str) -> dict[str, Any]:
        """Prove that one intact lab object is eligible for controlled reset."""
        try:
            record = self.vault.get_verified_record(quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "QUARANTINED":
                return self._fail("RECORD_NOT_QUARANTINED")
            original = Path(str(record.get("original_path", ""))).expanduser().resolve(strict=False)
            root = Path(str(record.get("approved_root", ""))).expanduser().resolve(strict=True)
            original.relative_to(root)
            if original.exists() or original.is_symlink():
                return self._fail("RESTORE_DESTINATION_NOT_EMPTY")
            if self.vault._has_reparse_component(original.parent):
                return self._fail("RESTORE_PARENT_REPARSE")
            evidence_id = record.get("evidence_quarantine_id")
            if not isinstance(evidence_id, str) or not self.vault.evidence_vault.verify_evidence(evidence_id):
                return self._fail("EVIDENCE_NOT_VERIFIED")
            if not self.vault.verify_object(record):
                return self._fail("CONTAINED_OBJECT_NOT_VERIFIED")
            if not self.vault.verify_receipt(quarantine_id, record):
                return self._fail("RECEIPT_NOT_VERIFIED")
            return {
                "component": "QuarantineIndependentVerifier", "version": self.VERSION,
                "accepted": True, "verified": True,
                "verification_outcome": "RESTORE_ELIGIBLE_VERIFIED",
                "quarantine_id": quarantine_id,
                "incident_id": record.get("incident_id"),
                "target": str(original),
                "target_sha256": record.get("target_sha256"),
                "production_authorization": "NOT_GRANTED",
                "authorization": "NOT_GRANTED",
                "real_world_effect_observed": False,
                "fail_closed": True,
            }
        except (QuarantineVaultError, OSError, RuntimeError, TypeError, ValueError):
            return self._fail("RESTORE_ELIGIBILITY_ERROR")

    def verify_restore(self, quarantine_id: str, *, original_path: str, target_sha256: str) -> dict[str, Any]:
        """Independently verify the exact target was restored and the vault copy removed."""
        try:
            record = self.vault.get_verified_record(quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "RESTORED":
                return self._fail("RECORD_NOT_RESTORED")
            if record.get("target_sha256") != target_sha256:
                return self._fail("RESTORE_HASH_SCOPE_MISMATCH")
            expected = Path(str(record.get("original_path", ""))).expanduser().resolve(strict=False)
            supplied = Path(original_path).expanduser().resolve(strict=False)
            if expected != supplied:
                return self._fail("RESTORE_PATH_SCOPE_MISMATCH")
            if self.vault._has_reparse_component(supplied):
                return self._fail("RESTORED_TARGET_REPARSE")
            if not self.vault.verify_restored_target(record):
                return self._fail("RESTORED_TARGET_NOT_VERIFIED")
            if Path(str(record.get("object_path", ""))).exists():
                return self._fail("QUARANTINE_OBJECT_STILL_PRESENT")
            if not self.vault.verify_receipt(quarantine_id, record):
                return self._fail("CONTAINMENT_RECEIPT_NOT_VERIFIED")
            if not self.vault.verify_restore_receipt(quarantine_id, record):
                return self._fail("RESTORE_RECEIPT_NOT_VERIFIED")
            evidence_id = record.get("evidence_quarantine_id")
            if not isinstance(evidence_id, str) or not self.vault.evidence_vault.verify_evidence(evidence_id):
                return self._fail("EVIDENCE_NOT_VERIFIED")
            return {
                "component": "QuarantineIndependentVerifier", "version": self.VERSION,
                "accepted": True, "verified": True,
                "verification_outcome": "RESTORED_VERIFIED",
                "quarantine_id": quarantine_id,
                "incident_id": record.get("incident_id"),
                "target": str(supplied),
                "target_sha256": target_sha256,
                "restore_capability_id": record.get("restore_capability_id"),
                "restore_scope_digest": record.get("restore_scope_digest"),
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "RESTORE_CAPABILITY_CONSUMED",
                "authorization": "NOT_GRANTED",
                "real_world_effect_observed": True,
                "fail_closed": True,
            }
        except (QuarantineVaultError, OSError, RuntimeError, TypeError, ValueError):
            return self._fail("RESTORE_VERIFICATION_ERROR")

    @staticmethod
    def _fail(reason: str) -> dict[str, Any]:
        return {
            "component": "QuarantineIndependentVerifier", "version": QuarantineIndependentVerifier.VERSION,
            "accepted": False, "verified": False, "verification_outcome": "UNVERIFIED",
            "reason": reason, "authorization": "NOT_GRANTED", "real_world_effect_observed": None,
            "fail_closed": True, "recovery_required": True,
        }
