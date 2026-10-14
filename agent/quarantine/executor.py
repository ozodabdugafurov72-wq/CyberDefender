from __future__ import annotations

"""Bounded Quarantine v2 lab-canary executor.

This module is not wired into ``CyberDefenderRuntime``. It can move only one
explicitly supplied regular file inside one explicit lab root. No shell,
network, service, registry, firewall, or process operation is available.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Any

from agent.quarantine.contracts import (
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    DRY_RUN_ONLY,
    LAB_CANARY_EXECUTION,
    PRODUCTION_AUTONOMOUS_EXECUTION,
    QuarantineCapabilityIssuer,
    QuarantineContractError,
    QuarantineRequest,
    RestoreCapabilityIssuer,
    RestoreRequest,
)
from agent.quarantine.v2_vault import BoundedQuarantineVault, QuarantineVaultError
from agent.quarantine.verifier import QuarantineIndependentVerifier


class BoundedQuarantineExecutor:
    VERSION = "2.0"
    FORBIDDEN_SUFFIXES = frozenset({".exe", ".dll", ".sys", ".drv", ".pyd", ".py", ".pyc", ".msi", ".bat", ".cmd", ".ps1", ".com"})

    def __init__(self, vault: BoundedQuarantineVault, issuer: QuarantineCapabilityIssuer,
                 *, approved_root: str | Path, mode: str = LAB_CANARY_EXECUTION,
                 restore_issuer: RestoreCapabilityIssuer | None = None) -> None:
        if mode not in (LAB_CANARY_EXECUTION, PRODUCTION_AUTONOMOUS_EXECUTION, DRY_RUN_ONLY):
            raise ValueError("unsupported executor mode")
        self.vault = vault
        self.issuer = issuer
        self.restore_issuer = restore_issuer or RestoreCapabilityIssuer()
        self.approved_root = Path(approved_root).expanduser().resolve()
        self.mode = mode
        self.verifier = QuarantineIndependentVerifier(vault)
        self.executions = 0
        self.rejected = 0

    @staticmethod
    def _hash(path: Path) -> tuple[str, int, bytes]:
        raw = path.read_bytes()
        return hashlib.sha256(raw).hexdigest(), len(raw), raw

    def _deny(self, reason: str) -> dict[str, Any]:
        self.rejected += 1
        return {"component": "BoundedQuarantineExecutor", "version": self.VERSION, "accepted": False,
                "executed": False, "status": "DENIED", "reason": reason, "authorization": "NOT_GRANTED",
                "real_world_effect": False, "fail_closed": True}

    def _after_effect(self, reason: str, *, quarantine_id: str | None = None,
                      state: str = "UNKNOWN_AFTER_EFFECT", capability_id: str | None = None,
                      scope_digest: str | None = None,
                      production_authorization: str = "NOT_GRANTED",
                      lab_authorization: str = "QUARANTINE_CAPABILITY_CONSUMED") -> dict[str, Any]:
        self.rejected += 1
        return {
            "component": "BoundedQuarantineExecutor", "version": self.VERSION,
            "accepted": False, "executed": True, "status": state, "reason": reason,
            "quarantine_id": quarantine_id, "authorization": "NOT_GRANTED",
            "production_authorization": production_authorization,
            "lab_authorization": lab_authorization,
            "capability_id": capability_id, "scope_digest": scope_digest,
            "real_world_effect": True, "recovery_required": True, "fail_closed": True,
        }

    @staticmethod
    def _resolved(value: str | Path) -> Path | None:
        try:
            return Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

    def _marker_valid(self) -> bool:
        try:
            marker = self.approved_root / CANARY_MARKER_FILENAME
            return (
                self.approved_root.is_dir()
                and not self.vault._has_reparse_component(self.approved_root)
                and marker.is_file()
                and not marker.is_symlink()
                and marker.read_bytes() == CANARY_MARKER.encode("utf-8")
            )
        except (OSError, RuntimeError, ValueError, QuarantineVaultError):
            return False

    def _protected_path(self, path: Path) -> bool:
        """Deny Windows/runtime/boot locations; uncertainty is protected."""
        resolved = self._resolved(path)
        if resolved is None:
            return True
        raw_candidates = [
            os.environ.get("WINDIR"), os.environ.get("SystemRoot"),
            os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
            os.environ.get("PROGRAMDATA"), os.environ.get("CYBERDEFENDER_ROOT"),
            "C:/Windows", "C:/Program Files", "C:/Program Files (x86)",
            "C:/ProgramData", "C:/Boot", "C:/EFI", "C:/Recovery",
            "C:/System Volume Information",
        ]
        try:
            candidates = [Path(value).expanduser().resolve(strict=False) for value in raw_candidates if value]
            candidates.extend([Path(__file__).resolve().parents[2]])
            return any(resolved == root or root in resolved.parents for root in candidates)
        except (OSError, RuntimeError, TypeError, ValueError):
            return True

    def _safe_target(self, request: QuarantineRequest) -> tuple[Path, str | None]:
        if self.mode == LAB_CANARY_EXECUTION and request.canary_marker != CANARY_MARKER:
            return Path(), "CANARY_MARKER_INVALID"
        root = self._resolved(request.approved_root)
        if root is None:
            return Path(), "APPROVED_ROOT_UNRESOLVED"
        if root != self.approved_root:
            return Path(), "APPROVED_ROOT_MISMATCH"
        if self.mode == LAB_CANARY_EXECUTION and not self._marker_valid():
            return Path(), "DEDICATED_CANARY_ROOT_REQUIRED"
        target = Path(request.target).expanduser()
        try:
            if BoundedQuarantineVault._has_reparse_component(target):
                return Path(), "TARGET_REPARSE_OR_SYMLINK"
            if not target.is_file():
                return Path(), "TARGET_NOT_REGULAR_FILE"
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
        except QuarantineVaultError:
            return Path(), "TARGET_IDENTITY_UNAVAILABLE"
        except (OSError, RuntimeError, ValueError):
            return Path(), "TARGET_OUTSIDE_APPROVED_ROOT"
        if self.mode == LAB_CANARY_EXECUTION and resolved.suffix.lower() in self.FORBIDDEN_SUFFIXES:
            return Path(), "PROTECTED_EXECUTABLE_TYPE"
        if self.mode == LAB_CANARY_EXECUTION and resolved == root / CANARY_MARKER_FILENAME:
            return Path(), "CANARY_MARKER_DENIED"
        if self._protected_path(resolved):
            return Path(), "PROTECTED_PATH_DENIED"
        if resolved == self.vault.root or self.vault.root in resolved.parents:
            return Path(), "VAULT_PATH_DENIED"
        if resolved.stat().st_size > self.vault.max_target_bytes:
            return Path(), "TARGET_SIZE_LIMIT"
        return resolved, None

    def execute(self, request: QuarantineRequest | dict[str, Any], capability: Any = None) -> dict[str, Any]:
        execution_started_at = time.time()
        execution_started_ns = time.perf_counter_ns()
        try:
            req = request if isinstance(request, QuarantineRequest) else QuarantineRequest.from_mapping(request)
        except QuarantineContractError:
            return self._deny("INVALID_REQUEST")
        if req.mode == DRY_RUN_ONLY or self.mode == DRY_RUN_ONLY:
            return {"component": "BoundedQuarantineExecutor", "version": self.VERSION, "accepted": True,
                    "executed": False, "status": "DRY_RUN", "authorization": "NOT_GRANTED",
                    "real_world_effect": False, "fail_closed": True}
        if req.mode != self.mode or capability is None:
            return self._deny("MODE_BOUND_CAPABILITY_REQUIRED")
        record: dict[str, Any] | None = None
        target: Path | None = None
        consumed: dict[str, Any] | None = None
        try:
            consumed = self.issuer.consume(capability, req)
            effect_auth = {
                "production_authorization": consumed.get("production_authorization", "NOT_GRANTED"),
                "lab_authorization": consumed.get("lab_authorization", "QUARANTINE_CAPABILITY_CONSUMED"),
            }
            existing = self.vault.find_by_idempotency(req.idempotency_key)
            if existing is not None:
                try:
                    same_target = Path(existing.get("original_path", "")).expanduser().resolve() == Path(req.target).expanduser().resolve()
                except (OSError, RuntimeError, ValueError):
                    same_target = False
                try:
                    same_root = Path(existing.get("approved_root", "")).expanduser().resolve() == self.approved_root
                except (OSError, RuntimeError, ValueError):
                    same_root = False
                if (existing.get("target_sha256") != req.target_sha256
                        or existing.get("incident_id") != req.incident_id
                        or not same_root
                        or not same_target):
                    return self._deny("DUPLICATE_IDEMPOTENCY_CONFLICT")
                requested_attribution = req.attribution()
                if any(existing.get(key) != value for key, value in requested_attribution.items()):
                    return self._deny("DUPLICATE_ATTRIBUTION_CONFLICT")
                if existing.get("state") != "QUARANTINED":
                    return self._deny("AMBIGUOUS_EXISTING_RECORD")
                verification = self.verifier.verify(existing["quarantine_id"], original_path=req.target,
                                                    approved_root=str(self.approved_root), target_sha256=req.target_sha256,
                                                    evidence_ref=req.evidence_ref, decision_digest=req.decision_digest)
                if verification.get("verified") is not True:
                    return self._deny("DUPLICATE_NOT_VERIFIED")
                return dict(verification, accepted=True, executed=False, status="ALREADY_QUARANTINED", idempotent_reuse=True)
            target, failure = self._safe_target(req)
            if failure:
                return self._deny(failure)
            identity_before = self.vault.file_identity(target)
            actual_hash, size, raw = self._hash(target)
            identity_after_read = self.vault.file_identity(target)
            if identity_before != identity_after_read:
                return self._deny("TARGET_CHANGED_DURING_CAPTURE")
            if actual_hash != req.target_sha256:
                return self._deny("TARGET_HASH_MISMATCH")
            self.vault.ensure_capacity(size)
            evidence = self.vault.capture_evidence(raw, reason="LAB_CANARY_QUARANTINE", source="BoundedQuarantineExecutor", event_id=req.event_id or req.incident_id)
            if not self.vault.evidence_vault.verify_evidence(evidence["quarantine_id"]):
                return self._deny("EVIDENCE_NOT_VERIFIED")
            record = self.vault.begin(incident_id=req.incident_id, idempotency_key=req.idempotency_key,
                                      requested_action="QUARANTINE",
                                      original_path=str(target), approved_root=str(self.approved_root), target_sha256=actual_hash,
                                      target_size=size, requester=req.requester, evidence=evidence,
                                      source_identity=identity_after_read, evidence_ref=req.evidence_ref,
                                      decision_digest=req.decision_digest, capability_id=consumed["capability_id"],
                                      scope_digest=consumed["scope_digest"], attribution=req.attribution(),
                                      production_authorization=consumed.get("production_authorization", "NOT_GRANTED"),
                                      lab_authorization=consumed.get("lab_authorization", "QUARANTINE_CAPABILITY_CONSUMED"),
                                      authorization_policy_id=consumed.get("policy_id"))
            final = self.vault.contain(record, target)
            if final.get("state") != "QUARANTINED":
                if final.get("state") in {"FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT"}:
                    return self._after_effect(final.get("failure_code", "CONTAINMENT_POST_EFFECT_FAILURE"),
                                              quarantine_id=final.get("quarantine_id"), state=final["state"],
                                              capability_id=consumed["capability_id"], scope_digest=consumed["scope_digest"],
                                              **effect_auth)
                return self._deny(final.get("failure_code", "CONTAINMENT_FAILED"))
            verification = self.verifier.verify(final["quarantine_id"], original_path=str(target),
                                                approved_root=str(self.approved_root), target_sha256=actual_hash,
                                                evidence_ref=req.evidence_ref, decision_digest=req.decision_digest)
            if verification.get("verified") is not True:
                failed = self.vault.mark_after_effect_failure(final["quarantine_id"], "POST_ACTION_UNVERIFIED")
                return self._after_effect(failed.get("failure_code", "POST_ACTION_UNVERIFIED"),
                                          quarantine_id=final["quarantine_id"], state=failed.get("state", "UNKNOWN_AFTER_EFFECT"),
                                          capability_id=consumed["capability_id"], scope_digest=consumed["scope_digest"],
                                          **effect_auth)
            try:
                execution_completed_at = time.time()
                execution_latency_ms = (time.perf_counter_ns() - execution_started_ns) / 1_000_000.0
                final = self.vault.mark_verified(
                    final["quarantine_id"],
                    verification_outcome=str(verification.get("verification_outcome") or "QUARANTINED_VERIFIED"),
                    execution_started_at=execution_started_at,
                    execution_completed_at=execution_completed_at,
                    execution_latency_ms=execution_latency_ms,
                )
            except (QuarantineVaultError, OSError, ValueError):
                failed = self.vault.mark_after_effect_failure(final["quarantine_id"], "VERIFICATION_RECORD_WRITE_FAILURE")
                return self._after_effect(failed.get("failure_code", "VERIFICATION_RECORD_WRITE_FAILURE"),
                                          quarantine_id=final["quarantine_id"], state=failed.get("state", "UNKNOWN_AFTER_EFFECT"),
                                          capability_id=consumed["capability_id"], scope_digest=consumed["scope_digest"],
                                          **effect_auth)
            self.executions += 1
            return {"component": "BoundedQuarantineExecutor", "version": self.VERSION, "accepted": True,
                    "executed": True, "status": "QUARANTINED", "quarantine_id": final["quarantine_id"],
                    "target_sha256": actual_hash, "requested_action": "QUARANTINE",
                    "verification": verification,
                    "authorization": consumed.get("production_authorization", "NOT_GRANTED"),
                    "production_authorization": consumed.get("production_authorization", "NOT_GRANTED"),
                    "lab_authorization": consumed.get("lab_authorization", "QUARANTINE_CAPABILITY_CONSUMED"),
                    "authorization_policy_id": consumed.get("policy_id"),
                    "capability_id": consumed["capability_id"], "scope_digest": consumed["scope_digest"],
                    "execution_started_at": execution_started_at,
                    "execution_completed_at": execution_completed_at,
                    "execution_latency_ms": round(execution_latency_ms, 3),
                    "real_world_effect": True, "fail_closed": True}
        except (QuarantineContractError, QuarantineVaultError, OSError, ValueError):
            if record is not None and target is not None and not target.exists():
                return self._after_effect("QUARANTINE_POST_EFFECT_FAILURE", quarantine_id=record.get("quarantine_id"),
                                          capability_id=(consumed or {}).get("capability_id"),
                                          scope_digest=(consumed or {}).get("scope_digest"),
                                          production_authorization=(consumed or {}).get("production_authorization", "NOT_GRANTED"),
                                          lab_authorization=(consumed or {}).get("lab_authorization", "QUARANTINE_CAPABILITY_CONSUMED"))
            return self._deny("QUARANTINE_DENIED")

    def _safe_restore_destination(self, request: RestoreRequest, record: dict[str, Any]) -> tuple[Path, str | None]:
        root = self._resolved(request.approved_root)
        target = self._resolved(request.target)
        if root is None or root != self.approved_root:
            return Path(), "RESTORE_ROOT_MISMATCH"
        if target is None:
            return Path(), "RESTORE_TARGET_UNRESOLVED"
        try:
            target.relative_to(root)
            if target != Path(str(record.get("original_path", ""))).expanduser().resolve(strict=False):
                return Path(), "RESTORE_ORIGINAL_PATH_MISMATCH"
            if target.exists() or target.is_symlink():
                return Path(), "RESTORE_DESTINATION_EXISTS"
            if not target.parent.is_dir() or self.vault._has_reparse_component(target.parent):
                return Path(), "RESTORE_PARENT_INVALID"
        except (QuarantineVaultError, OSError, RuntimeError, ValueError):
            return Path(), "RESTORE_DESTINATION_INVALID"
        if not self._marker_valid():
            return Path(), "DEDICATED_CANARY_ROOT_REQUIRED"
        if self._protected_path(target):
            return Path(), "PROTECTED_PATH_DENIED"
        if target == root / CANARY_MARKER_FILENAME:
            return Path(), "CANARY_MARKER_DENIED"
        return target, None

    def restore(self, request: RestoreRequest | dict[str, Any] | str, capability: Any = None, **legacy: Any) -> dict[str, Any]:
        """Restore one verified lab canary through a single-use capability."""
        if legacy:
            return self._deny("RESTORE_LEGACY_BOOLEAN_AUTHORIZATION_REJECTED")
        restore_started_at = time.time()
        restore_started_ns = time.perf_counter_ns()
        try:
            req = request if isinstance(request, RestoreRequest) else RestoreRequest.from_mapping(request)
        except QuarantineContractError:
            return self._deny("INVALID_RESTORE_REQUEST")
        if self.mode != LAB_CANARY_EXECUTION or capability is None:
            return self._deny("RESTORE_CAPABILITY_REQUIRED")
        try:
            consumed = self.restore_issuer.consume(capability, req)
            record = self.vault.get_verified_record(req.quarantine_id)
            if not isinstance(record, dict) or record.get("state") != "QUARANTINED":
                return self._deny("RESTORE_RECORD_NOT_QUARANTINED")
            if (
                record.get("incident_id") != req.incident_id
                or record.get("target_sha256") != req.target_sha256
                or req.idempotency_key != f"{req.quarantine_id}:restore"
            ):
                return self._deny("RESTORE_SCOPE_MISMATCH")
            destination, failure = self._safe_restore_destination(req, record)
            if failure:
                return self._deny(failure)
            restored = self.vault.restore(
                record,
                destination,
                capability_id=consumed["capability_id"],
                scope_digest=consumed["scope_digest"],
                requester=req.requester,
                restore_reason=req.restore_reason,
            )
            if restored.get("state") != "RESTORED":
                if restored.get("state") == "UNKNOWN_AFTER_RESTORE":
                    return self._after_effect(
                        restored.get("failure_code", "RESTORE_POST_EFFECT_FAILURE"),
                        quarantine_id=req.quarantine_id,
                        state="UNKNOWN_AFTER_RESTORE",
                        capability_id=consumed["capability_id"],
                        scope_digest=consumed["scope_digest"],
                    )
                return self._deny(restored.get("failure_code", "RESTORE_FAILED"))
            verification = self.verifier.verify_restore(
                req.quarantine_id,
                original_path=str(destination),
                target_sha256=req.target_sha256,
            )
            if verification.get("verified") is not True:
                failed = self.vault.mark_after_effect_failure(req.quarantine_id, "RESTORE_POST_ACTION_UNVERIFIED")
                return self._after_effect(
                    failed.get("failure_code", "RESTORE_POST_ACTION_UNVERIFIED"),
                    quarantine_id=req.quarantine_id,
                    state=failed.get("state", "UNKNOWN_AFTER_EFFECT"),
                    capability_id=consumed["capability_id"],
                    scope_digest=consumed["scope_digest"],
                )
            restore_completed_at = time.time()
            restore_latency_ms = (time.perf_counter_ns() - restore_started_ns) / 1_000_000.0
            self.vault.mark_restore_verified(
                req.quarantine_id,
                verification_outcome="RESTORED_VERIFIED",
                restore_latency_ms=restore_latency_ms,
            )
            return {
                "component": "BoundedQuarantineExecutor", "version": self.VERSION,
                "accepted": True, "executed": True, "status": "RESTORED",
                "quarantine_id": req.quarantine_id, "incident_id": req.incident_id,
                "target": str(destination), "target_sha256": req.target_sha256,
                "verification": verification,
                "restore_started_at": restore_started_at,
                "restore_completed_at": restore_completed_at,
                "restore_latency_ms": round(restore_latency_ms, 3),
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "RESTORE_CAPABILITY_CONSUMED",
                "capability_id": consumed["capability_id"],
                "scope_digest": consumed["scope_digest"],
                "real_world_effect": True, "recovery_required": False,
                "fail_closed": True,
            }
        except (QuarantineContractError, QuarantineVaultError, OSError, RuntimeError, ValueError):
            return self._deny("RESTORE_DENIED")

    def health_check(self) -> dict[str, Any]:
        vault_health = self.vault.health_check()
        return {"component": "BoundedQuarantineExecutor", "version": self.VERSION,
                "status": "HEALTHY" if vault_health.get("status") == "HEALTHY" else "DEGRADED",
                "mode": self.mode, "executions": self.executions, "rejected": self.rejected,
                "real_world_effect_scope": "ONE_LAB_FILE_ONLY" if self.mode == LAB_CANARY_EXECUTION else "NONE",
                "vault": vault_health, "restore_issuer": self.restore_issuer.health_check(),
                "verifier_process_separate": False,
                "fail_closed": True, "secrets_exported": False}
