from __future__ import annotations

"""Explicit service-driven bridge for one bounded Quarantine v2 lab canary.

The coordinator is deliberately constructed by a lab caller.  It is not wired
into the normal service loop and it has no production authorization path.  A
caller must provide the real detector, correlation, risk, policy, verifier,
SafetyCore, capability issuer, and bounded executor instances.
"""

import hashlib
import time
from pathlib import Path
from typing import Any

from agent.quarantine.contracts import (
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    LAB_CANARY_EXECUTION,
    QuarantineCapabilityIssuer,
    QuarantineRequest,
)
from agent.quarantine.executor import BoundedQuarantineExecutor
from agent.quarantine.v2_vault import BoundedQuarantineVault


class LabQuarantineCoordinator:
    """Run one explicitly approved, harmless lab event through real gates."""

    VERSION = "1.0"
    MAX_EVENT_ID = 256
    MAX_EVIDENCE_REF = 256
    TRACE = (
        "TELEMETRY",
        "DETECTION",
        "CORRELATION",
        "RISK",
        "POLICY",
        "INDEPENDENT_VERIFIER",
        "SAFETY_CORE_LAB_AUTHORIZATION",
        "CAPABILITY_ISSUER",
        "BOUNDED_QUARANTINE_EXECUTOR",
        "QUARANTINE_INDEPENDENT_VERIFIER",
    )

    def __init__(
        self,
        *,
        detector: Any,
        correlation_engine: Any,
        risk_engine: Any,
        attack_graph: Any,
        policy_engine: Any,
        independent_verifier: Any,
        safety: Any,
        issuer: QuarantineCapabilityIssuer,
        executor: BoundedQuarantineExecutor,
        approved_root: str | Path,
        requester: str = "local-lab-operator",
    ) -> None:
        required = {
            "detector": detector,
            "correlation_engine": correlation_engine,
            "risk_engine": risk_engine,
            "attack_graph": attack_graph,
            "policy_engine": policy_engine,
            "independent_verifier": independent_verifier,
            "safety": safety,
            "issuer": issuer,
            "executor": executor,
        }
        if any(value is None for value in required.values()):
            raise ValueError("all real pipeline components are required")
        root = self._resolve(approved_root)
        if root is None:
            raise ValueError("approved_root must resolve")
        executor_root = self._resolve(getattr(executor, "approved_root", None))
        if executor_root is None or executor_root != root:
            raise ValueError("coordinator and executor approved roots must match")
        requester = self._text(requester, "requester", 128)
        self.detector = detector
        self.correlation_engine = correlation_engine
        self.risk_engine = risk_engine
        self.attack_graph = attack_graph
        self.policy_engine = policy_engine
        self.independent_verifier = independent_verifier
        self.safety = safety
        self.issuer = issuer
        self.executor = executor
        self.approved_root = root
        self.requester = requester
        self.runs = 0
        self.successes = 0
        self.denied = 0

    @staticmethod
    def _text(value: Any, field: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be string")
        value = value.strip()
        if not value or len(value) > maximum:
            raise ValueError(f"invalid {field}")
        return value

    @staticmethod
    def _resolve(value: Any) -> Path | None:
        try:
            if value is None:
                return None
            return Path(value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

    def _failure(
        self,
        stage: str,
        reason: str,
        *,
        event_id: str | None = None,
        incident_id: str | None = None,
        target: str | None = None,
        target_sha256: str | None = None,
        endpoint_id: str | None = None,
        tenant_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        self.denied += 1
        return {
            "component": "LabQuarantineCoordinator",
            "version": self.VERSION,
            "accepted": False,
            "status": "DENIED",
            "stage": stage,
            "reason": reason,
            "event_id": event_id,
            "incident_id": incident_id,
            "endpoint_id": endpoint_id,
            "tenant_id": tenant_id,
            "target": target,
            "target_sha256": target_sha256,
            "evidence_ref": evidence_ref,
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": "NOT_GRANTED",
            "real_world_effect": False,
            "fail_closed": True,
            "pipeline_trace": list(self.TRACE),
        }

    def _validate_scope(self, data: dict[str, Any]) -> tuple[Path, Path, str, str, str] | tuple[None, ...]:
        if data.get("lab_canary") is not True:
            return (None, None, "LAB_CANARY_MARKER_REQUIRED", "", "")
        if data.get("execution_mode") != LAB_CANARY_EXECUTION:
            return (None, None, "LAB_EXECUTION_MODE_REQUIRED", "", "")
        if data.get("requested_action") != "QUARANTINE":
            return (None, None, "QUARANTINE_ACTION_REQUIRED", "", "")
        root = self._resolve(data.get("approved_root"))
        target = self._resolve(data.get("target"))
        if root is None or root != self.approved_root:
            return (None, None, "APPROVED_ROOT_MISMATCH", "", "")
        if target is None:
            return (None, None, "TARGET_UNRESOLVED", "", "")
        try:
            target.relative_to(root)
        except ValueError:
            return (None, None, "TARGET_OUTSIDE_APPROVED_ROOT", "", "")
        try:
            if BoundedQuarantineVault._has_reparse_component(target):
                return (None, None, "TARGET_REPARSE_OR_SYMLINK", "", "")
            marker = root / CANARY_MARKER_FILENAME
            if (
                not root.is_dir()
                or root.is_symlink()
                or not marker.is_file()
                or marker.is_symlink()
                or marker.read_bytes() != CANARY_MARKER.encode("utf-8")
                or target == marker
                or not target.is_file()
            ):
                return (None, None, "DEDICATED_CANARY_ROOT_REQUIRED", "", "")
            if target.suffix.lower() in self.executor.FORBIDDEN_SUFFIXES:
                return (None, None, "PROTECTED_EXECUTABLE_TYPE", "", "")
            if self.safety.is_protected_path(target) or self.safety.is_protected_path(root):
                return (None, None, "PROTECTED_PATH_DENIED", "", "")
            size = target.stat().st_size
            if size > self.executor.vault.max_target_bytes:
                return (None, None, "TARGET_SIZE_LIMIT", "", "")
            target_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        except (OSError, RuntimeError, ValueError):
            return (None, None, "TARGET_IDENTITY_UNAVAILABLE", "", "")
        supplied_hash = data.get("target_sha256")
        if supplied_hash is not None and supplied_hash != target_sha256:
            return (None, None, "TARGET_HASH_MISMATCH", "", "")
        evidence_ref = data.get("evidence_ref")
        try:
            evidence_ref = self._text(evidence_ref, "evidence_ref", self.MAX_EVIDENCE_REF)
        except ValueError:
            return (None, None, "EVIDENCE_REFERENCE_REQUIRED", "", "")
        return root, target, target_sha256, evidence_ref, ""

    def run(self, telemetry_event: dict[str, Any], *, operator_approved: bool = False) -> dict[str, Any]:
        """Process one marked telemetry event; every failure is fail-closed."""
        started = time.time()
        self.runs += 1
        if operator_approved is not True:
            return self._failure("ADMISSION", "EXPLICIT_OPERATOR_APPROVAL_REQUIRED")
        if not isinstance(telemetry_event, dict) or telemetry_event.get("event_type") not in {
            "HOST_SNAPSHOT", "RESOURCE_STATUS", "PROCESS_SNAPSHOT"
        }:
            return self._failure("ADMISSION", "TELEMETRY_EVENT_REQUIRED")
        event_id = telemetry_event.get("event_id")
        data = telemetry_event.get("data")
        try:
            event_id = self._text(event_id, "event_id", self.MAX_EVENT_ID)
        except ValueError:
            return self._failure("ADMISSION", "EVENT_ID_REQUIRED")
        if not isinstance(data, dict):
            return self._failure("ADMISSION", "TELEMETRY_DATA_REQUIRED", event_id=event_id)
        endpoint_id = data.get("endpoint_id") if isinstance(data.get("endpoint_id"), str) else None
        tenant_id = data.get("tenant_id") if isinstance(data.get("tenant_id"), str) else None
        scope = self._validate_scope(data)
        if scope[0] is None:
            return self._failure(
                "ADMISSION",
                scope[2],
                event_id=event_id,
                endpoint_id=endpoint_id,
                tenant_id=tenant_id,
                target=data.get("target") if isinstance(data.get("target"), str) else None,
            )
        root, target, target_sha256, evidence_ref, _ = scope
        try:
            detections = self.detector.handle_event(telemetry_event)
            if not isinstance(detections, list) or len(detections) != 1 or not isinstance(detections[0], dict):
                return self._failure("DETECTION", "EXACTLY_ONE_CANARY_DETECTION_REQUIRED", event_id=event_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            detection = dict(detections[0])
            detection.update({
                "tenant_id": data.get("tenant_id", "lab-tenant"),
                "host_id": data.get("host_id", endpoint_id),
                "entity_id": str(target),
                "target": str(target),
                "approved_root": str(root),
            })
            detection_event = {
                "event_type": "DETECTION",
                "event_id": event_id,
                "timestamp": telemetry_event.get("timestamp", time.time()),
                "source": "LabQuarantineCoordinator",
                "severity": detection.get("severity", "CRITICAL"),
                "data": detection,
            }
            incident_event = self.correlation_engine.ingest(detection_event, strict=True)
            if not isinstance(incident_event, dict) or incident_event.get("event_type") != "INCIDENT":
                return self._failure("CORRELATION", "INCIDENT_NOT_CREATED", event_id=event_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            incident_id = incident_event.get("incident_id")
            if not isinstance(incident_id, str) or not incident_id.strip():
                return self._failure("CORRELATION", "INCIDENT_ID_MISSING", event_id=event_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            risk = self.risk_engine.assess(self.attack_graph, [incident_event])
            if not isinstance(risk, dict) or not isinstance(risk.get("assessments"), list) or len(risk["assessments"]) != 1:
                return self._failure("RISK", "RISK_ASSESSMENT_REJECTED", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            risk = dict(risk)
            assessment = dict(risk["assessments"][0])
            if assessment.get("incident_id") != incident_id:
                return self._failure("RISK", "RISK_INCIDENT_MISMATCH", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            assessment["requested_action"] = "QUARANTINE"
            risk["assessments"] = [assessment]
            policy = self.policy_engine.evaluate(risk, safety=self.safety)
            if not isinstance(policy, dict) or policy.get("accepted") is not True:
                return self._failure("POLICY", "POLICY_REJECTED", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            policy_item = next((row for row in policy.get("assessments", []) if isinstance(row, dict) and row.get("incident_id") == incident_id), None)
            if not isinstance(policy_item, dict) or policy_item.get("requested_action") != "QUARANTINE" or policy_item.get("policy_outcome") != "REQUIRE_VERIFICATION":
                return self._failure("POLICY", "LAB_QUARANTINE_REQUIRES_VERIFICATION", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            verification = self.independent_verifier.verify(risk, policy, safety=self.safety)
            verified_item = next((row for row in verification.get("assessments", []) if isinstance(row, dict) and row.get("incident_id") == incident_id), None) if isinstance(verification, dict) else None
            decision_digest = policy_item.get("decision_digest")
            if (
                not isinstance(verification, dict)
                or verification.get("accepted") is not True
                or verification.get("verified") is not True
                or not isinstance(verified_item, dict)
                or verified_item.get("decision_digest") != decision_digest
            ):
                return self._failure("INDEPENDENT_VERIFIER", "DECISION_NOT_VERIFIED", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            request = QuarantineRequest.from_mapping({
                "incident_id": incident_id,
                "idempotency_key": f"{incident_id}:quarantine",
                "target": str(target),
                "approved_root": str(root),
                "target_sha256": target_sha256,
                "requester": self.requester,
                "evidence_ref": evidence_ref,
                "decision_digest": decision_digest,
                "mode": LAB_CANARY_EXECUTION,
            })
            safety_attestation = self.safety.authorize_lab_quarantine(request.scope())
            if not isinstance(safety_attestation, dict) or safety_attestation.get("allowed") is not True:
                return self._failure("SAFETY_CORE_LAB_AUTHORIZATION", "LAB_AUTHORIZATION_DENIED", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            capability = self.issuer.issue(
                request,
                policy_result=policy,
                verification_result=verification,
                safety=self.safety,
                operator_approved=True,
            )
            result = self.executor.execute(request, capability)
            if not isinstance(result, dict):
                return self._failure("BOUNDED_QUARANTINE_EXECUTOR", "INVALID_EXECUTOR_RESULT", event_id=event_id, incident_id=incident_id, endpoint_id=endpoint_id, tenant_id=tenant_id)
            verification_result = result.get("verification") if isinstance(result.get("verification"), dict) else {}
            output = {
                "component": "LabQuarantineCoordinator",
                "version": self.VERSION,
                "accepted": result.get("accepted") is True and result.get("status") == "QUARANTINED",
                "status": "VERIFIED_QUARANTINED" if result.get("status") == "QUARANTINED" else result.get("status", "DENIED"),
                "event_id": event_id,
                "incident_id": incident_id,
                "endpoint_id": endpoint_id,
                "tenant_id": tenant_id,
                "target": str(target),
                "target_sha256": target_sha256,
                "risk_result": risk,
                "policy_decision": policy,
                "independent_verification": verification,
                "decision_digest": decision_digest,
                "capability_id": result.get("capability_id"),
                "scope_digest": result.get("scope_digest"),
                "quarantine_id": result.get("quarantine_id"),
                "evidence_ref": evidence_ref,
                "containment_state": result.get("status"),
                "verification_outcome": verification_result.get("verification_outcome"),
                "production_authorization": result.get("production_authorization", "NOT_GRANTED"),
                "lab_authorization": result.get("lab_authorization", "NOT_GRANTED"),
                "real_world_effect": result.get("real_world_effect"),
                "recovery_required": result.get("recovery_required", False),
                "pipeline_trace": list(self.TRACE),
                "started_at": started,
                "completed_at": time.time(),
                "fail_closed": True,
            }
            if output["accepted"]:
                self.successes += 1
            else:
                self.denied += 1
            return output
        except Exception as exc:
            return self._failure("PIPELINE", type(exc).__name__, event_id=event_id, endpoint_id=endpoint_id, tenant_id=tenant_id)

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "LabQuarantineCoordinator",
            "version": self.VERSION,
            "status": "HEALTHY",
            "mode": LAB_CANARY_EXECUTION,
            "runs": self.runs,
            "successes": self.successes,
            "denied": self.denied,
            "production_authorization": "NOT_GRANTED",
            "fail_closed": True,
        }
