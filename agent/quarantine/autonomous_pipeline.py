from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from agent.quarantine.contracts import QuarantineContractError, QuarantineRequest


class AutonomousQuarantinePipeline:
    """Bind signed production policy, one-time capability and real executor."""

    VERSION = "1.0"

    def __init__(self, issuer: Any, executor: Any) -> None:
        self.issuer = issuer
        self.executor = executor
        self.executed = 0
        self.denied = 0

    def handle(self, request: QuarantineRequest | dict[str, Any], *,
               signed_policy: dict[str, Any], runtime_health: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter_ns()
        try:
            req = request if isinstance(request, QuarantineRequest) else QuarantineRequest.from_mapping(request)
            capability = self.issuer.issue(
                req, signed_policy=signed_policy, runtime_health=runtime_health
            )
            result = self.executor.execute(req, capability)
            if result.get("accepted") is not True or result.get("executed") is not True:
                self.denied += 1
                return result
            verification = result.get("verification")
            if not isinstance(verification, dict) or verification.get("verified") is not True:
                self.denied += 1
                return {
                    "accepted": False,
                    "executed": True,
                    "status": "POST_ACTION_UNVERIFIED",
                    "reason": "INDEPENDENT_VERIFICATION_REQUIRED",
                    "recovery_required": True,
                    "fail_closed": True,
                }
            response_latency_ms = (time.perf_counter_ns() - started) / 1_000_000.0
            self.executed += 1
            return dict(
                result,
                status="VERIFIED_QUARANTINED",
                target=req.target,
                target_name=Path(req.target).name,
                incident_id=req.incident_id,
                event_id=req.event_id,
                evidence_ref=req.evidence_ref,
                detection_types=list(req.detection_types),
                risk_score=req.risk_score,
                risk_level=req.risk_level,
                policy_outcome=req.policy_outcome,
                policy_reason=req.policy_reason,
                verifier_outcome=req.verifier_outcome,
                verification_outcome=verification.get("verification_outcome"),
                receipt_integrity=True,
                post_action_verification=True,
                response_latency_ms=round(response_latency_ms, 3),
                detection_to_response_ms=round(response_latency_ms, 3),
            )
        except QuarantineContractError as exc:
            self.denied += 1
            return {
                "component": "AutonomousQuarantinePipeline",
                "version": self.VERSION,
                "accepted": False,
                "executed": False,
                "status": "DENIED",
                "reason": type(exc).__name__,
                "authorization": "NOT_GRANTED",
                "fail_closed": True,
            }
