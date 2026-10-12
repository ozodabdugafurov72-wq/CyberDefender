from __future__ import annotations

"""Run the bounded detection, quarantine, verification, and restore acceptance path."""

import argparse
import hashlib
import json
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from agent.attack_graph import AttackGraph
from agent.correlation.engine import CorrelationEngine
from agent.detection.detector import Detector
from agent.detection.rules import RuleEngine
from agent.independent_verifier import IndependentVerifier
from agent.policy_engine import PolicyEngine
from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    LAB_CANARY_EXECUTION,
    LabQuarantineCoordinator,
    QuarantineCapabilityIssuer,
    RestoreCapabilityIssuer,
    RestoreRequest,
)
from agent.risk_engine import RiskEngine
from agent.safety import SafetyCore
from control_plane.xdr_compat import RESPONSE_EVIDENCE_SCHEMA, validate_response_evidence
from dashboard_owner.quarantine_read_model import QuarantineReadModel

RESPONSE_SLO_MS = 1_000.0
RESTORE_SLO_MS = 1_000.0


def _owner_detail(vault_root: Path, quarantine_id: str) -> dict[str, Any]:
    previous = QuarantineReadModel.APPROVED_VAULTS
    try:
        QuarantineReadModel.APPROVED_VAULTS = (("acceptance", vault_root),)
        result = QuarantineReadModel(vault_root).detail(quarantine_id)
    finally:
        QuarantineReadModel.APPROVED_VAULTS = previous
    if not isinstance(result, dict):
        raise RuntimeError("owner read model did not return verified evidence")
    return result


def run_acceptance() -> dict[str, Any]:
    raw = b"CyberDefender harmless restricted response acceptance canary\n"
    with tempfile.TemporaryDirectory(prefix="CyberDefender-Response-Acceptance-") as temporary:
        base = Path(temporary)
        canary_root = base / "canary-root"
        vault_root = base / "vault"
        canary_root.mkdir()
        (canary_root / CANARY_MARKER_FILENAME).write_bytes(CANARY_MARKER.encode("utf-8"))
        target = canary_root / "harmless-response-canary.txt"
        target.write_bytes(raw)
        target_sha256 = hashlib.sha256(raw).hexdigest()

        quarantine_issuer = QuarantineCapabilityIssuer()
        restore_issuer = RestoreCapabilityIssuer()
        safety = SafetyCore()
        vault = BoundedQuarantineVault(vault_root, max_records=8, max_bytes=2 * 1024 * 1024)
        executor = BoundedQuarantineExecutor(
            vault,
            quarantine_issuer,
            approved_root=canary_root,
            restore_issuer=restore_issuer,
        )
        coordinator = LabQuarantineCoordinator(
            detector=Detector(RuleEngine()),
            correlation_engine=CorrelationEngine(),
            risk_engine=RiskEngine(),
            attack_graph=AttackGraph(),
            policy_engine=PolicyEngine(),
            independent_verifier=IndependentVerifier(),
            safety=safety,
            issuer=quarantine_issuer,
            executor=executor,
            approved_root=canary_root,
        )

        event_id = "acceptance-" + uuid.uuid4().hex
        observed_at = time.time()
        quarantine = coordinator.run(
            {
                "event_type": "HOST_SNAPSHOT",
                "event_id": event_id,
                "timestamp": observed_at,
                "data": {
                    "memory_percent": 99.0,
                    "tenant_id": "restricted-lab-tenant",
                    "endpoint_id": "restricted-lab-endpoint",
                    "target": str(target),
                    "approved_root": str(canary_root),
                    "execution_mode": LAB_CANARY_EXECUTION,
                    "lab_canary": True,
                    "requested_action": "QUARANTINE",
                    "evidence_ref": "evidence://" + event_id,
                },
            },
            operator_approved=True,
        )
        if quarantine.get("accepted") is not True or quarantine.get("status") != "VERIFIED_QUARANTINED":
            raise RuntimeError("verified quarantine acceptance failed")
        if target.exists():
            raise RuntimeError("source remained present after quarantine")
        quarantine_id = str(quarantine.get("quarantine_id") or "")
        record = vault.get_verified_record(quarantine_id)
        if not isinstance(record, dict):
            raise RuntimeError("quarantine record unavailable")
        if not vault.verify_object(record) or not vault.verify_receipt(quarantine_id, record):
            raise RuntimeError("quarantine object or receipt integrity failed")
        contained_owner = _owner_detail(vault_root, quarantine_id)
        source_removed_after_quarantine = not target.exists()
        if contained_owner.get("post_action_verification") is not True:
            raise RuntimeError("owner containment evidence is not verified")

        eligibility = executor.verifier.verify_restore_eligibility(quarantine_id)
        restore_request = RestoreRequest.from_mapping(
            {
                "quarantine_id": quarantine_id,
                "incident_id": record["incident_id"],
                "idempotency_key": f"{quarantine_id}:restore",
                "target": record["original_path"],
                "approved_root": record["approved_root"],
                "target_sha256": record["target_sha256"],
                "requester": "local-lab-operator",
                "restore_reason": "LAB_CANARY_RESET",
            }
        )
        restore_capability = restore_issuer.issue(
            restore_request,
            eligibility_verification=eligibility,
            safety=safety,
            operator_approved=True,
        )
        restore = executor.restore(restore_request, restore_capability)
        if restore.get("accepted") is not True or restore.get("status") != "RESTORED":
            raise RuntimeError("verified restore acceptance failed")
        if target.read_bytes() != raw:
            raise RuntimeError("restored target differs from original")
        restored_record = vault.get_verified_record(quarantine_id)
        if not isinstance(restored_record, dict):
            raise RuntimeError("restored record unavailable")
        if not vault.verify_restore_receipt(quarantine_id, restored_record):
            raise RuntimeError("restore receipt integrity failed")
        restored_owner = _owner_detail(vault_root, quarantine_id)
        if (
            restored_owner.get("post_action_verification") is not True
            or restored_owner.get("restore_verification_outcome") != "RESTORED_VERIFIED"
        ):
            raise RuntimeError("owner restore evidence is not verified")

        response_latency_ms = float(quarantine["response_latency_ms"])
        execution_latency_ms = float(quarantine["execution_latency_ms"])
        detection_to_response_ms = float(quarantine["detection_to_response_ms"])
        restore_latency_ms = float(restore["restore_latency_ms"])
        cloud_response_evidence = {
            "schema": RESPONSE_EVIDENCE_SCHEMA,
            "evidence_id": quarantine_id + "-restored",
            "incident_id": str(quarantine["incident_id"]),
            "event_id": event_id,
            "target_name": target.name,
            "target_sha256": target_sha256,
            "detection_types": list(quarantine.get("detection_types") or []),
            "risk_score": quarantine.get("risk_score"),
            "risk_level": quarantine.get("risk_level"),
            "policy_outcome": quarantine.get("policy_outcome"),
            "policy_reason": quarantine.get("policy_reason"),
            "verifier_outcome": quarantine.get("verifier_outcome"),
            "action_state": "RESTORED",
            "verification_outcome": "RESTORED_VERIFIED",
            "response_latency_ms": response_latency_ms,
            "execution_latency_ms": execution_latency_ms,
            "detection_to_response_ms": detection_to_response_ms,
            "restore_latency_ms": restore_latency_ms,
            "evidence_ref": quarantine.get("evidence_ref"),
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": "RESTORE_CAPABILITY_CONSUMED",
            "receipt_integrity": True,
            "post_action_verification": True,
        }
        normalized_cloud_evidence = validate_response_evidence(
            cloud_response_evidence, endpoint_id="restricted-lab-endpoint"
        )
        gates = {
            "real_detection_chain": bool(quarantine.get("detection_types")),
            "verified_quarantine": True,
            "source_removed": source_removed_after_quarantine,
            "quarantine_receipt_integrity": bool(contained_owner.get("receipt_integrity")),
            "owner_containment_evidence": bool(contained_owner.get("post_action_verification")),
            "verified_restore": True,
            "restore_receipt_integrity": bool(restored_owner.get("restore_receipt_integrity")),
            "owner_restore_evidence": bool(restored_owner.get("post_action_verification")),
            "content_hash_preserved": hashlib.sha256(target.read_bytes()).hexdigest() == target_sha256,
            "response_slo": response_latency_ms <= RESPONSE_SLO_MS,
            "restore_slo": restore_latency_ms <= RESTORE_SLO_MS,
            "production_authorization_absent": (
                quarantine.get("production_authorization") == "NOT_GRANTED"
                and restore.get("production_authorization") == "NOT_GRANTED"
            ),
            "secrets_not_exported": "token_mac" not in json.dumps(
                {"quarantine": quarantine, "restore": restore, "owner": restored_owner}
            ),
            "cloud_response_contract_valid": normalized_cloud_evidence["endpoint_id"] == "restricted-lab-endpoint",
        }
        passed = all(gates.values())
        return {
            "schema": "cyberdefender.restricted-lab-response-acceptance.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "PASS" if passed else "FAIL",
            "scope": "ONE_HARMLESS_TEMPORARY_LAB_FILE",
            "production_authorization": "NOT_GRANTED",
            "event": {
                "event_id": event_id,
                "endpoint_id": quarantine.get("endpoint_id"),
                "tenant_id": quarantine.get("tenant_id"),
                "detection_types": quarantine.get("detection_types"),
                "risk_score": quarantine.get("risk_score"),
                "risk_level": quarantine.get("risk_level"),
                "policy_outcome": quarantine.get("policy_outcome"),
                "verifier_outcome": quarantine.get("verifier_outcome"),
            },
            "evidence": {
                "quarantine_id": quarantine_id,
                "target_name": target.name,
                "target_sha256": target_sha256,
                "containment_state_before_restore": contained_owner.get("containment_state"),
                "containment_verification": contained_owner.get("verification_outcome"),
                "final_state": restored_owner.get("containment_state"),
                "restore_verification": restored_owner.get("restore_verification_outcome"),
                "pipeline_trace": quarantine.get("pipeline_trace"),
            },
            "cloud_response_evidence": cloud_response_evidence,
            "latency_ms": {
                "detection_to_response": round(detection_to_response_ms, 3),
                "gate_pipeline": round(response_latency_ms, 3),
                "filesystem_executor": round(execution_latency_ms, 3),
                "restore": round(restore_latency_ms, 3),
                "response_slo": RESPONSE_SLO_MS,
                "restore_slo": RESTORE_SLO_MS,
            },
            "gates": gates,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = run_acceptance()
    except Exception as exc:
        report = {
            "schema": "cyberdefender.restricted-lab-response-acceptance.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "FAIL",
            "error": type(exc).__name__,
        }
    payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    print(payload, end="")
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
