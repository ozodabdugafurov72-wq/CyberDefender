from __future__ import annotations

"""Execute one bounded, harmless Quarantine v2 local lab canary."""

import hashlib
import json
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from agent.independent_verifier import IndependentVerifier
from agent.policy_engine import PolicyEngine
from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    LAB_CANARY_EXECUTION,
    QuarantineCapabilityIssuer,
    QuarantineRequest,
)
from agent.safety import SafetyCore


def run_canary() -> dict[str, Any]:
    """Run only inside a fresh temporary lab root and return verified metadata."""
    with tempfile.TemporaryDirectory(prefix="CyberDefender-QuarantineV2-Lab-") as temporary:
        base = Path(temporary)
        canary_root = base / "canary-root"
        vault_root = base / "vault"
        canary_root.mkdir()
        (canary_root / CANARY_MARKER_FILENAME).write_bytes(CANARY_MARKER.encode("utf-8"))
        target = canary_root / "harmless-canary.txt"
        target.write_text("CyberDefender harmless Quarantine v2 lab canary\n", encoding="utf-8")
        target_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

        incident_id = "LAB-QV2-" + uuid.uuid4().hex[:16]
        evidence_ref = f"evidence://{incident_id}"
        risk_result = {
            "assessments": [{
                "incident_id": incident_id,
                "risk_score": 40,
                "risk_level": "MEDIUM",
                "requested_action": "QUARANTINE",
            }]
        }
        safety = SafetyCore()
        production_decision = safety.evaluate("QUARANTINE", path=target)
        if production_decision.get("decision") != "DENY":
            raise RuntimeError("production SafetyCore quarantine path was not denied")
        policy = PolicyEngine().evaluate(risk_result, safety=safety)
        policy_assessment = policy.get("assessments", [None])[0]
        if not isinstance(policy_assessment, dict):
            raise RuntimeError("real PolicyEngine returned no assessment")
        decision_digest = policy_assessment.get("decision_digest")
        if not isinstance(decision_digest, str):
            raise RuntimeError("real PolicyEngine returned no decision digest")

        independent = IndependentVerifier().verify(risk_result, policy, safety=safety)
        verified_assessment = independent.get("assessments", [None])[0]
        if not isinstance(verified_assessment, dict) or independent.get("verified") is not True:
            raise RuntimeError("real IndependentVerifier rejected the lab decision")
        if verified_assessment.get("decision_digest") != decision_digest:
            raise RuntimeError("PolicyEngine/IndependentVerifier decision digest mismatch")

        request = QuarantineRequest.from_mapping({
            "incident_id": incident_id,
            "idempotency_key": f"{incident_id}:quarantine",
            "target": str(target),
            "approved_root": str(canary_root),
            "target_sha256": target_sha256,
            "requester": "local-lab-operator",
            "evidence_ref": evidence_ref,
            "decision_digest": decision_digest,
            "mode": LAB_CANARY_EXECUTION,
        })
        issuer = QuarantineCapabilityIssuer()
        capability = issuer.issue(
            request,
            policy_result=policy,
            verification_result=independent,
            safety=safety,
            operator_approved=True,
        )
        vault = BoundedQuarantineVault(vault_root, max_records=8, max_bytes=2 * 1024 * 1024)
        executor = BoundedQuarantineExecutor(vault, issuer, approved_root=canary_root)
        result = executor.execute(request, capability)
        if result.get("status") != "QUARANTINED" or result.get("accepted") is not True:
            raise RuntimeError(f"lab quarantine did not complete: {result.get('reason', result.get('status'))}")
        if target.exists():
            raise RuntimeError("original canary remained accessible")

        quarantine_id = result.get("quarantine_id")
        if not isinstance(quarantine_id, str):
            raise RuntimeError("quarantine id missing")
        record = vault.get_verified_record(quarantine_id)
        if not isinstance(record, dict):
            raise RuntimeError("quarantine record missing")
        evidence_id = record.get("evidence_quarantine_id")
        if not isinstance(evidence_id, str):
            raise RuntimeError("evidence reference missing")
        if not vault.verify_object(record):
            raise RuntimeError("vault object verification failed")
        if not vault.evidence_vault.verify_evidence(evidence_id):
            raise RuntimeError("evidence verification failed")
        if not vault.verify_receipt(quarantine_id, record):
            raise RuntimeError("receipt verification failed")
        if record.get("capability_id") != capability.get("capability_id"):
            raise RuntimeError("capability audit linkage failed")
        if record.get("scope_digest") != capability.get("scope_digest"):
            raise RuntimeError("scope audit linkage failed")
        if record.get("evidence_ref") != evidence_ref or record.get("decision_digest") != decision_digest:
            raise RuntimeError("decision/evidence audit linkage failed")
        if record.get("requested_action") != "QUARANTINE":
            raise RuntimeError("action audit linkage failed")
        if "token_mac" in json.dumps(record) or "token_mac" in json.dumps(result):
            raise RuntimeError("token MAC leaked into lab result")

        object_path = Path(record["object_path"])
        object_sha256 = hashlib.sha256(object_path.read_bytes()).hexdigest()
        return {
            "status": "VERIFIED_QUARANTINED",
            "incident_id": incident_id,
            "capability_id": capability["capability_id"],
            "target_sha256": target_sha256,
            "object_sha256": object_sha256,
            "evidence_quarantine_id": evidence_id,
            "quarantine_id": quarantine_id,
            "production_authorization": result.get("production_authorization"),
            "production_safety_decision": production_decision.get("decision"),
            "lab_authorization": result.get("lab_authorization"),
            "verification_outcome": result["verification"].get("verification_outcome"),
            "original_present": target.exists(),
            "vault_object_verified": True,
            "evidence_verified": True,
            "receipt_verified": True,
        }


def main() -> int:
    try:
        print(json.dumps(run_canary(), sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "LAB_CANARY_FAILED", "error": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
