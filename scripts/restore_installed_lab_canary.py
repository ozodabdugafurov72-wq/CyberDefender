from __future__ import annotations

"""Restore one verified installed-Agent LAB canary and publish signed evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from agent.fleet.client import FleetTelemetryClient
from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    QuarantineCapabilityIssuer,
    RestoreCapabilityIssuer,
    RestoreRequest,
)
from agent.safety import SafetyCore
from agent.windows_service import configure_machine_environment
from control_plane.xdr_compat import RESPONSE_EVIDENCE_SCHEMA, validate_response_evidence


LAB_ROOT = Path(r"C:\CD\LAB\LiveRansomwareTest")
VAULT_ROOT = Path(r"C:\CD\LAB\LiveRansomwareVault")
EVIDENCE_ROOT = Path(r"C:\CD\EVIDENCE")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _restored_evidence(record: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "schema": RESPONSE_EVIDENCE_SCHEMA,
        "evidence_id": str(record["quarantine_id"]) + "-restored",
        "incident_id": record["incident_id"],
        "event_id": record["event_id"],
        "target_name": Path(record["original_path"]).name,
        "target_sha256": record["target_sha256"],
        "detection_types": record["detection_types"],
        "risk_score": record["risk_score"],
        "risk_level": record["risk_level"],
        "policy_outcome": record["policy_outcome"],
        "policy_reason": record["policy_reason"],
        "verifier_outcome": record["verifier_outcome"],
        "action_state": "RESTORED",
        "verification_outcome": "RESTORED_VERIFIED",
        "response_latency_ms": record["response_latency_ms"],
        "execution_latency_ms": record["execution_latency_ms"],
        "detection_to_response_ms": record["detection_to_response_ms"],
        "restore_latency_ms": result["restore_latency_ms"],
        "evidence_ref": record["evidence_ref"],
        "production_authorization": "NOT_GRANTED",
        "lab_authorization": "RESTORE_CAPABILITY_CONSUMED",
        "receipt_integrity": True,
        "post_action_verification": True,
    }
    validate_response_evidence(evidence, endpoint_id=str(record["endpoint_id"]))
    return evidence


def restore_canary(quarantine_id: str) -> dict[str, Any]:
    if not quarantine_id.startswith("qv2-") or len(quarantine_id) > 128:
        raise ValueError("invalid quarantine id")
    paths = configure_machine_environment()
    vault = BoundedQuarantineVault(VAULT_ROOT, max_records=16, max_bytes=16 * 1024 * 1024)
    restore_issuer = RestoreCapabilityIssuer()
    executor = BoundedQuarantineExecutor(
        vault,
        QuarantineCapabilityIssuer(),
        approved_root=LAB_ROOT,
        restore_issuer=restore_issuer,
    )
    record = vault.get_verified_record(quarantine_id)
    if not isinstance(record, dict) or record.get("state") != "QUARANTINED":
        raise RuntimeError("verified quarantined record not found")
    if Path(str(record.get("approved_root"))).resolve() != LAB_ROOT.resolve():
        raise RuntimeError("record is outside fixed LAB root")
    target = Path(str(record.get("original_path")))
    if target.exists() or target.is_symlink():
        raise RuntimeError("restore destination is not empty")

    eligibility = executor.verifier.verify_restore_eligibility(quarantine_id)
    request = RestoreRequest.from_mapping(
        {
            "quarantine_id": quarantine_id,
            "incident_id": record["incident_id"],
            "idempotency_key": f"{quarantine_id}:restore",
            "target": record["original_path"],
            "approved_root": record["approved_root"],
            "target_sha256": record["target_sha256"],
            "requester": "CyberDefender-Authorized-LAB-Restore",
            "restore_reason": "GOLDEN_PATH_CANARY_RESET",
        }
    )

    unauthorized = executor.restore(request, None)
    if unauthorized.get("accepted") is not False or target.exists():
        raise RuntimeError("unauthorized restore negative control failed")

    safety = SafetyCore()
    capability = restore_issuer.issue(
        request,
        eligibility_verification=eligibility,
        safety=safety,
        operator_approved=True,
    )
    outside_target = Path(r"C:\CD\LAB\LiveRansomwareOutside\blocked-restore.txt")
    outside_request = RestoreRequest.from_mapping(
        {
            "quarantine_id": quarantine_id,
            "incident_id": record["incident_id"],
            "idempotency_key": f"{quarantine_id}:restore",
            "target": str(outside_target),
            "approved_root": record["approved_root"],
            "target_sha256": record["target_sha256"],
            "requester": "CyberDefender-Authorized-LAB-Restore",
            "restore_reason": "GOLDEN_PATH_SCOPE_NEGATIVE_CONTROL",
        }
    )
    outside = executor.restore(outside_request, capability)
    if outside.get("accepted") is not False or outside_target.exists():
        raise RuntimeError("out-of-scope restore negative control failed")

    result = executor.restore(request, capability)
    if result.get("accepted") is not True or result.get("status") != "RESTORED":
        raise RuntimeError("authorized restore failed")
    if _sha256(target) != record["target_sha256"]:
        raise RuntimeError("restored content hash mismatch")
    restored_record = vault.get_verified_record(quarantine_id)
    if not isinstance(restored_record, dict):
        raise RuntimeError("restored record unavailable")
    if not vault.verify_restore_receipt(quarantine_id, restored_record):
        raise RuntimeError("restore receipt integrity failed")

    replay = executor.restore(request, capability)
    if replay.get("accepted") is not False:
        raise RuntimeError("restore capability replay was accepted")

    evidence = _restored_evidence(restored_record, result)
    client = FleetTelemetryClient(
        str(os.environ["CYBERDEFENDER_DISTRIBUTION_URL"]),
        Path(os.environ["CYBERDEFENDER_FLEET_TOKEN_FILE"]),
        paths["endpoint_id"],
        timeout=5.0,
    )
    cloud_accepted = False
    for attempt in range(3):
        if client.publish_response_evidence(evidence, runtime_version="2.4"):
            cloud_accepted = True
            break
        if attempt < 2:
            time.sleep(1.0)
    if not cloud_accepted:
        raise RuntimeError("signed restored evidence was not accepted")

    report = {
        "schema": "cyberdefender.installed-lab-restore.v1",
        "status": "RESTORED_VERIFIED",
        "quarantine_id": quarantine_id,
        "incident_id": restored_record["incident_id"],
        "event_id": restored_record["event_id"],
        "endpoint_id": restored_record["endpoint_id"],
        "target_name": target.name,
        "target_sha256": restored_record["target_sha256"],
        "restored_sha256": _sha256(target),
        "restore_latency_ms": result["restore_latency_ms"],
        "unauthorized_restore_rejected": True,
        "out_of_scope_restore_rejected": True,
        "replay_rejected": True,
        "restore_receipt_integrity": True,
        "cloud_evidence_accepted": True,
        "production_authorization": "NOT_GRANTED",
        "lab_authorization": "RESTORE_CAPABILITY_CONSUMED",
    }
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    evidence_path = EVIDENCE_ROOT / f"installed-restore-{int(time.time())}.json"
    evidence_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    report["evidence_path"] = str(evidence_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--quarantine-id", required=True)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "reason": "--execute required"}))
        return 2
    try:
        print(json.dumps(restore_canary(args.quarantine_id), sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "RESTORE_FAILED", "error": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
