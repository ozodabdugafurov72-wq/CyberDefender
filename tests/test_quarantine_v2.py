from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    DRY_RUN_ONLY,
    LAB_CANARY_EXECUTION,
    QuarantineCapabilityIssuer,
    QuarantineContractError,
    QuarantineRequest,
    canonical_scope_digest,
)
from agent.quarantine.v2_vault import QuarantineVaultError
from agent.independent_verifier import IndependentVerifier
from agent.policy_engine import PolicyEngine
from agent.safety_authorization_gate import SafetyAuthorizationGate


class LabSafety:
    def __init__(self) -> None:
        self.allowed = True
        self.scope_digest_override: str | None = None

    def health_snapshot(self) -> dict[str, object]:
        return {"safe_mode": False, "shutdown_requested": False}

    def authorize_lab_quarantine(self, scope: dict[str, str]) -> dict[str, object]:
        return {"allowed": self.allowed, "mode": LAB_CANARY_EXECUTION,
                "scope_digest": self.scope_digest_override or canonical_scope_digest(scope),
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED"}


def decision_evidence(incident_id: str, digest: str) -> tuple[dict[str, object], dict[str, object]]:
    row = {"incident_id": incident_id, "requested_action": "QUARANTINE", "decision_digest": digest}
    return (
        {"accepted": True, "policy_outcome": "REQUIRE_VERIFICATION", "authorization": "NOT_GRANTED",
         "action": "OBSERVE_ONLY", "assessments": [dict(row)]},
        {"accepted": True, "verified": True, "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
         "assessments": [dict(row)]},
    )


class QuarantineV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cd-quarantine-v2-")
        self.root = Path(self.temp.name) / "canary"
        self.root.mkdir()
        (self.root / CANARY_MARKER_FILENAME).write_bytes(CANARY_MARKER.encode("utf-8"))
        self.vault = BoundedQuarantineVault(Path(self.temp.name) / "vault", max_records=4, max_bytes=4096, max_target_bytes=512)
        self.issuer = QuarantineCapabilityIssuer()
        self.executor = BoundedQuarantineExecutor(self.vault, self.issuer, approved_root=self.root)
        self.safety = LabSafety()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _request(self, name: str = "sample.txt", *, mode: str = LAB_CANARY_EXECUTION,
                 key: str = "idem-1") -> QuarantineRequest:
        target = self.root / name
        target.write_text("harmless canary", encoding="utf-8")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        decision = hashlib.sha256(f"decision-{key}".encode()).hexdigest()
        return QuarantineRequest.from_mapping({
            "incident_id": "INC-QV2-1", "idempotency_key": key, "target": str(target),
            "approved_root": str(self.root), "target_sha256": digest, "requester": "operator",
            "evidence_ref": "evidence://INC-QV2-1", "decision_digest": decision, "mode": mode,
        })

    def _request_for_existing_path(self, target: Path, *, key: str,
                                   target_sha256: str | None = None) -> QuarantineRequest:
        digest = target_sha256 or hashlib.sha256(target.read_bytes()).hexdigest()
        decision = hashlib.sha256(f"decision-{key}".encode()).hexdigest()
        return QuarantineRequest.from_mapping({
            "incident_id": "INC-QV2-1", "idempotency_key": key, "target": str(target),
            "approved_root": str(self.root), "target_sha256": digest, "requester": "operator",
            "evidence_ref": "evidence://INC-QV2-1", "decision_digest": decision,
            "mode": LAB_CANARY_EXECUTION,
        })

    def _capability(self, request: QuarantineRequest, *, operator: bool = True) -> dict[str, object]:
        policy, verification = decision_evidence(request.incident_id, request.decision_digest)
        return self.issuer.issue(request, policy_result=policy, verification_result=verification,
                                 safety=self.safety, operator_approved=operator)

    def test_valid_canary_evidence_containment_and_independent_verify(self) -> None:
        request = self._request()
        capability = self._capability(request)
        result = self.executor.execute(request, capability)
        self.assertTrue(result["accepted"])
        self.assertTrue(result["executed"])
        self.assertEqual(result["status"], "QUARANTINED")
        self.assertFalse(Path(request.target).exists())
        self.assertTrue(result["verification"]["verified"])
        self.assertEqual(self.vault.health_check()["status"], "HEALTHY")
        record = self.vault.get_verified_record(result["quarantine_id"])
        self.assertIsNotNone(record)
        self.assertEqual(record["capability_id"], capability["capability_id"])
        self.assertEqual(record["scope_digest"], capability["scope_digest"])
        self.assertEqual(record["requested_action"], "QUARANTINE")
        self.assertEqual(record["decision_digest"], request.decision_digest)
        self.assertEqual(record["evidence_ref"], request.evidence_ref)
        self.assertEqual(result["production_authorization"], "NOT_GRANTED")
        self.assertEqual(result["lab_authorization"], "QUARANTINE_CAPABILITY_CONSUMED")
        self.assertEqual(result["capability_id"], capability["capability_id"])
        serialized = json.dumps(record)
        receipt = (self.vault.receipts_dir / f"{result['quarantine_id']}.json").read_text(encoding="utf-8")
        self.assertNotIn("token_mac", serialized)
        self.assertNotIn("token_mac", receipt)
        self.assertEqual(result["verification"]["decision_digest"], request.decision_digest)
        self.assertEqual(result["verification"]["evidence_ref"], request.evidence_ref)
        with self.assertRaises(QuarantineContractError):
            self.issuer.consume(capability, request)

    def test_real_policy_and_verifier_outputs_remain_fail_closed_for_lab_issuer(self) -> None:
        class SafetyStub:
            def health_snapshot(self) -> dict[str, object]:
                return {"safe_mode": False, "shutdown_requested": False}

            def evaluate(self, action: str, path: object = None) -> dict[str, str]:
                return {"decision": "DENY"}

        risk = {"assessments": [{
            "incident_id": "INC-QV2-1", "risk_score": 40, "risk_level": "MEDIUM",
            "requested_action": "QUARANTINE",
        }]}
        safety = SafetyStub()
        policy = PolicyEngine().evaluate(risk, safety=safety)
        verification = IndependentVerifier().verify(risk, policy, safety=safety)
        self.assertIsInstance(policy["assessments"][0].get("decision_digest"), str)
        self.assertIsInstance(verification["assessments"][0].get("decision_digest"), str)
        self.assertEqual(policy["assessments"][0]["decision_digest"],
                         verification["assessments"][0]["decision_digest"])
        request = replace(self._request(key="real-schema"),
                          decision_digest=verification["assessments"][0]["decision_digest"])
        with self.assertRaises(QuarantineContractError):
            self.issuer.issue(request, policy_result=policy, verification_result=verification,
                              safety=SafetyAuthorizationGate(), operator_approved=True)
        self.assertFalse(hasattr(SafetyAuthorizationGate(), "authorize_lab_quarantine"))

    def test_invalid_expired_reused_and_wrong_scope_capability_denied(self) -> None:
        request = self._request()
        with self.assertRaises(QuarantineContractError):
            self.issuer.issue(request, policy_result={}, verification_result={}, safety=self.safety, operator_approved=False)
        short = QuarantineCapabilityIssuer(ttl_seconds=0.01)
        policy, verification = decision_evidence(request.incident_id, request.decision_digest)
        cap = short.issue(request, policy_result=policy, verification_result=verification, safety=self.safety, operator_approved=True)
        time.sleep(0.03)
        with self.assertRaises(QuarantineContractError):
            short.consume(cap, request)
        cap = self._capability(request)
        wrong = self._request("other.txt", key="other")
        with self.assertRaises(QuarantineContractError):
            self.issuer.consume(cap, wrong)

    def test_safety_policy_and_verification_scope_digests_are_bound(self) -> None:
        request = self._request(key="scope")
        self.safety.scope_digest_override = "0" * 64
        policy, verification = decision_evidence(request.incident_id, request.decision_digest)
        with self.assertRaises(QuarantineContractError):
            self.issuer.issue(request, policy_result=policy, verification_result=verification,
                              safety=self.safety, operator_approved=True)
        self.safety.scope_digest_override = None
        policy, verification = decision_evidence(request.incident_id, request.decision_digest)
        policy["assessments"][0]["decision_digest"] = "1" * 64
        with self.assertRaises(QuarantineContractError):
            self.issuer.issue(request, policy_result=policy, verification_result=verification,
                              safety=self.safety, operator_approved=True)
        policy, verification = decision_evidence(request.incident_id, request.decision_digest)
        verification["assessments"][0]["decision_digest"] = "2" * 64
        with self.assertRaises(QuarantineContractError):
            self.issuer.issue(request, policy_result=policy, verification_result=verification,
                              safety=self.safety, operator_approved=True)

    def test_direct_and_parent_symlink_targets_are_denied_when_supported(self) -> None:
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        direct = self.root / "direct-link.txt"
        try:
            direct.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable on this host")
        direct_request = self._request_for_existing_path(
            direct, key="direct-link", target_sha256=hashlib.sha256(outside.read_bytes()).hexdigest())
        direct_result = self.executor.execute(direct_request, self._capability(direct_request))
        self.assertEqual(direct_result["reason"], "TARGET_REPARSE_OR_SYMLINK")
        outside_dir = Path(self.temp.name) / "outside-dir"
        outside_dir.mkdir()
        nested = outside_dir / "nested.txt"
        nested.write_text("nested", encoding="utf-8")
        parent_link = self.root / "parent-link"
        try:
            parent_link.symlink_to(outside_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation is unavailable on this host")
        parent_request = self._request_for_existing_path(
            parent_link / "nested.txt", key="parent-link",
            target_sha256=hashlib.sha256(nested.read_bytes()).hexdigest())
        parent_result = self.executor.execute(parent_request, self._capability(parent_request))
        self.assertEqual(parent_result["reason"], "TARGET_REPARSE_OR_SYMLINK")

    def test_target_change_between_capture_and_containment_fails_closed(self) -> None:
        request = self._request(key="changed")
        original_contain = self.vault.contain

        def mutate_then_contain(record: dict[str, object], source: Path) -> dict[str, object]:
            source.write_text("substituted target", encoding="utf-8")
            return original_contain(record, source)

        self.vault.contain = mutate_then_contain  # type: ignore[method-assign]
        result = self.executor.execute(request, self._capability(request))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "SOURCE_CHANGED_BEFORE_CONTAINMENT")
        self.assertFalse(result["real_world_effect"])
        self.assertTrue(Path(request.target).exists())

    def test_protected_cyberdefender_runtime_root_is_denied(self) -> None:
        previous = os.environ.get("CYBERDEFENDER_ROOT")
        os.environ["CYBERDEFENDER_ROOT"] = str(self.root)
        try:
            request = self._request(key="runtime")
            result = self.executor.execute(request, self._capability(request))
            self.assertEqual(result["reason"], "PROTECTED_PATH_DENIED")
        finally:
            if previous is None:
                os.environ.pop("CYBERDEFENDER_ROOT", None)
            else:
                os.environ["CYBERDEFENDER_ROOT"] = previous

    def test_outside_root_system_type_vault_and_hash_mismatch_denied(self) -> None:
        executable = self._request("sample.exe", key="exe")
        self.assertEqual(self.executor.execute(executable, self._capability(executable))["reason"], "PROTECTED_EXECUTABLE_TYPE")
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        outside_request = replace(self._request(key="outside"), target=str(outside),
                                  target_sha256=hashlib.sha256(outside.read_bytes()).hexdigest(), idempotency_key="outside")
        self.assertEqual(self.executor.execute(outside_request, self._capability(outside_request))["reason"], "TARGET_OUTSIDE_APPROVED_ROOT")
        target_request = self._request(key="hash")
        bad = replace(target_request, target_sha256="0" * 64)
        self.assertEqual(self.executor.execute(bad, self._capability(bad))["reason"], "TARGET_HASH_MISMATCH")

        vault_file = self.vault.root / "vault-target.txt"
        vault_file.write_text("vault", encoding="utf-8")
        (self.vault.root / CANARY_MARKER_FILENAME).write_bytes(CANARY_MARKER.encode("utf-8"))
        vault_executor = BoundedQuarantineExecutor(self.vault, self.issuer, approved_root=self.vault.root)
        vault_request = replace(self._request(key="vault"), target=str(vault_file), approved_root=str(self.vault.root),
                                target_sha256=hashlib.sha256(vault_file.read_bytes()).hexdigest())
        self.assertEqual(vault_executor.execute(vault_request, self._capability(vault_request))["reason"], "VAULT_PATH_DENIED")

        import os
        old_windir = os.environ.get("WINDIR")
        system_root = Path(self.temp.name) / "fake-windows"
        system_root.mkdir()
        (system_root / CANARY_MARKER_FILENAME).write_bytes(CANARY_MARKER.encode("utf-8"))
        system_file = system_root / "system.txt"
        system_file.write_text("system", encoding="utf-8")
        os.environ["WINDIR"] = str(system_root)
        try:
            system_executor = BoundedQuarantineExecutor(self.vault, self.issuer, approved_root=system_root)
            system_request = replace(self._request(key="system"), target=str(system_file), approved_root=str(system_root),
                                     target_sha256=hashlib.sha256(system_file.read_bytes()).hexdigest())
            self.assertEqual(system_executor.execute(system_request, self._capability(system_request))["reason"], "PROTECTED_PATH_DENIED")
        finally:
            if old_windir is None:
                os.environ.pop("WINDIR", None)
            else:
                os.environ["WINDIR"] = old_windir

    def test_evidence_failure_leaves_original_and_duplicate_is_idempotent(self) -> None:
        request = self._request()
        original = Path(request.target)
        capture = self.vault.capture_evidence
        self.vault.capture_evidence = lambda *args, **kwargs: (_ for _ in ()).throw(QuarantineVaultError("injected"))  # type: ignore[method-assign]
        self.assertFalse(self.executor.execute(request, self._capability(request))["accepted"])
        self.assertTrue(original.exists())
        self.vault.capture_evidence = capture  # type: ignore[method-assign]
        self.assertTrue(self.executor.execute(request, self._capability(request))["accepted"])
        duplicate = self.executor.execute(request, self._capability(request))
        self.assertTrue(duplicate["accepted"])
        self.assertTrue(duplicate["idempotent_reuse"])
        self.assertFalse(original.exists())

    def test_receipt_failure_after_move_is_truthful_and_persisted_health_degrades(self) -> None:
        request = self._request(key="receipt-failure")
        original_atomic = self.vault._atomic_write

        def fail_receipt(path: Path, payload: bytes) -> None:
            if Path(path).parent == self.vault.receipts_dir:
                raise OSError("injected receipt failure")
            original_atomic(path, payload)

        self.vault._atomic_write = fail_receipt  # type: ignore[method-assign]
        result = self.executor.execute(request, self._capability(request))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "FAILED_AFTER_EFFECT")
        self.assertTrue(result["real_world_effect"])
        self.assertTrue(result["recovery_required"])
        self.assertFalse(Path(request.target).exists())
        reopened = BoundedQuarantineVault(self.vault.root, max_records=4, max_bytes=4096, max_target_bytes=512)
        self.assertEqual(reopened.health_check()["status"], "DEGRADED")

    def test_record_failure_after_move_is_unknown_after_effect(self) -> None:
        request = self._request(key="record-failure")
        original_atomic = self.vault._atomic_write
        record_writes = [0]

        def fail_final_record(path: Path, payload: bytes) -> None:
            if Path(path).parent == self.vault.records_dir:
                record_writes[0] += 1
                if record_writes[0] >= 2:
                    raise OSError("injected record failure")
            original_atomic(path, payload)

        self.vault._atomic_write = fail_final_record  # type: ignore[method-assign]
        result = self.executor.execute(request, self._capability(request))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "UNKNOWN_AFTER_EFFECT")
        self.assertTrue(result["real_world_effect"])
        self.assertTrue(result["recovery_required"])
        self.assertFalse(Path(request.target).exists())

    def test_capacity_bounded_scan_corruption_restore_and_no_secret_export(self) -> None:
        request = self._request()
        self.assertTrue(self.executor.execute(request, self._capability(request))["accepted"])
        with self.assertRaises(QuarantineVaultError):
            self.vault.ensure_capacity(999999)
        source_record = next(self.vault.records_dir.glob("*.json"))
        for index in range(self.vault.max_records):
            shutil.copyfile(source_record, self.vault.records_dir / f"extra-{index}.json")
        with self.assertRaises(QuarantineVaultError):
            self.vault.find_by_idempotency("idem-1")
        record = next(self.vault.records_dir.glob("*.json"))
        value = json.loads(record.read_text(encoding="utf-8"))
        value["incident_id"] = "tampered"
        record.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(self.vault.health_check()["status"], "DEGRADED")
        self.assertFalse(self.executor.restore("missing", authorized=False, policy_valid=True, clean_verified=True)["accepted"])
        restore = self.executor.restore("missing", authorized=True, policy_valid=True, clean_verified=True)
        self.assertFalse(restore["accepted"])
        self.assertEqual(restore["reason"], "RESTORE_NOT_IMPLEMENTED_FAIL_CLOSED")
        self.assertNotIn("token_mac", json.dumps(self.executor.health_check()))

    def test_dry_run_compatibility_has_no_filesystem_effect(self) -> None:
        request = self._request(mode=DRY_RUN_ONLY)
        target = Path(request.target)
        result = BoundedQuarantineExecutor(self.vault, self.issuer, approved_root=self.root, mode=DRY_RUN_ONLY).execute(request)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["executed"])
        self.assertFalse(result["real_world_effect"])
        self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
