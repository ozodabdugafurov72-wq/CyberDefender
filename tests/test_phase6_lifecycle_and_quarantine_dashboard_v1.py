from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    LAB_CANARY_EXECUTION,
    QuarantineCapabilityIssuer,
    QuarantineRequest,
    canonical_scope_digest,
)
from agent.service_runner import ServiceRunner
from agent.service_crash_guard import fresh_record
from agent.service_lifecycle import run_guarded_service
from dashboard_owner.quarantine_read_model import QuarantineReadModel


class _LabSafety:
    def health_snapshot(self) -> dict[str, object]:
        return {"safe_mode": False, "shutdown_requested": False}

    def authorize_lab_quarantine(self, scope: dict[str, str]) -> dict[str, object]:
        return {
            "allowed": True,
            "mode": LAB_CANARY_EXECUTION,
            "scope_digest": canonical_scope_digest(scope),
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
        }


def _decision_evidence(incident_id: str, digest: str) -> tuple[dict[str, object], dict[str, object]]:
    row = {"incident_id": incident_id, "requested_action": "QUARANTINE", "decision_digest": digest}
    return (
        {"accepted": True, "policy_outcome": "REQUIRE_VERIFICATION", "authorization": "NOT_GRANTED",
         "action": "OBSERVE_ONLY", "assessments": [dict(row)]},
        {"accepted": True, "verified": True, "authorization": "NOT_GRANTED",
         "action": "OBSERVE_ONLY", "assessments": [dict(row)]},
    )


class LifecycleRegressionTests(unittest.TestCase):
    def test_guard_failure_reason_is_not_counted_twice(self) -> None:
        class Store:
            def __init__(self) -> None:
                self.record = fresh_record("CyberDefenderAgent")

            def load(self) -> dict[str, object]:
                return dict(self.record)

            def write(self, value: dict[str, object]) -> dict[str, object]:
                value = dict(value)
                value["revision"] = int(value["revision"]) + 1
                self.record = value
                return value

            def close(self) -> None:
                return None

        store = Store()
        stop = threading.Event()

        def observe(_service: str, state: str) -> None:
            if state == "READY":
                stop.set()

        def failed_attempt(guard: object) -> bool:
            guard.failed("UNHANDLED_EXCEPTION")
            return False

        run_guarded_service(
            "CyberDefenderAgent", stop, failed_attempt,
            store_factory=lambda: store, boot_factory=lambda: "boot",
            observer=observe,
        )
        self.assertEqual(store.record["cumulative_failures"], 1)
        self.assertEqual(store.record["recent_failures"][-1]["code"], "UNHANDLED_EXCEPTION")

    def test_runner_survives_beyond_previous_fifteen_cycle_point(self) -> None:
        stop = threading.Event()

        class Runtime:
            VERSION = "2.4"

            def __init__(self) -> None:
                self.cycles = 0
                self.stopped = False
                self.closed = False
                self.safety = type("Safety", (), {"enter_safe_mode": lambda *_: None})()

            def run_cycle(self) -> None:
                self.cycles += 1
                if self.cycles >= 25:
                    stop.set()  # explicit host stop, not runner cleanup

            def health_snapshot(self) -> dict[str, object]:
                return {"runtime": {"status": "HEALTHY"}, "resource_guard": {"state": "NORMAL"}}

            def stop(self, _reason: str = "") -> None:
                self.stopped = True

            def close(self) -> None:
                self.closed = True

        runtime = Runtime()
        runner = ServiceRunner(lambda: runtime, interval_seconds=0.001, stop_event=stop)
        runner.run()
        self.assertGreaterEqual(runtime.cycles, 25)
        self.assertEqual(runner.exit_reason, "SERVICE_STOP_EVENT_SET")
        self.assertTrue(runtime.stopped and runtime.closed)

    def test_runner_does_not_turn_clean_runtime_return_into_host_stop(self) -> None:
        stop = threading.Event()

        class Runtime:
            def run_cycle(self) -> None:
                return None

            def stop(self, _reason: str = "") -> None:
                return None

            def close(self) -> None:
                return None

        runner = ServiceRunner(lambda: Runtime(), stop_event=stop)
        runner.run(max_cycles=1)
        self.assertEqual(runner.exit_reason, "TEST_CYCLE_LIMIT")
        self.assertFalse(stop.is_set())

    def test_unexpected_factory_exception_is_machine_readable_and_does_not_set_host_stop(self) -> None:
        stop = threading.Event()

        def factory() -> object:
            raise RuntimeError("synthetic failure")

        runner = ServiceRunner(factory, stop_event=stop)
        with self.assertRaises(RuntimeError):
            runner.run()
        self.assertEqual(runner.exit_reason, "UNHANDLED_EXCEPTION")
        self.assertEqual(runner.exit_detail, "RuntimeError")
        self.assertFalse(stop.is_set())

    def test_degraded_resource_state_does_not_terminate_loop(self) -> None:
        stop = threading.Event()

        class Runtime:
            def __init__(self) -> None:
                self.cycles = 0
                self.safety = type("Safety", (), {"enter_safe_mode": lambda *_: None})()

            def run_cycle(self) -> None:
                self.cycles += 1
                if self.cycles >= 20:
                    stop.set()

            def health_snapshot(self) -> dict[str, object]:
                return {"runtime": {"status": "DEGRADED"}, "resource_guard": {"state": "DEGRADED"}}

            def stop(self, _reason: str = "") -> None:
                return None

            def close(self) -> None:
                return None

        runtime = Runtime()
        runner = ServiceRunner(lambda: runtime, interval_seconds=0.001, stop_event=stop)
        runner.run()
        self.assertGreaterEqual(runtime.cycles, 20)
        self.assertEqual(runner.exit_reason, "SERVICE_STOP_EVENT_SET")

    def test_eventlog_failure_is_isolated_from_runtime_lifecycle(self) -> None:
        import agent.windows_service as host
        from unittest.mock import Mock, patch

        service = object.__new__(host.CyberDefenderWindowsService)
        service._runner = None
        service._stop_event = threading.Event()
        runtime = Mock()
        runtime.run_cycle.side_effect = lambda: service._stop_event.set()
        runtime.health_snapshot.return_value = {"runtime": {"status": "HEALTHY"}}
        runtime.child_cleanup_verified = True
        guard = Mock(allow_optional=True)
        paths = {"fleet_token": Mock(), "endpoint_id": Mock()}
        with patch.object(host, "configure_machine_environment", return_value=paths), \
                patch("agent.main.build_managed_runtime", return_value=runtime), \
                patch("agent.service_diagnostics.write_service_log"), \
                patch.object(host.servicemanager, "LogInfoMsg", side_effect=RuntimeError("eventlog unavailable")):
            service._run_attempt(guard)
        self.assertEqual(runtime.run_cycle.call_count, 1)
        self.assertTrue(service._runner.cleanup_verified)


class QuarantineDashboardReadModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cd-quarantine-dashboard-")
        self.base = Path(self.temp.name)
        self.root = self.base / "canary"
        self.root.mkdir()
        (self.root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
        self.vault_root = self.base / "vault"
        self.vault = BoundedQuarantineVault(self.vault_root, max_records=64, max_bytes=8 * 1024 * 1024)
        self.previous_vaults = QuarantineReadModel.APPROVED_VAULTS
        QuarantineReadModel.APPROVED_VAULTS = (("test", self.vault_root),)

    def tearDown(self) -> None:
        QuarantineReadModel.APPROVED_VAULTS = self.previous_vaults
        self.temp.cleanup()

    def _verified_record(self) -> dict[str, object]:
        target = self.root / "dashboard-canary.txt"
        target.write_text("harmless dashboard canary\n", encoding="utf-8")
        request = QuarantineRequest.from_mapping({
            "incident_id": "INC-DASH-1", "idempotency_key": "dash-1", "target": str(target),
            "approved_root": str(self.root), "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "requester": "operator", "evidence_ref": "evidence://INC-DASH-1",
            "decision_digest": hashlib.sha256(b"dash-decision").hexdigest(), "mode": LAB_CANARY_EXECUTION,
        })
        issuer = QuarantineCapabilityIssuer()
        capability = issuer.issue(
            request,
            policy_result=_decision_evidence(request.incident_id, request.decision_digest)[0],
            verification_result=_decision_evidence(request.incident_id, request.decision_digest)[1],
            safety=_LabSafety(), operator_approved=True,
        )
        result = BoundedQuarantineExecutor(self.vault, issuer, approved_root=self.root).execute(request, capability)
        self.assertEqual(result["status"], "QUARANTINED")
        return self.vault.get_verified_record(result["quarantine_id"]) or {}

    @staticmethod
    def _write_signed_record(root: Path, name: str, **overrides: object) -> None:
        record: dict[str, object] = {
            "schema": "cd.quarantine.record.v2", "version": "2.0", "quarantine_id": name,
            "incident_id": "INC-" + name, "requested_action": "QUARANTINE", "idempotency_key": name,
            "original_path": "C:/CD/LAB/LiveRansomwareTest/placeholder.txt", "approved_root": "C:/CD/LAB/LiveRansomwareTest",
            "target_sha256": "a" * 64, "target_size": 1, "state": "FAILED_AFTER_EFFECT",
            "created_at": "2026-10-05T00:00:00+00:00", "tenant_id": "tenant-a", "endpoint_id": "endpoint-a",
            "risk_level": "CRITICAL", "risk_score": 99, "recovery_required": True,
            "production_authorization": "NOT_GRANTED", "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
            "evidence_ref": "evidence://" + name, "decision_digest": "b" * 64, "capability_id": "cap-" + name,
            "scope_digest": "c" * 64, "evidence_quarantine_id": "ev-" + name,
        }
        record.update(overrides)
        unsigned = dict(record)
        record["record_sha256"] = hashlib.sha256(
            json.dumps(unsigned, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        (root / "v2-records").mkdir(parents=True, exist_ok=True)
        (root / "v2-records" / f"{name}.json").write_text(
            json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )

    def test_empty_state_is_unavailable_without_records_and_is_bounded(self) -> None:
        model = QuarantineReadModel(self.vault_root)
        snapshot = model.snapshot()
        self.assertEqual(snapshot["status"], "OPERATIONAL")
        self.assertEqual(snapshot["items"], [])
        self.assertLessEqual(snapshot["vault"]["records_scanned"], model.MAX_RECORDS)

    def test_verified_item_exposes_audit_chain_without_token_mac(self) -> None:
        record = self._verified_record()
        snapshot = QuarantineReadModel(self.vault_root).snapshot(detail=True)
        self.assertEqual(snapshot["summary"]["verified_quarantined"], 1)
        item = snapshot["items"][0]
        self.assertEqual(item["containment_state"], "QUARANTINED")
        self.assertTrue(item["post_action_verification"])
        self.assertEqual(item["production_authorization"], "NOT_GRANTED")
        self.assertEqual(item["lab_authorization"], "QUARANTINE_CAPABILITY_CONSUMED")
        self.assertEqual(item["capability_id"], record["capability_id"])
        self.assertNotIn("token_mac", json.dumps(snapshot))

    def test_failure_integrity_and_tenant_filters_fail_closed(self) -> None:
        self._write_signed_record(self.vault_root, "q-failed")
        self._write_signed_record(self.vault_root, "q-unknown", state="UNKNOWN_AFTER_EFFECT", tenant_id="tenant-b")
        (self.vault_root / "v2-records" / "malformed.json").write_text("{broken", encoding="utf-8")
        all_rows = QuarantineReadModel(self.vault_root).snapshot(detail=True)
        self.assertEqual(all_rows["status"], "DEGRADED")
        self.assertGreaterEqual(all_rows["summary"]["failed_unknown"], 2)
        self.assertGreaterEqual(all_rows["summary"]["evidence_integrity_problems"], 2)
        tenant_a = QuarantineReadModel(self.vault_root, tenant_id="tenant-a").snapshot(detail=True)
        self.assertEqual({row["tenant_id"] for row in tenant_a["items"]}, {"tenant-a"})
        self.assertTrue(all("token_mac" not in json.dumps(row) for row in tenant_a["items"]))

    def test_record_scan_is_bounded_and_malformed_records_are_not_trusted(self) -> None:
        for index in range(QuarantineReadModel.MAX_RECORDS + 1):
            self._write_signed_record(self.vault_root, f"q-{index}")
        snapshot = QuarantineReadModel(self.vault_root).snapshot()
        self.assertEqual(snapshot["status"], "DEGRADED")
        self.assertEqual(snapshot["items"], [])
        self.assertEqual(snapshot["error_count"], 1)

    def test_dashboard_surfaces_are_read_only_and_separate_lab_authority(self) -> None:
        self._verified_record()
        import dashboard_owner.server as server
        previous = os.environ.get("CYBERDEFENDER_LAB_QUARANTINE_VAULT")
        previous_tenant = os.environ.get("CYBERDEFENDER_TENANT_ID")
        previous_vaults = QuarantineReadModel.APPROVED_VAULTS
        os.environ["CYBERDEFENDER_LAB_QUARANTINE_VAULT"] = str(self.vault_root)
        os.environ["CYBERDEFENDER_TENANT_ID"] = "UNKNOWN"
        QuarantineReadModel.APPROVED_VAULTS = (("test", self.vault_root),)
        try:
            owner = server.quarantine_snapshot(detail=False)
            admin = server.quarantine_snapshot(detail=True)
            self.assertEqual(owner["items"][0]["production_authorization"], "NOT_GRANTED")
            self.assertNotIn("capability_id", owner["items"][0])
            self.assertIn("capability_id", admin["items"][0])
            admin_html = Path("dashboard_owner/static/admin/index.html").read_text(encoding="utf-8")
            owner_html = Path("dashboard_owner/static/index.html").read_text(encoding="utf-8")
            self.assertIn('href="#quarantine">Quarantine</a>', admin_html)
            self.assertIn('<i>10</i><span>Quarantine & Containment</span>', owner_html)
            self.assertIn("INCIDENT</span><span>ENDPOINT</span><span>TENANT</span>", owner_html)
            self.assertIn("No quarantine records", owner_html)
            self.assertIn("No quarantine records", admin_html)
            self.assertNotIn("token_mac", Path("dashboard_owner/static/admin/admin.js").read_text(encoding="utf-8"))
            self.assertNotIn("token_mac", Path("dashboard_owner/static/owner.js").read_text(encoding="utf-8"))
        finally:
            if previous is None:
                os.environ.pop("CYBERDEFENDER_LAB_QUARANTINE_VAULT", None)
            else:
                os.environ["CYBERDEFENDER_LAB_QUARANTINE_VAULT"] = previous
            if previous_tenant is None:
                os.environ.pop("CYBERDEFENDER_TENANT_ID", None)
            else:
                os.environ["CYBERDEFENDER_TENANT_ID"] = previous_tenant
            QuarantineReadModel.APPROVED_VAULTS = previous_vaults


if __name__ == "__main__":
    unittest.main()
