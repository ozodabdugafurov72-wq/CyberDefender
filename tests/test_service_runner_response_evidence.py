from __future__ import annotations

import unittest

from agent.service_runner import ServiceRunner
from control_plane.xdr_compat import validate_response_evidence


def verified_quarantine() -> dict[str, object]:
    return {
        "accepted": True,
        "status": "VERIFIED_QUARANTINED",
        "quarantine_id": "qv2-1234567890abcdef",
        "incident_id": "INC-RESPONSE-1",
        "event_id": "event-response-1",
        "target": r"C:\CD\LAB\LiveRansomwareTest\harmless.txt",
        "target_name": "harmless.txt",
        "target_sha256": "a" * 64,
        "detection_types": ["RANSOMWARE_BEHAVIOR"],
        "risk_score": 100,
        "risk_level": "CRITICAL",
        "policy_outcome": "REQUIRE_VERIFICATION",
        "policy_reason": "critical risk requires independent verification",
        "verifier_outcome": "VERIFIED",
        "verification_outcome": "QUARANTINED_VERIFIED",
        "response_latency_ms": 25.0,
        "execution_latency_ms": 10.0,
        "detection_to_response_ms": 30.0,
        "evidence_ref": "evidence://INC-RESPONSE-1",
        "production_authorization": "NOT_GRANTED",
        "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
        "receipt_integrity": True,
        "post_action_verification": True,
    }


class Runtime:
    VERSION = "2.4"

    def __init__(self) -> None:
        self.last_lab_quarantine_result = verified_quarantine()
        self.running = False
        self.shutdown_requested = False
        self.safety = type("Safety", (), {"enter_safe_mode": lambda *_: None})()
        self.child_cleanup_verified = True

    def begin_managed_loop(self) -> None:
        self.running = True

    def run_cycle(self) -> None:
        return None

    def health_snapshot(self) -> dict[str, object]:
        return {
            "runtime": {"status": "HEALTHY"},
            "resource_guard": {"state": "NORMAL"},
        }

    def stop(self, _reason: str) -> None:
        self.running = False

    def close(self) -> None:
        return None


class Telemetry:
    def __init__(self, outcomes: list[bool]) -> None:
        self.outcomes = list(outcomes)
        self.evidence: list[dict[str, object]] = []

    def register(self, **_kwargs) -> bool:
        return True

    def heartbeat(self, **_kwargs) -> bool:
        return True

    def publish_response_evidence(self, evidence, **_kwargs) -> bool:
        self.evidence.append(dict(evidence))
        return self.outcomes.pop(0)


class ServiceRunnerResponseEvidenceTests(unittest.TestCase):
    def test_verified_runtime_action_is_published_once(self) -> None:
        runtime = Runtime()
        telemetry = Telemetry([True])
        runner = ServiceRunner(lambda: runtime, interval_seconds=0.001, telemetry_client=telemetry)
        runner.run(max_cycles=2)
        self.assertEqual(1, len(telemetry.evidence))
        self.assertEqual(1, runner.response_evidence_sent)
        normalized = validate_response_evidence(
            telemetry.evidence[0], endpoint_id="endpoint-test"
        )
        self.assertEqual("QUARANTINED", normalized["action_state"])

    def test_ambiguous_failure_retries_until_accepted(self) -> None:
        runtime = Runtime()
        telemetry = Telemetry([False, True])
        runner = ServiceRunner(lambda: runtime, interval_seconds=0.001, telemetry_client=telemetry)
        runner.run(max_cycles=2)
        self.assertEqual(2, len(telemetry.evidence))
        self.assertEqual(1, runner.response_evidence_failures)
        self.assertEqual(1, runner.response_evidence_sent)

    def test_unverified_action_is_never_published(self) -> None:
        runtime = Runtime()
        runtime.last_lab_quarantine_result["receipt_integrity"] = False
        telemetry = Telemetry([])
        runner = ServiceRunner(lambda: runtime, interval_seconds=0.001, telemetry_client=telemetry)
        runner.run(max_cycles=1)
        self.assertEqual([], telemetry.evidence)


if __name__ == "__main__":
    unittest.main()
