from __future__ import annotations

import copy
import unittest

from agent.storage.durable_spool import DurableSpoolPolicy
from scripts.agent_release.agent_service_bootstrap import _validate_spool_copy_health


class RecoverySpoolSaturationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = DurableSpoolPolicy()
        self.saturated = {
            "status": "DEGRADED",
            "bounded": True,
            "capacity_status": "SATURATED",
            "terminal_state_safe": True,
            "pending": self.policy.max_pending_events,
            "pending_active_bytes": self.policy.max_pending_bytes - 1,
            "pending_physical_bytes": self.policy.max_recovery_scan_bytes - 1,
            "max_pending_events": self.policy.max_pending_events,
            "max_pending_bytes": self.policy.max_pending_bytes,
            "max_terminal_records": self.policy.max_terminal_records,
            "max_terminal_state_bytes": self.policy.max_terminal_state_bytes,
        }

    def test_plan_accepts_only_bounded_safe_saturation(self) -> None:
        _validate_spool_copy_health(self.saturated, self.policy, require_live_safe=False)
        for field, value in (
            ("terminal_state_safe", False),
            ("bounded", False),
            ("capacity_status", "UNKNOWN"),
            ("status", "HEALTHY"),
            ("pending", self.policy.max_pending_events + 1),
            ("pending_active_bytes", self.policy.max_pending_bytes + 1),
            ("pending_physical_bytes", self.policy.max_recovery_scan_bytes + 1),
        ):
            invalid = copy.deepcopy(self.saturated)
            invalid[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                _validate_spool_copy_health(invalid, self.policy, require_live_safe=False)

    def test_pre_start_rejects_saturation_and_accepts_healthy_pressure(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "RECOVERY_SPOOL_COPY_UNHEALTHY"):
            _validate_spool_copy_health(self.saturated, self.policy, require_live_safe=True)
        healthy = copy.deepcopy(self.saturated)
        healthy.update(status="HEALTHY", capacity_status="PRESSURE", pending=self.policy.max_pending_events - 1)
        _validate_spool_copy_health(healthy, self.policy, require_live_safe=True)

    def test_missing_and_wrong_typed_fields_fail_closed(self) -> None:
        for field in tuple(self.saturated):
            invalid = copy.deepcopy(self.saturated)
            invalid.pop(field)
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                _validate_spool_copy_health(invalid, self.policy, require_live_safe=False)
        invalid = copy.deepcopy(self.saturated)
        invalid["pending"] = True
        with self.assertRaises(RuntimeError):
            _validate_spool_copy_health(invalid, self.policy, require_live_safe=False)


if __name__ == "__main__":
    unittest.main()
