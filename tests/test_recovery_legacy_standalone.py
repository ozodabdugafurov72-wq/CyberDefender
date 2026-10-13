from __future__ import annotations

import base64
import os
import tempfile
import unittest

from agent.config import load_config
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


class LegacyStandaloneRecoveryTests(unittest.TestCase):
    def test_tenantless_legacy_state_recovers_without_manufacturing_tenant(self) -> None:
        previous = {
            name: os.environ.get(name)
            for name in (
                "CYBERDEFENDER_STATE_DIR",
                "CYBERDEFENDER_LOG_DIR",
                "CYBERDEFENDER_STORAGE_KEY_B64",
                "CYBERDEFENDER_ENDPOINT_ID",
            )
        }
        try:
            with tempfile.TemporaryDirectory(prefix="cd-legacy-standalone-recovery-") as root:
                os.environ["CYBERDEFENDER_STATE_DIR"] = root
                os.environ.pop("CYBERDEFENDER_LOG_DIR", None)
                os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode("ascii")
                os.environ["CYBERDEFENDER_ENDPOINT_ID"] = "legacy-endpoint"
                runtime = CyberDefenderRuntime(SafetyCore(), load_config())
                try:
                    active = SecurityEvent(
                        event_type="LEGACY_STANDALONE_ALERT",
                        severity="WARNING",
                        value=1,
                        source="test",
                        message="legacy active state",
                        tenant_id=None,
                    )
                    runtime.state_manager.update(active)
                    self.assertNotIn("tenant_id", runtime.state_manager.get_state(active.event_type))

                    recovered: list[SecurityEvent] = []
                    original_admit = runtime.admit_event

                    def capture_recovery(event: SecurityEvent):
                        if event.event_type == "LEGACY_STANDALONE_ALERT_RECOVERED":
                            recovered.append(event)
                        return original_admit(event)

                    runtime.admit_event = capture_recovery
                    before_failures = runtime.component_failures

                    runtime.process_recovery({}, set())

                    self.assertIsNone(runtime.state_manager.get_state(active.event_type))
                    self.assertEqual(before_failures, runtime.component_failures)
                    self.assertFalse(runtime.degraded)
                    self.assertEqual(1, len(recovered))
                    self.assertIsNone(recovered[0].tenant_id)
                    self.assertEqual(
                        "local-endpoint:legacy-endpoint",
                        runtime.correlation_adapter.standalone_scope_id,
                    )
                finally:
                    runtime.close()
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


if __name__ == "__main__":
    unittest.main()
