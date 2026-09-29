from __future__ import annotations

import base64
import os
import tempfile

from agent.config import load_config
from agent.core.runtime_security_pipeline import RuntimePipelineResult
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_recovery_rollback_") as td:
        os.environ["CYBERDEFENDER_STATE_DIR"] = td
        os.environ.pop("CYBERDEFENDER_LOG_DIR", None)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()
        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        try:
            active = SecurityEvent(
                event_type="ROLLBACK_TEST",
                severity="WARNING",
                value=1,
                source="test",
                message="active",
                tenant_id="test-tenant",
            )
            runtime.state_manager.update(active)
            before = runtime.state_manager.get_state("ROLLBACK_TEST")

            original = runtime.runtime_pipeline.ingest
            runtime.runtime_pipeline.ingest = lambda event: RuntimePipelineResult(
                accepted=False,
                reason="INTENTIONAL_REJECT",
                event_id=getattr(event, "event_id", None),
                stage="TEST",
            )
            try:
                runtime.process_recovery({}, set())
            finally:
                runtime.runtime_pipeline.ingest = original

            after = runtime.state_manager.get_state("ROLLBACK_TEST")
            checks = {
                "Rejected recovery restores exact ACTIVE state": after == before,
                "Rejected recovery degrades runtime": runtime.degraded is True,
                "Rejected recovery increments recovery failures": runtime.recovery_failures >= 1,
                "Recovery event is rejected, not silently trusted": runtime.events_rejected >= 1,
            }
            failures = 0
            for label, ok in checks.items():
                print(("PASS" if ok else "FAIL") + " | " + label)
                failures += 0 if ok else 1
            print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'}")
            return 0 if failures == 0 else 1
        finally:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
