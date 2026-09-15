from __future__ import annotations

import base64
import os
import tempfile
from collections import Counter

from agent.config import load_config
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_recovery_traversal_") as td:
        os.environ["CYBERDEFENDER_STATE_DIR"] = td
        os.environ.pop("CYBERDEFENDER_LOG_DIR", None)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        runtime.cycle_count = 1
        runtime.resource_guard.check = lambda: {"state": "NORMAL", "resource": {}}
        assert runtime.update_resource_safety_cycle() is not None

        active = SecurityEvent(
            event_type="RECOVERY_TRAVERSAL_TEST",
            severity="WARNING",
            value=1,
            source="test",
            message="active before recovery",
        )
        runtime.state_manager.update(active)

        calls = Counter()
        original_ingest = runtime.runtime_pipeline.ingest
        original_bridge = runtime.event_bridge.to_detection
        original_corr = runtime.correlation_adapter.handle_event

        def ingest(event):
            if getattr(event, "event_type", "").endswith("_RECOVERED"):
                calls["runtime_pipeline"] += 1
            return original_ingest(event)

        def bridge(event):
            if getattr(event, "event_type", "").endswith("_RECOVERED"):
                calls["bridge"] += 1
            return original_bridge(event)

        def corr(event):
            if isinstance(event, dict) and event.get("event_type") == "DETECTION":
                data = event.get("data", {})
                if isinstance(data, dict) and str(data.get("type", "")).endswith("_RECOVERED"):
                    calls["correlation"] += 1
            return original_corr(event)

        runtime.runtime_pipeline.ingest = ingest
        runtime.event_bridge.to_detection = bridge
        runtime.correlation_adapter.handle_event = corr

        seen = []
        runtime.event_bus.subscribe(
            lambda event: seen.append(event)
            if isinstance(event, SecurityEvent) and event.event_type.endswith("_RECOVERED")
            else None
        )

        before_created = runtime.events_created
        before_admitted = runtime.events_admitted
        before_published = runtime.events_published

        runtime.process_recovery({}, set())
        dispatched = runtime.event_bus.dispatch_all()

        checks = {
            "Recovered ACTIVE state is removed": runtime.state_manager.get_state("RECOVERY_TRAVERSAL_TEST") is None,
            "Recovery crossed RuntimeSecurityPipeline": calls["runtime_pipeline"] == 1,
            "Recovery was admitted": runtime.events_admitted == before_admitted + 1,
            "Recovery counted as SecurityEvent": runtime.events_created == before_created + 1,
            "Recovery published to EventBus": runtime.events_published == before_published + 1,
            "Recovery dispatched in trusted EventBus path": dispatched >= 1 and len(seen) == 1,
            "Recovery crossed SecurityEventBridge": calls["bridge"] == 1,
            "Recovery crossed CorrelationAdapter": calls["correlation"] == 1,
        }

        failures = 0
        for label, ok in checks.items():
            print(("PASS" if ok else "FAIL") + " | " + label)
            failures += 0 if ok else 1

        print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'}")
        result = 0 if failures == 0 else 1
        runtime.close()
        return result


if __name__ == "__main__":
    raise SystemExit(main())
