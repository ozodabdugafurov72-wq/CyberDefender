from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.config import load_config
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {name}: {detail}")
    print(f"[PASS] {name}")


def main() -> None:
    print("FAILURE INJECTION v2 — REPLAY ATTACK")
    print("=" * 72)

    old_state_dir = os.environ.get("CYBERDEFENDER_STATE_DIR")
    old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")

    with tempfile.TemporaryDirectory(prefix="cd_replay_v2_") as tmp:
        runtime = None
        try:
            os.environ["CYBERDEFENDER_STATE_DIR"] = tmp
            key = os.urandom(32)
            os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(key).decode("ascii")

            runtime = CyberDefenderRuntime(SafetyCore(), load_config())

            # Test-only bootstrap: production key provisioning is a separate security contract.
            runtime.key_manager.generate_key()

            event = SecurityEvent(
                event_type="REPLAY_TEST_EVENT",
                severity="MEDIUM",
                value=1,
                source="ReplayInjectionTest",
                message="Deterministic replay-admission test event",
            )

            pipeline = runtime.runtime_pipeline
            gateway = runtime.admission_gateway
            durable = runtime.pipeline
            replay = runtime.replay_guard
            event_id = event.event_id

            before = {
                "pipeline_accepted": pipeline.accepted,
                "pipeline_rejected": pipeline.rejected,
                "gateway_accepted": gateway.accepted,
                "gateway_rejected": gateway.rejected,
                "gateway_replay_rejected": gateway.replay_rejected,
                "durable_ingest": durable.ingested if hasattr(durable, "ingested") else None,
                "replay_size": replay.size(),
            }

            first = pipeline.ingest(event)
            check("First event admitted", first.accepted is True, repr(first))
            check("First event reached ADMITTED stage", first.stage == "ADMITTED", repr(first))
            check("First event identity preserved", first.event_id == event_id, repr(first))
            check("ReplayGuard remembered first event", replay.contains(event_id))

            after_first_gateway_replay = gateway.replay_rejected
            after_first_durable = durable.get_stats()
            after_first_pipeline = pipeline.get_stats()

            # Exact same SecurityEvent object: same event_id and same canonical payload/signature semantics.
            second = pipeline.ingest(event)

            check("Replay rejected", second.accepted is False, repr(second))
            check("Replay reason is REPLAY_REJECTED", second.reason == "REPLAY_REJECTED", repr(second))
            check("Replay stage is REPLAY_PROTECTION", second.stage == "REPLAY_PROTECTION", repr(second))
            check("Replay is fail-closed", second.fail_closed is True, repr(second))
            check("Replay is not retryable", second.retryable is False, repr(second))
            check("Event ID preserved on rejection", second.event_id == event_id, repr(second))
            check(
                "Replay counter incremented exactly once",
                gateway.replay_rejected == after_first_gateway_replay + 1,
                repr(gateway.get_stats()),
            )
            check(
                "Durable pipeline not entered on replay",
                durable.get_stats().get("counters", {}).get("spooled")
                == after_first_durable.get("counters", {}).get("spooled"),
                repr(durable.get_stats()),
            )
            check(
                "Runtime pipeline accepted counter unchanged by replay",
                pipeline.accepted == after_first_pipeline["accepted"],
                repr(pipeline.get_stats()),
            )
            check(
                "Runtime pipeline rejected counter increased",
                pipeline.rejected == after_first_pipeline["rejected"] + 1,
                repr(pipeline.get_stats()),
            )
            check(
                "ReplayGuard tracks exactly one copy of event",
                replay.contains(event_id) and replay.size() == before["replay_size"] + 1,
                repr(replay.get_stats()),
            )

            # Third replay must remain rejected; this guards against accidental removal/poisoning.
            third = pipeline.ingest(event)
            check("Repeated replay remains rejected", third.accepted is False, repr(third))
            check("Repeated replay remains REPLAY_REJECTED", third.reason == "REPLAY_REJECTED", repr(third))
            check("ReplayGuard still contains original event", replay.contains(event_id))

            print("\nCOUNTERS")
            print("Runtime pipeline:", pipeline.get_stats())
            print("Admission gateway:", gateway.get_stats())
            print("Replay guard:", replay.get_stats())
            print("Durable pipeline:", durable.get_stats())

            print("\nRESULT: PASS")

        finally:
            if runtime is not None:
                runtime.close()
            if old_state_dir is None:
                os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
            else:
                os.environ["CYBERDEFENDER_STATE_DIR"] = old_state_dir

            if old_key is None:
                os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
            else:
                os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_key


if __name__ == "__main__":
    main()
