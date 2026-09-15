from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.crypto.key_manager import KeyManager, generate_storage_key
from agent.crypto.replay_guard import ReplayGuard
from agent.core.crypto_replay_admission_gateway import (
    CryptoReplayAdmissionGateway,
)


ROOT = Path(
    "state/test_p11_19_failure_recovery"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

ROOT.mkdir(
    parents=True,
    exist_ok=True,
)


print("=== P11.19-04 FAILURE / RECOVERY SEMANTICS ===")


# ============================================================
# SETUP
# ============================================================

storage_key = generate_storage_key()

key_manager = KeyManager(
    ROOT / "keys",
    storage_key,
)

key_id = key_manager.generate_key()

assert key_id is not None


def create_stack():
    bus = EventBus(100)

    spool = DurableEventSpool(
        ROOT / "spool"
    )

    pipeline = DurableEventPipeline(
        spool,
        bus,
    )

    replay_guard = ReplayGuard(
        max_entries=1000
    )

    gateway = CryptoReplayAdmissionGateway(
        key_manager,
        replay_guard,
        pipeline,
    )

    return (
        bus,
        spool,
        pipeline,
        replay_guard,
        gateway,
    )


(
    bus,
    spool,
    pipeline,
    replay_guard,
    gateway,
) = create_stack()


# ============================================================
# EVENT
# ============================================================

print()
print("=== 01 CREATE EVENT ===")

event = SecurityEvent(
    event_type="P11_19_FAILURE_RECOVERY",
    severity="CRITICAL",
    value=100,
    source="P11.19RecoverySensor",
    message="Crash recovery test event",
    confidence=1.0,
    host_id="host-p11-19",
    sensor_id="sensor-p11-19",
)

envelope = gateway.sign_event(event)

print(
    "EVENT_ID=",
    event.event_id,
)

print(
    "KEY_ID=",
    envelope["key_id"],
)

assert envelope["key_id"] == key_id

print("EVENT_CREATED=PASS")


# ============================================================
# SIMULATED FAILURE
# ============================================================

print()
print("=== 02 SIMULATED PIPELINE FAILURE ===")

original_ingest = pipeline.ingest


def failing_ingest(*args, **kwargs):
    raise RuntimeError(
        "SIMULATED_CRASH_BEFORE_DURABLE_COMMIT"
    )


pipeline.ingest = failing_ingest

try:
    first_result = gateway.admit(
        event,
        envelope["key_id"],
        envelope["signature"],
    )
finally:
    pipeline.ingest = original_ingest


print(
    "FIRST_ADMISSION=",
    first_result,
)

assert first_result is False

print("FAILURE_REJECTED=PASS")


# ============================================================
# VERIFY NO FALSE DURABLE RECORD
# ============================================================

print()
print("=== 03 NO FALSE DURABLE COMMIT ===")

pending = spool.pending_records()

print(
    "PENDING_AFTER_FAILURE=",
    len(pending),
)

assert len(pending) == 0

print("NO_FALSE_DURABLE_COMMIT=PASS")


# ============================================================
# VERIFY REPLAY STATE
# ============================================================

print()
print("=== 04 REPLAY STATE AFTER FAILURE ===")

print(
    "REPLAY_CONTAINS=",
    replay_guard.contains(
        event.event_id
    ),
)

print(
    "REPLAY_STATS=",
    replay_guard.get_stats(),
)


# ============================================================
# RETRY
# ============================================================

print()
print("=== 05 RETRY ===")

retry_result = gateway.admit(
    event,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "RETRY_ADMITTED=",
    retry_result,
)

assert retry_result is True

print("RETRY_ACCEPTED=PASS")


# ============================================================
# VERIFY SINGLE COMMIT
# ============================================================

print()
print("=== 06 SINGLE DURABLE COMMIT ===")

pending_after_retry = (
    spool.pending_records()
)

print(
    "PENDING_AFTER_RETRY=",
    len(pending_after_retry),
)

print(
    "BUS_SIZE_AFTER_RETRY=",
    bus.size(),
)

assert len(pending_after_retry) == 1
assert bus.size() == 1

print("SINGLE_DURABLE_COMMIT=PASS")
print("SINGLE_BUS_PUBLICATION=PASS")


# ============================================================
# SECOND RETRY / REPLAY
# ============================================================

print()
print("=== 07 SECOND RETRY ===")

second_retry = gateway.admit(
    event,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "SECOND_RETRY_ADMITTED=",
    second_retry,
)

assert second_retry is False

print("SECOND_RETRY_BLOCKED=PASS")


# ============================================================
# FINAL
# ============================================================

print()
print("=== 08 FINAL STATE ===")

print(
    "PENDING_FINAL=",
    len(spool.pending_records()),
)

print(
    "BUS_FINAL=",
    bus.size(),
)

print(
    "REPLAY_FINAL=",
    replay_guard.get_stats(),
)

assert len(spool.pending_records()) == 1
assert bus.size() == 1


print()
print("=== P11.19-04 RESULT ===")

print("FAILURE_REJECTED=True")
print("NO_FALSE_DURABLE_COMMIT=True")
print("RETRY_ACCEPTED=True")
print("SINGLE_DURABLE_COMMIT=True")
print("SINGLE_BUS_PUBLICATION=True")
print("SECOND_RETRY_BLOCKED=True")
print("ALL_ASSERTIONS_PASS=True")
print("TEST_COMPLETE=True")
