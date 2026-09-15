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
    "state/test_p11_19_adversarial"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

ROOT.mkdir(
    parents=True,
    exist_ok=True,
)


print("=== P11.19-03 ADVERSARIAL ADMISSION TEST ===")


# ============================================================
# SETUP
# ============================================================

storage_key = generate_storage_key()

key_manager = KeyManager(
    ROOT / "keys",
    storage_key,
)

replay_guard = ReplayGuard(
    max_entries=1000,
)

bus = EventBus(
    100,
)

spool = DurableEventSpool(
    ROOT / "spool",
)

pipeline = DurableEventPipeline(
    spool,
    bus,
)

gateway = CryptoReplayAdmissionGateway(
    key_manager,
    replay_guard,
    pipeline,
)


# ============================================================
# KEY
# ============================================================

print()
print("=== 01 KEY ===")

key1 = key_manager.generate_key()

assert key1 is not None

print("KEY_CREATED=PASS")
print("ACTIVE_KEY=", key1)


# ============================================================
# VALID SIGNED EVENT
# ============================================================

print()
print("=== 02 VALID SIGNED EVENT ===")

event = SecurityEvent(
    event_type="P11_19_ADVERSARIAL_EVENT",
    severity="HIGH",
    value=90,
    source="P11.19TestSensor",
    message="Original trusted event",
    confidence=0.99,
    host_id="host-p11-19",
    sensor_id="sensor-p11-19",
)

envelope = gateway.sign_event(
    event
)

valid_result = gateway.admit(
    event,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "VALID_ADMITTED=",
    valid_result,
)

assert valid_result is True

print("VALID_EVENT=PASS")


# ============================================================
# TAMPERING
# ============================================================

print()
print("=== 03 TAMPERED EVENT ===")

tampered = SecurityEvent(
    event_type=event.event_type,
    severity=event.severity,
    value=event.value,
    source=event.source,
    message="ATTACKER MODIFIED EVENT",
    confidence=event.confidence,
    host_id=event.host_id,
    sensor_id=event.sensor_id,
)

tampered_result = gateway.admit(
    tampered,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "TAMPERED_ADMITTED=",
    tampered_result,
)

assert tampered_result is False

print("TAMPERING_BLOCKED=PASS")


# ============================================================
# WRONG SIGNATURE
# ============================================================

print()
print("=== 04 WRONG SIGNATURE ===")

wrong_signature = gateway.admit(
    event,
    envelope["key_id"],
    "00" * 32,
)

print(
    "WRONG_SIGNATURE_ADMITTED=",
    wrong_signature,
)

assert wrong_signature is False

print("WRONG_SIGNATURE_BLOCKED=PASS")


# ============================================================
# UNKNOWN KEY
# ============================================================

print()
print("=== 05 UNKNOWN KEY ===")

unknown_key = gateway.admit(
    event,
    "key-attacker-controlled",
    envelope["signature"],
)

print(
    "UNKNOWN_KEY_ADMITTED=",
    unknown_key,
)

assert unknown_key is False

print("UNKNOWN_KEY_BLOCKED=PASS")


# ============================================================
# ROTATE KEY
# ============================================================

print()
print("=== 06 RETIRED KEY ===")

key2 = key_manager.rotate()

print(
    "NEW_ACTIVE_KEY=",
    key2,
)

retired_key_result = gateway.admit(
    event,
    key1,
    envelope["signature"],
)

print(
    "RETIRED_KEY_ADMITTED=",
    retired_key_result,
)

assert retired_key_result is False

print("RETIRED_KEY_BLOCKED=PASS")


# ============================================================
# NEW ACTIVE EVENT
# ============================================================

print()
print("=== 07 NEW ACTIVE KEY EVENT ===")

event2 = SecurityEvent(
    event_type="P11_19_ACTIVE_KEY_EVENT",
    severity="CRITICAL",
    value=100,
    source="P11.19TestSensor",
    message="New active-key event",
    confidence=1.0,
    host_id="host-p11-19",
    sensor_id="sensor-p11-19",
)

envelope2 = gateway.sign_event(
    event2
)

active_result = gateway.admit(
    event2,
    envelope2["key_id"],
    envelope2["signature"],
)

print(
    "ACTIVE_KEY_ADMITTED=",
    active_result,
)

assert active_result is True

print("ACTIVE_KEY_EVENT=PASS")


# ============================================================
# REPLAY
# ============================================================

print()
print("=== 08 REPLAY ===")

replay_result = gateway.admit(
    event2,
    envelope2["key_id"],
    envelope2["signature"],
)

print(
    "REPLAY_ADMITTED=",
    replay_result,
)

assert replay_result is False

print("REPLAY_BLOCKED=PASS")


# ============================================================
# PIPELINE FAILURE
# ============================================================

print()
print("=== 09 PIPELINE FAILURE ===")

event3 = SecurityEvent(
    event_type="P11_19_PIPELINE_FAILURE",
    severity="HIGH",
    value=95,
    source="P11.19TestSensor",
    message="Pipeline failure test",
    confidence=0.95,
    host_id="host-p11-19",
    sensor_id="sensor-p11-19",
)

envelope3 = gateway.sign_event(
    event3
)

original_ingest = pipeline.ingest


def failing_ingest(*args, **kwargs):
    raise RuntimeError(
        "SIMULATED_PIPELINE_FAILURE"
    )


pipeline.ingest = failing_ingest

try:
    failure_result = gateway.admit(
        event3,
        envelope3["key_id"],
        envelope3["signature"],
    )
finally:
    pipeline.ingest = original_ingest


print(
    "PIPELINE_FAILURE_ADMITTED=",
    failure_result,
)

assert failure_result is False

print("PIPELINE_FAILURE_FAIL_CLOSED=PASS")


# ============================================================
# FINAL STORAGE CHECK
# ============================================================

print()
print("=== 10 FINAL STORAGE CHECK ===")

pending = spool.pending_records()

print(
    "PENDING_COUNT=",
    len(pending),
)

print(
    "BUS_SIZE=",
    bus.size(),
)

assert len(pending) == 2
assert bus.size() == 2

print("NO_FALSE_PERSISTENCE=PASS")
print("NO_FALSE_BUS_PUBLICATION=PASS")


# ============================================================
# STATS
# ============================================================

print()
print("=== 11 SECURITY STATS ===")

print(
    "GATEWAY_STATS=",
    gateway.get_stats(),
)

print(
    "REPLAY_STATS=",
    replay_guard.get_stats(),
)

print(
    "PIPELINE_STATS=",
    pipeline.get_stats(),
)

print(
    "SPOOL_STATS=",
    spool.get_stats(),
)


# ============================================================
# FINAL
# ============================================================

print()
print("=== P11.19-03 RESULT ===")

print("VALID_EVENT_ACCEPTED=True")
print("TAMPERING_BLOCKED=True")
print("WRONG_SIGNATURE_BLOCKED=True")
print("UNKNOWN_KEY_BLOCKED=True")
print("RETIRED_KEY_BLOCKED=True")
print("ACTIVE_KEY_EVENT_ACCEPTED=True")
print("REPLAY_BLOCKED=True")
print("PIPELINE_FAILURE_FAIL_CLOSED=True")
print("NO_FALSE_PERSISTENCE=True")
print("NO_FALSE_BUS_PUBLICATION=True")
print("ALL_ASSERTIONS_PASS=True")
print("TEST_COMPLETE=True")
