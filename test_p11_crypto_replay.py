from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import (
    DurableEventPipeline,
)

from agent.crypto.key_manager import (
    KeyManager,
    generate_storage_key,
)

from agent.crypto.replay_guard import (
    ReplayGuard,
)

from agent.core.crypto_replay_admission_gateway import (
    CryptoReplayAdmissionGateway,
)


ROOT = Path(
    "state/test_p11_crypto_replay"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)


# ============================================================
# SETUP
# ============================================================

storage_key = (
    generate_storage_key()
)

key_root = (
    ROOT / "keys"
)

spool_root = (
    ROOT / "spool"
)

bus = EventBus(
    10
)

key_manager = KeyManager(
    key_root,
    storage_key,
)

replay_guard = ReplayGuard(
    max_entries=100
)

spool = DurableEventSpool(
    spool_root
)

pipeline = DurableEventPipeline(
    spool,
    bus,
)

gateway = (
    CryptoReplayAdmissionGateway(
        key_manager,
        replay_guard,
        pipeline,
    )
)


# ============================================================
# P11.9-01 KEY
# ============================================================

print(
    "=== P11.9-01 KEY ==="
)

key_id = (
    key_manager.generate_key()
)

print(
    "KEY_CREATED=",
    key_id is not None,
)

print(
    "ACTIVE_KEY=",
    key_manager.active_key_id(),
)


# ============================================================
# P11.9-02 FIRST EVENT
# ============================================================

print()
print(
    "=== P11.9-02 FIRST EVENT ==="
)

event = SecurityEvent(
    event_type="P11_9_FIRST_EVENT",
    severity="HIGH",
    value=77,
    source="P11.9TestSensor",
    message="First trusted event",
    confidence=0.99,
    host_id="host-p11-9",
    sensor_id="sensor-p11-9",
)

envelope = (
    gateway.sign_event(
        event
    )
)

first = gateway.admit(
    event,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "FIRST_ACCEPT=",
    first,
)

print(
    "SPOOL_PENDING=",
    len(
        spool.pending_records()
    ),
)

print(
    "BUS_SIZE=",
    bus.size(),
)


# ============================================================
# P11.9-03 SAME EVENT REPLAY
# ============================================================

print()
print(
    "=== P11.9-03 SAME EVENT REPLAY ==="
)

replay = gateway.admit(
    event,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "REPLAY_ACCEPT=",
    replay,
)

print(
    "SPOOL_PENDING_AFTER_REPLAY=",
    len(
        spool.pending_records()
    ),
)

print(
    "BUS_SIZE_AFTER_REPLAY=",
    bus.size(),
)


# ============================================================
# P11.9-04 TAMPERED EVENT
# ============================================================

print()
print(
    "=== P11.9-04 TAMPERED EVENT ==="
)

tampered = SecurityEvent(
    event_type="P11_9_FIRST_EVENT",
    severity="CRITICAL",
    value=9999,
    source="P11.9TestSensor",
    message="ATTACKER MODIFIED",
    confidence=0.99,
    host_id="host-p11-9",
    sensor_id="sensor-p11-9",
)

tampered_result = gateway.admit(
    tampered,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "TAMPER_ACCEPT=",
    tampered_result,
)

print(
    "SPOOL_PENDING_AFTER_TAMPER=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.9-05 WRONG SIGNATURE
# ============================================================

print()
print(
    "=== P11.9-05 WRONG SIGNATURE ==="
)

wrong_signature = gateway.admit(
    event,
    envelope["key_id"],
    "00" * 32,
)

print(
    "BAD_SIGNATURE_ACCEPT=",
    wrong_signature,
)

print(
    "SPOOL_PENDING_AFTER_BAD_SIGNATURE=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.9-06 UNKNOWN KEY
# ============================================================

print()
print(
    "=== P11.9-06 UNKNOWN KEY ==="
)

unknown_key = gateway.admit(
    event,
    "key-attacker-controlled",
    envelope["signature"],
)

print(
    "UNKNOWN_KEY_ACCEPT=",
    unknown_key,
)


# ============================================================
# P11.9-07 NEW UNIQUE EVENT
# ============================================================

print()
print(
    "=== P11.9-07 NEW UNIQUE EVENT ==="
)

event2 = SecurityEvent(
    event_type="P11_9_SECOND_EVENT",
    severity="CRITICAL",
    value=100,
    source="P11.9TestSensor",
    message="Second trusted event",
    confidence=1.0,
    host_id="host-p11-9",
    sensor_id="sensor-p11-9",
)

envelope2 = (
    gateway.sign_event(
        event2
    )
)

second = gateway.admit(
    event2,
    envelope2["key_id"],
    envelope2["signature"],
)

print(
    "SECOND_ACCEPT=",
    second,
)

print(
    "SPOOL_PENDING_FINAL=",
    len(
        spool.pending_records()
    ),
)

print(
    "BUS_SIZE_FINAL=",
    bus.size(),
)


# ============================================================
# P11.9-08 DISPATCH
# ============================================================

print()
print(
    "=== P11.9-08 DISPATCH ==="
)

received = []

bus.subscribe(
    lambda event: received.append(
        event
    )
)

bus.dispatch_all()

print(
    "RECEIVED=",
    len(received),
)

print(
    "BUS_AFTER_DISPATCH=",
    bus.size(),
)


# ============================================================
# P11.9-09 ACK BOTH
# ============================================================

print()
print(
    "=== P11.9-09 ACK ==="
)

ack_count = 0

for received_event in received:

    if pipeline.ack(
        received_event.event_id
    ):
        ack_count += 1

print(
    "ACK_COUNT=",
    ack_count,
)

print(
    "PENDING_AFTER_ACK=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.9-10 STATS
# ============================================================

print()
print(
    "=== P11.9-10 STATS ==="
)

print(
    "GATEWAY_STATS=",
    gateway.get_stats(),
)

print(
    "PIPELINE_STATS=",
    pipeline.get_stats(),
)

print(
    "REPLAY_STATS=",
    replay_guard.get_stats(),
)

print(
    "SPOOL_STATS=",
    spool.get_stats(),
)

print(
    "BUS_STATS=",
    bus.get_stats(),
)


# ============================================================
# P11.9-11 HEALTH
# ============================================================

print()
print(
    "=== P11.9-11 HEALTH ==="
)

print(
    gateway.health_check()
)


# ============================================================
# P11.9-12 FINAL
# ============================================================

print()
print(
    "=== P11.9-12 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
