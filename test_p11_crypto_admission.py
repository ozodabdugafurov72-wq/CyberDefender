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
from agent.core.crypto_admission_gateway import (
    CryptoAdmissionGateway,
)


ROOT = Path(
    "state/test_p11_crypto_admission"
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

spool = DurableEventSpool(
    spool_root
)

pipeline = DurableEventPipeline(
    spool,
    bus,
)

gateway = CryptoAdmissionGateway(
    key_manager,
    pipeline,
)


# ============================================================
# P11.8-01 KEY CREATION
# ============================================================

print(
    "=== P11.8-01 KEY CREATION ==="
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
# P11.8-02 TRUSTED EVENT
# ============================================================

print()
print(
    "=== P11.8-02 TRUSTED EVENT ==="
)

event = SecurityEvent(
    event_type="P11_8_TRUSTED_EVENT",
    severity="HIGH",
    value=91,
    source="P11.8TestSensor",
    message="Trusted admission test",
    confidence=0.99,
    host_id="host-p11-8",
    sensor_id="sensor-p11-8",
)

envelope = (
    gateway.sign_event(
        event
    )
)

print(
    "EVENT_ID=",
    event.event_id,
)

print(
    "ENVELOPE_KEY_ID=",
    envelope["key_id"],
)

print(
    "SIGNATURE_PRESENT=",
    bool(
        envelope["signature"]
    ),
)

print(
    "ALGORITHM=",
    envelope["algorithm"],
)


# ============================================================
# P11.8-03 TRUSTED ADMISSION
# ============================================================

print()
print(
    "=== P11.8-03 TRUSTED ADMISSION ==="
)

accepted = gateway.admit(
    event,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "ADMITTED=",
    accepted,
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
# P11.8-04 TAMPERED EVENT
# ============================================================

print()
print(
    "=== P11.8-04 TAMPERED EVENT ==="
)

tampered = SecurityEvent(
    event_type="P11_8_TRUSTED_EVENT",
    severity="HIGH",
    value=91,
    source="P11.8TestSensor",
    message="ATTACKER MODIFIED EVENT",
    confidence=0.99,
    host_id="host-p11-8",
    sensor_id="sensor-p11-8",
)

tampered_result = gateway.admit(
    tampered,
    envelope["key_id"],
    envelope["signature"],
)

print(
    "TAMPER_ADMITTED=",
    tampered_result,
)

print(
    "SPOOL_PENDING_AFTER_TAMPER=",
    len(
        spool.pending_records()
    ),
)

print(
    "BUS_SIZE_AFTER_TAMPER=",
    bus.size(),
)


# ============================================================
# P11.8-05 WRONG SIGNATURE
# ============================================================

print()
print(
    "=== P11.8-05 WRONG SIGNATURE ==="
)

wrong_signature_result = (
    gateway.admit(
        event,
        envelope["key_id"],
        "00" * 32,
    )
)

print(
    "WRONG_SIGNATURE_ADMITTED=",
    wrong_signature_result,
)

print(
    "SPOOL_PENDING_AFTER_BAD_SIGNATURE=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.8-06 UNKNOWN KEY
# ============================================================

print()
print(
    "=== P11.8-06 UNKNOWN KEY ==="
)

unknown_key_result = (
    gateway.admit(
        event,
        "key-attacker-controlled",
        envelope["signature"],
    )
)

print(
    "UNKNOWN_KEY_ADMITTED=",
    unknown_key_result,
)

print(
    "SPOOL_PENDING_AFTER_UNKNOWN_KEY=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.8-07 RETIRED KEY
# ============================================================

print()
print(
    "=== P11.8-07 RETIRED KEY ==="
)

key2 = (
    key_manager.rotate()
)

print(
    "NEW_ACTIVE_KEY=",
    key2,
)

retired_result = gateway.admit(
    event,
    key_id,
    envelope["signature"],
)

print(
    "RETIRED_KEY_ADMITTED=",
    retired_result,
)

print(
    "SPOOL_PENDING_AFTER_RETIRED=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.8-08 NEW ACTIVE EVENT
# ============================================================

print()
print(
    "=== P11.8-08 NEW ACTIVE EVENT ==="
)

event2 = SecurityEvent(
    event_type="P11_8_NEW_ACTIVE_EVENT",
    severity="CRITICAL",
    value=100,
    source="P11.8TestSensor",
    message="New active key event",
    confidence=1.0,
    host_id="host-p11-8",
    sensor_id="sensor-p11-8",
)

envelope2 = (
    gateway.sign_event(
        event2
    )
)

active_result = gateway.admit(
    event2,
    envelope2["key_id"],
    envelope2["signature"],
)

print(
    "ACTIVE_EVENT_ADMITTED=",
    active_result,
)

print(
    "ACTIVE_KEY_USED=",
    envelope2["key_id"],
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
# P11.8-09 DISPATCH
# ============================================================

print()
print(
    "=== P11.8-09 BUS DISPATCH ==="
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
    "BUS_SIZE_AFTER_DISPATCH=",
    bus.size(),
)


# ============================================================
# P11.8-10 ACK
# ============================================================

print()
print(
    "=== P11.8-10 ACK ==="
)

if received:
    ack_result = (
        pipeline.ack(
            received[0].event_id
        )
    )
else:
    ack_result = False

print(
    "ACK=",
    ack_result,
)

print(
    "PENDING_AFTER_ACK=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.8-11 STATS
# ============================================================

print()
print(
    "=== P11.8-11 STATS ==="
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
    "SPOOL_STATS=",
    spool.get_stats(),
)

print(
    "BUS_STATS=",
    bus.get_stats(),
)


# ============================================================
# P11.8-12 HEALTH
# ============================================================

print()
print(
    "=== P11.8-12 HEALTH ==="
)

print(
    gateway.health_check()
)


# ============================================================
# P11.8-13 FINAL
# ============================================================

print()
print(
    "=== P11.8-13 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
