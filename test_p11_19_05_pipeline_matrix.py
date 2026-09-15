from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.crypto.key_manager import generate_storage_key
from agent.crypto.key_manager import KeyManager


ROOT = Path(
    "state/test_p11_19_05_pipeline_matrix"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

ROOT.mkdir(
    parents=True,
    exist_ok=True,
)


def make_event(
    event_type="P11_19_05_EVENT",
    message="pipeline test",
):
    return SecurityEvent(
        event_type=event_type,
        severity="HIGH",
        value=90,
        source="P11.19.05TestSensor",
        message=message,
        confidence=0.99,
        host_id="host-p11-19-05",
        sensor_id="sensor-p11-19-05",
    )


def make_stack(name):
    root = ROOT / name

    bus = EventBus(
        100
    )

    spool = DurableEventSpool(
        root / "spool"
    )

    pipeline = DurableEventPipeline(
        spool,
        bus,
    )

    return spool, bus, pipeline


print(
    "=== P11.19.05 DURABLE PIPELINE FAILURE MATRIX ==="
)


# ============================================================
# 01 NORMAL INGEST
# ============================================================

print()
print("=== 01 NORMAL INGEST ===")

spool, bus, pipeline = make_stack(
    "01_normal"
)

event = make_event()

result = pipeline.ingest(
    event
)

assert result is True
assert len(spool.pending_records()) == 1
assert bus.size() == 1

print("INGEST=PASS")
print("DURABLE_RECORD=PASS")
print("BUS_PUBLICATION=PASS")


# ============================================================
# 02 INVALID OBJECT
# ============================================================

print()
print("=== 02 INVALID OBJECT ===")

spool, bus, pipeline = make_stack(
    "02_invalid_object"
)

result = pipeline.ingest(
    {"fake": "event"}
)

assert result is False
assert len(spool.pending_records()) == 0
assert bus.size() == 0

print("INVALID_OBJECT_REJECTED=PASS")
print("NO_STORAGE=PASS")
print("NO_BUS=PASS")


# ============================================================
# 03 TAMPERED EVENT
# ============================================================

print()
print("=== 03 TAMPERED EVENT ===")

spool, bus, pipeline = make_stack(
    "03_tampered"
)

event = make_event()

# Event yaratilib bo'lgandan keyin integrity'dagi
# signed/derived field'ni buzishga harakat qilamiz.
event.message = "ATTACKER MODIFIED EVENT"

result = pipeline.ingest(
    event
)

assert result is False
assert len(spool.pending_records()) == 0
assert bus.size() == 0

print("TAMPER_REJECTED=PASS")
print("NO_FALSE_STORAGE=PASS")
print("NO_FALSE_BUS=PASS")


# ============================================================
# 04 SPOOL FAILURE
# ============================================================

print()
print("=== 04 SPOOL FAILURE ===")

spool, bus, pipeline = make_stack(
    "04_spool_failure"
)

event = make_event()

original_append = spool.append


def failing_append(event):
    raise RuntimeError(
        "SIMULATED_SPOOL_FAILURE"
    )


spool.append = failing_append

try:
    result = pipeline.ingest(
        event
    )
finally:
    spool.append = original_append


assert result is False
assert len(spool.pending_records()) == 0
assert bus.size() == 0

print("SPOOL_FAILURE_REJECTED=PASS")
print("NO_FALSE_STORAGE=PASS")
print("NO_BUS_AFTER_SPOOL_FAILURE=PASS")


# ============================================================
# 05 BUS RETURN FALSE
# ============================================================

print()
print("=== 05 BUS RETURN FALSE ===")

spool, bus, pipeline = make_stack(
    "05_bus_false"
)

event = make_event()

original_publish = bus.publish


def failing_publish(event):
    return False


bus.publish = failing_publish

try:
    result = pipeline.ingest(
        event
    )
finally:
    bus.publish = original_publish


assert result is False

# MUHIM:
# spool commit bo'lgan bo'lishi kerak.
assert len(spool.pending_records()) == 1

print("BUS_FAILURE_REJECTED=PASS")
print("EVENT_REMAINS_PENDING=PASS")
print("NO_EVENT_LOSS=PASS")


# ============================================================
# 06 BUS EXCEPTION
# ============================================================

print()
print("=== 06 BUS EXCEPTION ===")

spool, bus, pipeline = make_stack(
    "06_bus_exception"
)

event = make_event()

original_publish = bus.publish


def raising_publish(event):
    raise RuntimeError(
        "SIMULATED_EVENT_BUS_CRASH"
    )


bus.publish = raising_publish

try:
    result = pipeline.ingest(
        event
    )
finally:
    bus.publish = original_publish


assert result is False
assert len(spool.pending_records()) == 1

print("BUS_EXCEPTION_REJECTED=PASS")
print("PENDING_PRESERVED=PASS")


# ============================================================
# 07 RECOVERY / PUBLISH PENDING
# ============================================================

print()
print("=== 07 PENDING RECOVERY ===")

spool, bus, pipeline = make_stack(
    "07_recovery"
)

event = make_event()

original_publish = bus.publish


def first_failure(event):
    return False


bus.publish = first_failure

try:
    result = pipeline.ingest(
        event
    )
finally:
    bus.publish = original_publish


assert result is False
assert len(spool.pending_records()) == 1

published = pipeline.publish_pending()

assert published == 1
assert bus.size() == 1
assert len(spool.pending_records()) == 1

print("PENDING_REMAINED=PASS")
print("RECOVERY_PUBLISH=PASS")
print("NO_PREMATURE_ACK=PASS")


# ============================================================
# 08 ACK SUCCESS
# ============================================================

print()
print("=== 08 ACK SUCCESS ===")

event_id = event.event_id

ack_result = pipeline.ack(
    event_id
)

assert ack_result is True
assert len(spool.pending_records()) == 0

print("ACK_SUCCESS=PASS")
print("PENDING_REMOVED=PASS")


# ============================================================
# 09 DUPLICATE ACK
# ============================================================

print()
print("=== 09 DUPLICATE ACK ===")

duplicate_ack = pipeline.ack(
    event_id
)

assert duplicate_ack is False

print("DUPLICATE_ACK_REJECTED=PASS")


# ============================================================
# 10 RESTART PERSISTENCE
# ============================================================

print()
print("=== 10 RESTART PERSISTENCE ===")

spool, bus, pipeline = make_stack(
    "10_restart"
)

event = make_event(
    event_type="P11_19_05_RESTART"
)

result = pipeline.ingest(
    event
)

assert result is True

event_id = event.event_id

# Yangi process/object sifatida qayta ochish.
spool2 = DurableEventSpool(
    ROOT / "10_restart" / "spool"
)

bus2 = EventBus(
    100
)

pipeline2 = DurableEventPipeline(
    spool2,
    bus2,
)

pending = spool2.pending_records()

assert len(pending) == 1
assert pending[0]["event_id"] == event_id

print("RESTART_PERSISTENCE=PASS")
print("PENDING_SURVIVES_RESTART=PASS")


# ============================================================
# 11 CORRUPTED PENDING RECORD
# ============================================================

print()
print("=== 11 CORRUPTED PENDING RECORD ===")

spool, bus, pipeline = make_stack(
    "11_corrupted"
)

event = make_event(
    event_type="P11_19_05_CORRUPTION"
)

assert pipeline.ingest(event) is True

records = spool.pending_records()

assert len(records) == 1

corrupted = dict(
    records[0]
)

corrupted["event"] = {
    "event_id": event.event_id,
    "message": "ATTACKER CORRUPTED RECORD",
}

class CorruptedSpool:
    def pending_records(self):
        return [corrupted]


corrupted_spool = CorruptedSpool()

corrupted_bus = EventBus(
    100
)

corrupted_pipeline = DurableEventPipeline(
    corrupted_spool,
    corrupted_bus,
)

published = corrupted_pipeline.publish_pending()

assert published == 0
assert corrupted_bus.size() == 0

print("CORRUPTED_RECORD_BLOCKED=PASS")
print("NO_FALSE_BUS_PUBLICATION=PASS")


# ============================================================
# 12 IDENTITY MISMATCH
# ============================================================

print()
print("=== 12 EVENT ID MISMATCH ===")

event = make_event(
    event_type="P11_19_05_ID_MISMATCH"
)

record = {
    "event_id": "attacker-controlled-id",
    "event": event.to_dict(),
}


class IdentityMismatchSpool:
    def pending_records(self):
        return [record]


identity_bus = EventBus(
    100
)

identity_pipeline = DurableEventPipeline(
    IdentityMismatchSpool(),
    identity_bus,
)

published = identity_pipeline.publish_pending()

assert published == 0
assert identity_bus.size() == 0

print("IDENTITY_MISMATCH_BLOCKED=PASS")


# ============================================================
# 13 REPEATED PENDING PUBLISH
# ============================================================

print()
print("=== 13 REPEATED PENDING PUBLISH ===")

spool, bus, pipeline = make_stack(
    "13_repeated_publish"
)

event = make_event(
    event_type="P11_19_05_REPEATED"
)

assert pipeline.ingest(event) is True

# Birinchi publish allaqachon ingest ichida bo'lgan.
first = pipeline.publish_pending()

# Ikkinchi publish yana delivery qilishi mumkin.
second = pipeline.publish_pending()

assert first == 1
assert second == 1

# AT-LEAST-ONCE semantics:
# duplicate delivery mumkin,
# ACK qilinmaguncha pending qoladi.
assert len(spool.pending_records()) == 1

print("REPEATED_DELIVERY_EXPECTED=PASS")
print("AT_LEAST_ONCE_SEMANTICS=PASS")
print("NO_PREMATURE_ACK=PASS")


# ============================================================
# 14 EVENT BUS CAPACITY PRESSURE
# ============================================================

print()
print("=== 14 EVENT BUS CAPACITY PRESSURE ===")

root = ROOT / "14_capacity"

small_bus = EventBus(
    1
)

small_spool = DurableEventSpool(
    root / "spool"
)

small_pipeline = DurableEventPipeline(
    small_spool,
    small_bus,
)

event_a = make_event(
    event_type="P11_19_05_CAPACITY_A"
)

event_b = make_event(
    event_type="P11_19_05_CAPACITY_B"
)

result_a = small_pipeline.ingest(
    event_a
)

result_b = small_pipeline.ingest(
    event_b
)

assert result_a is True

# Bus capacity failure event B uchun
# spool state'ni yo'qotmasligi kerak.
assert result_b is False
assert len(small_spool.pending_records()) == 2

print("CAPACITY_PRESSURE_HANDLED=PASS")
print("UNPUBLISHED_EVENT_PRESERVED=PASS")


# ============================================================
# FINAL STATS
# ============================================================

print()
print("=== 15 FINAL ===")

print(
    "NORMAL_PIPELINE=PASS"
)

print(
    "INVALID_INPUT_REJECTION=PASS"
)

print(
    "TAMPER_REJECTION=PASS"
)

print(
    "SPOOL_FAILURE_HANDLING=PASS"
)

print(
    "BUS_FAILURE_HANDLING=PASS"
)

print(
    "BUS_EXCEPTION_HANDLING=PASS"
)

print(
    "PENDING_RECOVERY=PASS"
)

print(
    "ACK_SEMANTICS=PASS"
)

print(
    "RESTART_PERSISTENCE=PASS"
)

print(
    "CORRUPTED_RECORD_REJECTION=PASS"
)

print(
    "IDENTITY_BINDING=PASS"
)

print(
    "AT_LEAST_ONCE=PASS"
)

print(
    "CAPACITY_PRESSURE=PASS"
)

print()
print(
    "=== P11.19.05 RESULT ==="
)

print(
    "TEST_COMPLETE=True"
)
