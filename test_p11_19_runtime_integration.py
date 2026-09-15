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
from agent.core.runtime_security_pipeline import (
    RuntimeSecurityPipeline,
)


ROOT = Path("state/test_p11_19_runtime_integration")

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

ROOT.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# SETUP
# ============================================================

print("=== P11.19-02 REAL RUNTIME INTEGRATION ===")

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

runtime = RuntimeSecurityPipeline(
    gateway,
)


# ============================================================
# KEY SETUP
# ============================================================

print()
print("=== 01 KEY SETUP ===")

key_id = key_manager.generate_key()

assert key_id is not None
assert key_manager.active_key_id() == key_id

print("KEY_CREATED=True")
print("ACTIVE_KEY=", key_id)


# ============================================================
# VALID EVENT
# ============================================================

print()
print("=== 02 VALID EVENT ===")

event = SecurityEvent(
    event_type="P11_19_RUNTIME_TEST",
    severity="HIGH",
    value=91,
    source="P11.19TestSensor",
    message="Runtime integration trusted event",
    confidence=0.99,
    host_id="host-p11-19",
    sensor_id="sensor-p11-19",
)

result = runtime.ingest(event)

print(
    "ACCEPTED=",
    result.accepted,
)

print(
    "REASON=",
    result.reason,
)

print(
    "STAGE=",
    result.stage,
)

assert result.accepted is True
assert result.event_id == event.event_id

print("VALID_EVENT_ADMISSION=PASS")


# ============================================================
# VERIFY DURABLE STORAGE
# ============================================================

print()
print("=== 03 DURABLE STORAGE ===")

pending = spool.pending_records()

print(
    "PENDING_COUNT=",
    len(pending),
)

assert len(pending) == 1

print("DURABLE_PERSISTENCE=PASS")


# ============================================================
# VERIFY EVENT BUS
# ============================================================

print()
print("=== 04 EVENT BUS ===")

print(
    "BUS_SIZE=",
    bus.size(),
)

assert bus.size() == 1

print("EVENT_BUS_ADMISSION=PASS")


# ============================================================
# REPLAY ATTACK
# ============================================================

print()
print("=== 05 REPLAY ATTACK ===")

replay_result = runtime.ingest(
    event
)

print(
    "REPLAY_ACCEPTED=",
    replay_result.accepted,
)

print(
    "REPLAY_REASON=",
    replay_result.reason,
)

print(
    "REPLAY_STAGE=",
    replay_result.stage,
)

assert replay_result.accepted is False

print("REPLAY_BLOCKED=PASS")


# ============================================================
# REPLAY MUST NOT CREATE SECOND RECORD
# ============================================================

print()
print("=== 06 REPLAY STORAGE ISOLATION ===")

pending_after_replay = spool.pending_records()

print(
    "PENDING_AFTER_REPLAY=",
    len(pending_after_replay),
)

print(
    "BUS_SIZE_AFTER_REPLAY=",
    bus.size(),
)

assert len(pending_after_replay) == 1
assert bus.size() == 1

print("NO_DUPLICATE_STORAGE=PASS")
print("NO_DUPLICATE_BUS_EVENT=PASS")


# ============================================================
# SECOND VALID EVENT
# ============================================================

print()
print("=== 07 SECOND VALID EVENT ===")

event2 = SecurityEvent(
    event_type="P11_19_SECOND_EVENT",
    severity="CRITICAL",
    value=100,
    source="P11.19TestSensor",
    message="Second trusted runtime event",
    confidence=1.0,
    host_id="host-p11-19",
    sensor_id="sensor-p11-19",
)

result2 = runtime.ingest(
    event2
)

print(
    "SECOND_ACCEPTED=",
    result2.accepted,
)

assert result2.accepted is True

assert len(
    spool.pending_records()
) == 2

assert bus.size() == 2

print("SECOND_EVENT_ADMISSION=PASS")


# ============================================================
# STATS
# ============================================================

print()
print("=== 08 STATS ===")

print(
    "RUNTIME_STATS=",
    runtime.get_stats(),
)

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

print(
    "BUS_STATS=",
    bus.get_stats(),
)


# ============================================================
# HEALTH
# ============================================================

print()
print("=== 09 HEALTH ===")

health = runtime.health_check()

print(
    "RUNTIME_HEALTH=",
    health,
)


# ============================================================
# FINAL ASSERTIONS
# ============================================================

print()
print("=== P11.19-02 RESULT ===")

print("VALID_EVENT_ACCEPTED=True")
print("DURABLE_PERSISTENCE=True")
print("EVENT_BUS_ADMISSION=True")
print("REPLAY_BLOCKED=True")
print("NO_DUPLICATE_STORAGE=True")
print("NO_DUPLICATE_BUS_EVENT=True")
print("SECOND_VALID_EVENT_ACCEPTED=True")
print("ALL_ASSERTIONS_PASS=True")
print("TEST_COMPLETE=True")
