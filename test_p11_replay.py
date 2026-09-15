from agent.event import SecurityEvent
from agent.crypto.trust import (
    CryptographicTrust,
    TrustedEventEnvelope,
)
from agent.crypto.replay_guard import (
    ReplayGuard,
)


def verify_and_accept(
    envelope: dict,
    replay_guard: ReplayGuard,
) -> bool:
    """
    Security order:

        1. Cryptographic verification
        2. Replay verification

    Muhim:
    ReplayGuard'ga event ID faqat signature valid
    bo'lgandan keyin beriladi.
    """

    if not TrustedEventEnvelope.verify_envelope(
        envelope
    ):
        return False

    event_data = envelope.get(
        "event"
    )

    if not isinstance(
        event_data,
        dict,
    ):
        return False

    event_id = event_data.get(
        "event_id"
    )

    return replay_guard.check_and_remember(
        event_id
    )


print(
    "=== P11.2-01 FIRST EVENT ==="
)

trust = CryptographicTrust.generate()

event = SecurityEvent(
    event_type="P11_REPLAY_TEST",
    severity="HIGH",
    value=100,
    source="ReplayTestSensor",
    message="Replay protection test",
    confidence=0.99,
    host_id="host-p11",
    sensor_id="sensor-p11",
)

envelope = TrustedEventEnvelope(
    event,
    trust,
).to_dict()

guard = ReplayGuard(
    max_entries=100,
)

first = verify_and_accept(
    envelope,
    guard,
)

print(
    "FIRST_ACCEPT=",
    first,
)

print(
    "TRACKED=",
    guard.size(),
)


print()
print(
    "=== P11.2-02 SAME EVENT REPLAY ==="
)

second = verify_and_accept(
    envelope,
    guard,
)

print(
    "SECOND_ACCEPT=",
    second,
)

print(
    "TRACKED=",
    guard.size(),
)


print()
print(
    "=== P11.2-03 TAMPERED EVENT ==="
)

tampered = dict(
    envelope
)

tampered["event"] = dict(
    envelope["event"]
)

tampered["event"]["message"] = (
    "ATTACKER MODIFIED"
)

third = verify_and_accept(
    tampered,
    guard,
)

print(
    "TAMPER_ACCEPT=",
    third,
)

print(
    "TRACKED_AFTER_TAMPER=",
    guard.size(),
)


print()
print(
    "=== P11.2-04 INVALID EVENT ID ==="
)

invalid_id_event = dict(
    envelope
)

invalid_id_event["event"] = dict(
    envelope["event"]
)

invalid_id_event["event"]["event_id"] = ""

invalid_id = verify_and_accept(
    invalid_id_event,
    guard,
)

print(
    "INVALID_ID_ACCEPT=",
    invalid_id,
)


print()
print(
    "=== P11.2-05 DIFFERENT EVENT ==="
)

event2 = SecurityEvent(
    event_type="P11_REPLAY_TEST_2",
    severity="MEDIUM",
    value=50,
    source="ReplayTestSensor",
    message="Second unique event",
    confidence=0.95,
    host_id="host-p11",
    sensor_id="sensor-p11",
)

envelope2 = TrustedEventEnvelope(
    event2,
    trust,
).to_dict()

unique = verify_and_accept(
    envelope2,
    guard,
)

print(
    "SECOND_UNIQUE_ACCEPT=",
    unique,
)

print(
    "TRACKED_FINAL=",
    guard.size(),
)


print()
print(
    "=== P11.2-06 STATS ==="
)

print(
    guard.get_stats()
)


print()
print(
    "=== P11.2-07 HEALTH ==="
)

print(
    guard.health_check()
)
