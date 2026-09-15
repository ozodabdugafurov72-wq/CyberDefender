from agent.event import SecurityEvent
from agent.crypto.trust import (
    CryptographicTrust,
    TrustedEventEnvelope,
)

trust = CryptographicTrust.generate()

event = SecurityEvent(
    event_type="P11_VALID_EVENT",
    severity="HIGH",
    value=91.7,
    source="P11TestSensor",
    message="Cryptographic trust test",
    confidence=0.99,
    host_id="host-p11",
    sensor_id="sensor-p11",
)

envelope = TrustedEventEnvelope(
    event,
    trust,
)

data = envelope.to_dict()

print("=== P11-01 VALID SIGNATURE ===")
print("EVENT_ID=", event.event_id)
print("ALGORITHM=", trust.health_check()["algorithm"])
print("SIGNATURE_PRESENT=", bool(data["signature"]))
print(
    "VERIFY=",
    TrustedEventEnvelope.verify_envelope(data),
)


print()
print("=== P11-02 TAMPER REJECTION ===")

tampered = dict(data)

tampered["event"] = dict(
    data["event"]
)

tampered["event"]["message"] = (
    "ATTACKER MODIFIED THIS"
)

print(
    "VERIFY_TAMPERED=",
    TrustedEventEnvelope.verify_envelope(
        tampered
    ),
)


print()
print("=== P11-03 SIGNATURE MODIFICATION ===")

bad_signature = dict(data)

bad_signature["signature"] = (
    "AAAA"
)

print(
    "VERIFY_BAD_SIGNATURE=",
    TrustedEventEnvelope.verify_envelope(
        bad_signature
    ),
)


print()
print("=== P11-04 WRONG PUBLIC KEY ===")

wrong_trust = CryptographicTrust.generate()

wrong_key = dict(data)

wrong_key["public_key"] = (
    wrong_trust.export_public_key()
)

print(
    "VERIFY_WRONG_KEY=",
    TrustedEventEnvelope.verify_envelope(
        wrong_key
    ),
)


print()
print("=== P11-05 REPLAY / SAME SIGNATURE ===")

replay = dict(data)

print(
    "FIRST_VERIFY=",
    TrustedEventEnvelope.verify_envelope(
        data
    ),
)

print(
    "SECOND_VERIFY=",
    TrustedEventEnvelope.verify_envelope(
        replay
    ),
)

print()
print("=== P11-06 HEALTH ===")

print(
    trust.health_check()
)
