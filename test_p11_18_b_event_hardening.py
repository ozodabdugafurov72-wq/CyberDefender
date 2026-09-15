from __future__ import annotations

from agent.event import SecurityEvent


def expect_reject(label, callback):
    try:
        callback()
    except (TypeError, ValueError):
        print(f"{label}= PASS")
        return True

    print(f"{label}= FAIL")
    return False


print()
print("=== P11.18-B SECURITY EVENT HARDENING ===")


# =========================================================
# 01 CREATE EVENT
# =========================================================

event = SecurityEvent(
    event_type="P11_18_B_TEST",
    severity="warning",
    value=87.5,
    source="SecurityTest",
    message="Security event integrity test",
    confidence=0.95,
    host_id="host-test",
    asset_id="asset-test",
    sensor_id="sensor-test",
    tenant_id="tenant-test",
    correlation_keys=[
        "host-test",
        "process-test",
        "host-test",
    ],
    provenance={
        "sensor": "SecurityTest",
        "version": "1.0",
    },
    action="OBSERVE_ONLY",
)

print("EVENT_CREATED=", True)
print("EVENT_ID=", event.event_id)
print("SEVERITY_NORMALIZED=", event.severity)
print("INTEGRITY_VALID=", event.verify_integrity())


# =========================================================
# 02 JSON ROUND TRIP
# =========================================================

serialized = event.to_json()

restored = SecurityEvent.from_json(
    serialized
)

print()
print("=== ROUND TRIP ===")

print(
    "EVENT_ID_PRESERVED=",
    restored.event_id == event.event_id,
)

print(
    "INTEGRITY_PRESERVED=",
    restored.integrity == event.integrity,
)

print(
    "ROUND_TRIP_INTEGRITY=",
    restored.verify_integrity(),
)


# =========================================================
# 03 MESSAGE TAMPERING
# =========================================================

tampered = event.to_dict()
tampered["message"] = "ATTACKER MODIFIED THIS"

message_rejected = expect_reject(
    "MESSAGE_TAMPERING_REJECTED",
    lambda: SecurityEvent.from_dict(
        tampered
    ),
)


# =========================================================
# 04 SEVERITY TAMPERING
# =========================================================

tampered = event.to_dict()
tampered["severity"] = "CRITICAL"

severity_rejected = expect_reject(
    "SEVERITY_TAMPERING_REJECTED",
    lambda: SecurityEvent.from_dict(
        tampered
    ),
)


# =========================================================
# 05 EVENT ID TAMPERING
# =========================================================

tampered = event.to_dict()
tampered["event_id"] = (
    "00000000-0000-0000-0000-000000000000"
)

event_id_rejected = expect_reject(
    "EVENT_ID_TAMPERING_REJECTED",
    lambda: SecurityEvent.from_dict(
        tampered
    ),
)


# =========================================================
# 06 PROVENANCE TAMPERING
# =========================================================

tampered = event.to_dict()
tampered["provenance"] = {
    "sensor": "ATTACKER"
}

provenance_rejected = expect_reject(
    "PROVENANCE_TAMPERING_REJECTED",
    lambda: SecurityEvent.from_dict(
        tampered
    ),
)


# =========================================================
# 07 INVALID CONFIDENCE
# =========================================================

confidence_rejected = expect_reject(
    "INVALID_CONFIDENCE_REJECTED",
    lambda: SecurityEvent(
        event_type="TEST",
        severity="LOW",
        value=1,
        source="TEST",
        message="TEST",
        confidence=2.0,
    ),
)


# =========================================================
# 08 INVALID CORRELATION KEYS
# =========================================================

correlation_rejected = expect_reject(
    "INVALID_CORRELATION_KEYS_REJECTED",
    lambda: SecurityEvent(
        event_type="TEST",
        severity="LOW",
        value=1,
        source="TEST",
        message="TEST",
        correlation_keys="not-a-list",
    ),
)


# =========================================================
# 09 INVALID SCHEMA
# =========================================================

tampered = event.to_dict()
tampered["schema_version"] = "99.0"

schema_rejected = expect_reject(
    "INVALID_SCHEMA_REJECTED",
    lambda: SecurityEvent.from_dict(
        tampered
    ),
)


# =========================================================
# 10 INVALID INTEGRITY
# =========================================================

tampered = event.to_dict()
tampered["integrity"] = "abc"

integrity_format_rejected = expect_reject(
    "INVALID_INTEGRITY_FORMAT_REJECTED",
    lambda: SecurityEvent.from_dict(
        tampered
    ),
)


# =========================================================
# 11 NON-JSON VALUE
# =========================================================

non_json_rejected = expect_reject(
    "NON_JSON_VALUE_REJECTED",
    lambda: SecurityEvent(
        event_type="TEST",
        severity="LOW",
        value=object(),
        source="TEST",
        message="TEST",
    ),
)


# =========================================================
# 12 DEFENSIVE COPY
# =========================================================

keys = [
    "original"
]

provenance = {
    "origin": "trusted"
}

mutable_event = SecurityEvent(
    event_type="MUTABLE_TEST",
    severity="INFO",
    value={
        "nested": "original"
    },
    source="TEST",
    message="Mutable input test",
    correlation_keys=keys,
    provenance=provenance,
)

keys.append(
    "attacker-added"
)

provenance["origin"] = "attacker"

print()
print("=== DEFENSIVE COPY ===")

defensive_copy_valid = (
    mutable_event.correlation_keys
    == ["original"]
    and
    mutable_event.provenance["origin"]
    == "trusted"
)

print(
    "DEFENSIVE_COPY_VALID=",
    defensive_copy_valid,
)

print(
    "MUTABLE_EVENT_INTEGRITY=",
    mutable_event.verify_integrity(),
)


# =========================================================
# FINAL RESULT
# =========================================================

all_pass = all(
    [
        event.verify_integrity(),
        restored.event_id == event.event_id,
        restored.integrity == event.integrity,
        restored.verify_integrity(),
        message_rejected,
        severity_rejected,
        event_id_rejected,
        provenance_rejected,
        confidence_rejected,
        correlation_rejected,
        schema_rejected,
        integrity_format_rejected,
        non_json_rejected,
        defensive_copy_valid,
        mutable_event.verify_integrity(),
    ]
)


print()
print("=== P11.18-B RESULT ===")

print(
    "EVENT_INTEGRITY_VALID=",
    event.verify_integrity(),
)

print(
    "TAMPERING_REJECTION_VALID=",
    all(
        [
            message_rejected,
            severity_rejected,
            event_id_rejected,
            provenance_rejected,
        ]
    ),
)

print(
    "SCHEMA_VALIDATION_VALID=",
    all(
        [
            confidence_rejected,
            correlation_rejected,
            schema_rejected,
            integrity_format_rejected,
            non_json_rejected,
        ]
    ),
)

print(
    "DEFENSIVE_COPY_VALID=",
    defensive_copy_valid,
)

print(
    "ROUND_TRIP_VALID=",
    (
        restored.event_id == event.event_id
        and
        restored.integrity == event.integrity
        and
        restored.verify_integrity()
    ),
)

print(
    "ALL_ASSERTIONS_PASS=",
    all_pass,
)

print(
    "TEST_COMPLETE=",
    all_pass,
)

assert all_pass
