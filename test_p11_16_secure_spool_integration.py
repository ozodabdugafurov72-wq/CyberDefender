from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool
from agent.quarantine.vault import SecureQuarantineVault


# ============================================================
# P11.16 — SECURE SPOOL + QUARANTINE INTEGRATION
# ============================================================
#
# Security invariants:
#
# 1. Valid events are recoverable.
# 2. Tampered events never reach the consumer.
# 3. Tampered events are never ACKed.
# 4. Invalid events are quarantined.
# 5. Raw evidence is preserved.
# 6. Evidence SHA-256 remains verifiable.
# 7. Valid events are isolated from invalid events.
# 8. Repeated recovery does not redeliver ACKed events.
# 9. Repeated quarantine does not create uncontrolled duplicates.
# 10. Quarantine is restore-by-default=false.
#
# IMPORTANT:
#
# DurableEventSpool does NOT accept quarantine_vault
# in its constructor.
#
# Therefore quarantine is explicitly integrated at the
# recovery boundary using the raw pending record.
#
# ============================================================


ROOT = Path(
    "state/test_p11_16_secure_spool_integration"
)

# Clean isolated test environment.
shutil.rmtree(
    ROOT,
    ignore_errors=True,
)


# ============================================================
# P11.16-01 CREATE SECURE QUARANTINE
# ============================================================

print(
    "=== P11.16-01 CREATE SECURE QUARANTINE ==="
)

vault = SecureQuarantineVault(
    ROOT / "quarantine"
)

print(
    "VAULT_HEALTH=",
    vault.health_check()
)


# ============================================================
# P11.16-02 CREATE DURABLE SPOOL
# ============================================================

print()
print(
    "=== P11.16-02 CREATE DURABLE SPOOL ==="
)

spool = DurableEventSpool(
    ROOT / "spool",
    quarantine_vault=vault,
)

print(
    "SPOOL_STATS=",
    spool.get_stats()
)


# ============================================================
# P11.16-03 CREATE EVENTS
# ============================================================

print()
print(
    "=== P11.16-03 CREATE EVENTS ==="
)


event_a = SecurityEvent(
    event_type="P11_16_VALID_A",
    severity="HIGH",
    value=80,
    source="P11.16Sensor",
    message="Valid event A",
    confidence=0.99,
    host_id="host-p11-16",
    sensor_id="sensor-p11-16",
)


event_b = SecurityEvent(
    event_type="P11_16_TAMPER_TARGET",
    severity="CRITICAL",
    value=99,
    source="P11.16Sensor",
    message="Original event B",
    confidence=1.0,
    host_id="host-p11-16",
    sensor_id="sensor-p11-16",
)


event_c = SecurityEvent(
    event_type="P11_16_VALID_C",
    severity="MEDIUM",
    value=50,
    source="P11.16Sensor",
    message="Valid event C",
    confidence=0.95,
    host_id="host-p11-16",
    sensor_id="sensor-p11-16",
)


print(
    "EVENT_A=",
    event_a.event_id,
)

print(
    "EVENT_B=",
    event_b.event_id,
)

print(
    "EVENT_C=",
    event_c.event_id,
)


# ============================================================
# P11.16-04 APPEND EVENTS
# ============================================================

print()
print(
    "=== P11.16-04 APPEND EVENTS ==="
)

append_a = spool.append(
    event_a
)

append_b = spool.append(
    event_b
)

append_c = spool.append(
    event_c
)


print(
    "APPEND_A=",
    append_a,
)

print(
    "APPEND_B=",
    append_b,
)

print(
    "APPEND_C=",
    append_c,
)

print(
    "PENDING_INITIAL=",
    len(
        spool.pending_records()
    ),
)


# ============================================================
# P11.16-05 SAVE ORIGINAL RAW RECORD
# ============================================================
#
# We save B's original raw record before tampering.
# This lets us prove that the quarantine operation preserves
# the exact evidence presented to the recovery boundary.
#
# ============================================================

print()
print(
    "=== P11.16-05 SAVE ORIGINAL RAW RECORD ==="
)

records_before_tamper = (
    spool.pending_records()
)

original_b_record = None

for record in records_before_tamper:

    if (
        record.get("event_id")
        == event_b.event_id
    ):
        original_b_record = record
        break


assert original_b_record is not None


# ============================================================
# P11.16-06 TAMPER EVENT B
# ============================================================

print()
print(
    "=== P11.16-06 TAMPER EVENT B ==="
)

pending_path = (
    ROOT
    / "spool"
    / "pending.jsonl"
)

if not pending_path.exists():

    # Fallback: locate actual pending file.
    candidates = list(
        (
            ROOT
            / "spool"
        ).glob(
            "*pending*"
        )
    )

    if not candidates:
        raise RuntimeError(
            "Pending storage file topilmadi."
        )

    pending_path = candidates[0]


lines = (
    pending_path
    .read_text(
        encoding="utf-8"
    )
    .splitlines()
)


tampered_lines = []

for line in lines:

    record = json.loads(
        line
    )

    if (
        record.get("event_id")
        == event_b.event_id
    ):

        event_data = record.get(
            "event"
        )

        if not isinstance(
            event_data,
            dict,
        ):
            raise RuntimeError(
                "Event B record strukturasi noto'g'ri."
            )

        event_data["message"] = (
            "ATTACKER MODIFIED EVENT B"
        )

        record["event"] = (
            event_data
        )

        tampered_lines.append(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    else:

        tampered_lines.append(
            line
        )


pending_path.write_text(
    "\n".join(
        tampered_lines
    )
    + "\n",
    encoding="utf-8",
)


print(
    "TAMPER_TARGET=",
    event_b.event_id,
)

print(
    "TAMPERED_MESSAGE=",
    "ATTACKER MODIFIED EVENT B",
)


# ============================================================
# P11.16-07 VERIFY TAMPERED RAW RECORD
# ============================================================

print()
print(
    "=== P11.16-07 VERIFY TAMPERED RAW RECORD ==="
)

raw_pending_after_tamper = (
    spool.pending_records()
)

tampered_b_record = None

for record in raw_pending_after_tamper:

    if (
        record.get("event_id")
        == event_b.event_id
    ):
        tampered_b_record = record
        break


assert tampered_b_record is not None


print(
    "RAW_PENDING_COUNT=",
    len(
        raw_pending_after_tamper
    ),
)

print(
    "TAMPERED_B_PRESENT=",
    tampered_b_record is not None,
)


# ============================================================
# P11.16-08 FIRST RECOVERY
# ============================================================

print()
print(
    "=== P11.16-08 FIRST RECOVERY ==="
)

recovered_ids: list[str] = []


def consumer(
    event: SecurityEvent,
) -> bool:

    recovered_ids.append(
        event.event_id
    )

    print(
        "CONSUMER_EVENT=",
        event.event_id,
    )

    return True


recovered_count = (
    spool.replay_events(
        consumer
    )
)


print(
    "RECOVERED_COUNT=",
    recovered_count,
)

print(
    "RECOVERED_IDS=",
    recovered_ids,
)


# ============================================================
# P11.16-09 VALID EVENT ISOLATION
# ============================================================

print()
print(
    "=== P11.16-09 VALID EVENT ISOLATION ==="
)

a_recovered = (
    event_a.event_id
    in recovered_ids
)

b_recovered = (
    event_b.event_id
    in recovered_ids
)

c_recovered = (
    event_c.event_id
    in recovered_ids
)


print(
    "A_RECOVERED=",
    a_recovered,
)

print(
    "B_RECOVERED=",
    b_recovered,
)

print(
    "C_RECOVERED=",
    c_recovered,
)


# ============================================================
# P11.16-10 QUARANTINE TAMPERED EVENT
# ============================================================
#
# DurableEventSpool correctly refuses to deserialize B.
#
# Because replay_events() intentionally does not invoke the
# consumer for invalid events, quarantine is performed here
# at the integration boundary using the tampered raw record.
#
# ============================================================

print()
print(
    "=== P11.16-10 QUARANTINE TAMPERED EVENT ==="
)


tampered_raw_bytes = json.dumps(
    tampered_b_record,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode(
    "utf-8"
)


quarantine_record = (
    vault.quarantine(
        raw_record=tampered_raw_bytes,
        reason=(
            "SECURITY_EVENT_DESERIALIZATION_FAILURE"
        ),
        source="DurableEventSpool",
        event_id=event_b.event_id,
        failure_type="INVALID_SECURITY_EVENT",
    )
)


print(
    "QUARANTINED=",
    True,
)

print(
    "QUARANTINE_ID=",
    quarantine_record[
        "quarantine_id"
    ],
)

print(
    "EVENT_ID=",
    quarantine_record[
        "event_id"
    ],
)

print(
    "STATUS=",
    quarantine_record[
        "status"
    ],
)

print(
    "FAILURE_TYPE=",
    quarantine_record[
        "failure_type"
    ],
)

print(
    "REASON=",
    quarantine_record[
        "reason"
    ],
)

print(
    "RAW_SHA256=",
    quarantine_record[
        "raw_sha256"
    ],
)

print(
    "RAW_SIZE=",
    quarantine_record[
        "raw_size"
    ],
)

print(
    "RESTORE_ALLOWED=",
    quarantine_record[
        "restore_allowed"
    ],
)


# ============================================================
# P11.16-11 VERIFY QUARANTINE EVIDENCE
# ============================================================

print()
print(
    "=== P11.16-11 VERIFY QUARANTINE EVIDENCE ==="
)

evidence_valid = (
    vault.verify_evidence(
        quarantine_record[
            "quarantine_id"
        ]
    )
)


print(
    "EVIDENCE_VERIFY=",
    evidence_valid,
)


# ============================================================
# P11.16-12 READ QUARANTINE METADATA
# ============================================================

print()
print(
    "=== P11.16-12 READ QUARANTINE METADATA ==="
)

record_from_vault = (
    vault.get_record(
        quarantine_record[
            "quarantine_id"
        ]
    )
)


print(
    "RECORD_PRESENT=",
    record_from_vault is not None,
)

if record_from_vault is not None:

    print(
        "STATUS=",
        record_from_vault[
            "status"
        ],
    )

    print(
        "FAILURE_TYPE=",
        record_from_vault[
            "failure_type"
        ],
    )

    print(
        "REASON=",
        record_from_vault[
            "reason"
        ],
    )


# ============================================================
# P11.16-13 VERIFY EXACT EVIDENCE HASH
# ============================================================

print()
print(
    "=== P11.16-13 VERIFY EXACT EVIDENCE ==="
)

expected_sha256 = (
    SecureQuarantineVault.sha256(
        tampered_raw_bytes
    )
)


stored_sha256 = (
    quarantine_record[
        "raw_sha256"
    ]
)


print(
    "EXPECTED_SHA256=",
    expected_sha256,
)

print(
    "STORED_SHA256=",
    stored_sha256,
)

print(
    "SHA256_MATCH=",
    expected_sha256
    == stored_sha256,
)


# ============================================================
# P11.16-14 REPEATED QUARANTINE ATTEMPT
# ============================================================
#
# The same exact evidence is submitted again.
#
# The vault should recognize the same evidence hash rather
# than create uncontrolled duplicate evidence records.
#
# ============================================================

print()
print(
    "=== P11.16-14 REPEATED QUARANTINE ATTEMPT ==="
)

records_before_duplicate = (
    vault.list_records()
)

duplicate_record = (
    vault.quarantine(
        raw_record=tampered_raw_bytes,
        reason=(
            "SECURITY_EVENT_DESERIALIZATION_FAILURE"
        ),
        source="DurableEventSpool",
        event_id=event_b.event_id,
        failure_type="INVALID_SECURITY_EVENT",
    )
)

records_after_duplicate = (
    vault.list_records()
)


print(
    "FIRST_RECORD_COUNT=",
    len(
        records_before_duplicate
    ),
)

print(
    "FINAL_RECORD_COUNT=",
    len(
        records_after_duplicate
    ),
)

print(
    "DUPLICATE_QUARANTINE_ID=",
    duplicate_record[
        "quarantine_id"
    ],
)


# ============================================================
# P11.16-15 SECOND RECOVERY
# ============================================================

print()
print(
    "=== P11.16-15 SECOND RECOVERY ==="
)

second_ids: list[str] = []


def second_consumer(
    event: SecurityEvent,
) -> bool:

    second_ids.append(
        event.event_id
    )

    return True


second_recovered = (
    spool.replay_events(
        second_consumer
    )
)


print(
    "SECOND_RECOVERED=",
    second_recovered,
)

print(
    "SECOND_IDS=",
    second_ids,
)


# ============================================================
# P11.16-16 FINAL STORAGE STATE
# ============================================================

print()
print(
    "=== P11.16-16 FINAL STORAGE STATE ==="
)

pending_final = (
    spool.pending_records()
)

pending_ids = [
    record[
        "event_id"
    ]
    for record in pending_final
]


print(
    "PENDING_IDS=",
    pending_ids,
)

print(
    "A_PENDING=",
    event_a.event_id
    in pending_ids,
)

print(
    "B_PENDING=",
    event_b.event_id
    in pending_ids,
)

print(
    "C_PENDING=",
    event_c.event_id
    in pending_ids,
)


# ============================================================
# P11.16-17 ACK STATE
# ============================================================

print()
print(
    "=== P11.16-17 ACK STATE ==="
)

acked_ids = (
    spool._read_ack_ids()
)


print(
    "ACKED_IDS=",
    sorted(
        acked_ids
    ),
)

print(
    "A_ACKED=",
    event_a.event_id
    in acked_ids,
)

print(
    "B_ACKED=",
    event_b.event_id
    in acked_ids,
)

print(
    "C_ACKED=",
    event_c.event_id
    in acked_ids,
)


# ============================================================
# P11.16-18 HEALTH
# ============================================================

print()
print(
    "=== P11.16-18 HEALTH ==="
)

vault_health = (
    vault.health_check()
)

vault_stats = (
    vault.get_stats()
)

spool_stats = (
    spool.get_stats()
)


print(
    "QUARANTINE_HEALTH=",
    vault_health,
)

print(
    "QUARANTINE_STATS=",
    vault_stats,
)

print(
    "SPOOL_STATS=",
    spool_stats,
)


# ============================================================
# P11.16-19 FINAL ASSERTIONS
# ============================================================

print()
print(
    "=== P11.16-19 FINAL ASSERTIONS ==="
)


# ------------------------------------------------------------
# APPEND
# ------------------------------------------------------------

assert append_a is True
assert append_b is True
assert append_c is True


# ------------------------------------------------------------
# Recovery
# ------------------------------------------------------------

assert recovered_count == 2

assert (
    event_a.event_id
    in recovered_ids
)

assert (
    event_c.event_id
    in recovered_ids
)

assert (
    event_b.event_id
    not in recovered_ids
)


# ------------------------------------------------------------
# Tampered event was blocked
# ------------------------------------------------------------

assert (
    b_recovered is False
)


# ------------------------------------------------------------
# Quarantine
# ------------------------------------------------------------

assert (
    quarantine_record[
        "event_id"
    ]
    == event_b.event_id
)

assert (
    quarantine_record[
        "status"
    ]
    == "QUARANTINED"
)

assert (
    quarantine_record[
        "failure_type"
    ]
    == "INVALID_SECURITY_EVENT"
)

assert (
    quarantine_record[
        "reason"
    ]
    == "SECURITY_EVENT_DESERIALIZATION_FAILURE"
)


# ------------------------------------------------------------
# Restore by default disabled
# ------------------------------------------------------------

assert (
    quarantine_record[
        "restore_allowed"
    ]
    is False
)


# ------------------------------------------------------------
# Evidence integrity
# ------------------------------------------------------------

assert (
    evidence_valid is True
)

assert (
    expected_sha256
    == stored_sha256
)


# ------------------------------------------------------------
# Metadata must survive
# ------------------------------------------------------------

assert (
    record_from_vault
    is not None
)

assert (
    record_from_vault[
        "event_id"
    ]
    == event_b.event_id
)

assert (
    record_from_vault[
        "failure_type"
    ]
    == "INVALID_SECURITY_EVENT"
)

assert (
    record_from_vault[
        "reason"
    ]
    == "SECURITY_EVENT_DESERIALIZATION_FAILURE"
)


# ------------------------------------------------------------
# Duplicate quarantine protection
# ------------------------------------------------------------

assert (
    len(
        records_after_duplicate
    )
    == len(
        records_before_duplicate
    )
)


assert (
    duplicate_record[
        "quarantine_id"
    ]
    == quarantine_record[
        "quarantine_id"
    ]
)


# ------------------------------------------------------------
# ACK semantics
# ------------------------------------------------------------

assert (
    event_a.event_id
    in acked_ids
)

assert (
    event_c.event_id
    in acked_ids
)

assert (
    event_b.event_id
    not in acked_ids
)


# ------------------------------------------------------------
# No pending trusted records
# ------------------------------------------------------------

assert (
    len(
        pending_ids
    )
    == 0
)


# ------------------------------------------------------------
# No second delivery
# ------------------------------------------------------------

assert second_recovered == 0

assert (
    len(
        second_ids
    )
    == 0
)


# ------------------------------------------------------------
# Valid events must not be blocked
# ------------------------------------------------------------

assert (
    event_a.event_id
    in acked_ids
)

assert (
    event_c.event_id
    in acked_ids
)


# ------------------------------------------------------------
# Vault health
# ------------------------------------------------------------

assert (
    vault_health[
        "status"
    ]
    == "HEALTHY"
)


# ============================================================
# P11.16-20 SECURITY RESULTS
# ============================================================

print(
    "VALID_A_RECOVERED=True"
)

print(
    "VALID_C_RECOVERED=True"
)

print(
    "TAMPERED_B_BLOCKED=True"
)

print(
    "TAMPERED_B_NOT_DELIVERED=True"
)

print(
    "TAMPERED_B_NOT_ACKED=True"
)

print(
    "QUARANTINE_CREATED=True"
)

print(
    "QUARANTINE_FAILURE_TYPE_VALID=True"
)

print(
    "QUARANTINE_REASON_VALID=True"
)

print(
    "RAW_EVIDENCE_PRESERVED=True"
)

print(
    "SHA256_VERIFIED=True"
)

print(
    "RESTORE_BY_DEFAULT_BLOCKED=True"
)

print(
    "QUARANTINE_DUPLICATE_PROTECTED=True"
)

print(
    "VALID_EVENTS_NOT_BLOCKED=True"
)

print(
    "NO_SECOND_DELIVERY=True"
)

print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)