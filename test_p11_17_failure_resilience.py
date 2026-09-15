from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent.event import SecurityEvent
from agent.quarantine.vault import SecureQuarantineVault
from agent.storage.durable_spool import DurableEventSpool


ROOT = Path(
    "state/test_p11_17_failure_resilience"
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
    event_type: str,
    message: str,
    severity: str = "HIGH",
) -> SecurityEvent:

    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        value=90,
        source="P11.17",
        message=message,
        confidence=0.99,
        host_id="host-p11-17",
        sensor_id="sensor-p11-17",
    )


print(
    "=== P11.17-01 CREATE SECURITY COMPONENTS ==="
)

vault = SecureQuarantineVault(
    ROOT / "quarantine"
)

spool = DurableEventSpool(
    ROOT / "spool",
    quarantine_vault=vault,
)

print(
    "VAULT_HEALTH=",
    vault.health_check(),
)

print(
    "SPOOL_STATS=",
    spool.get_stats(),
)


print()
print(
    "=== P11.17-02 CREATE EVENTS ==="
)

event_a = make_event(
    "P11_17_VALID_A",
    "Valid event A",
)

event_b = make_event(
    "P11_17_TAMPER_B",
    "Original event B",
    "CRITICAL",
)

event_c = make_event(
    "P11_17_VALID_C",
    "Valid event C",
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


print()
print(
    "=== P11.17-03 APPEND EVENTS ==="
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


assert append_a is True
assert append_b is True
assert append_c is True


print()
print(
    "=== P11.17-04 CREATE TAMPERED RECORD ==="
)

raw_records = spool.pending_records()

tampered_record = None

for record in raw_records:

    if (
        record.get("event_id")
        == event_b.event_id
    ):
        tampered_record = dict(
            record
        )

        break


assert tampered_record is not None


tampered_event = dict(
    tampered_record["event"]
)

tampered_event["message"] = (
    "ATTACKER MODIFIED EVENT B"
)

tampered_record[
    "event"
] = tampered_event


print(
    "TAMPER_TARGET=",
    event_b.event_id,
)

print(
    "TAMPERED_MESSAGE=",
    tampered_event["message"],
)


print()
print(
    "=== P11.17-05 WRITE TAMPERED RECORD ==="
)

pending_path = (
    spool.pending_path
)

lines = []

with pending_path.open(
    "rb"
) as handle:

    for raw_line in handle:

        line = raw_line.strip()

        if not line:
            continue

        record = json.loads(
            line.decode("utf-8")
        )

        if (
            record.get("event_id")
            == event_b.event_id
        ):

            record = tampered_record

        lines.append(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(
                    ",",
                    ":",
                ),
            )
        )


pending_path.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)


print(
    "TAMPER_WRITE_COMPLETE=",
    True,
)


print()
print(
    "=== P11.17-06 RECOVERY ATTEMPT ==="
)

recovered = []


def recovery_callback(
    event: SecurityEvent,
) -> bool:

    recovered.append(
        event.event_id
    )

    print(
        "RECOVERED_EVENT=",
        event.event_id,
    )

    return True


recovered_count = (
    spool.replay_events(
        recovery_callback
    )
)


print(
    "RECOVERED_COUNT=",
    recovered_count,
)

print(
    "RECOVERED_IDS=",
    recovered,
)


print()
print(
    "=== P11.17-07 VALID EVENT ISOLATION ==="
)

a_recovered = (
    event_a.event_id
    in recovered
)

b_recovered = (
    event_b.event_id
    in recovered
)

c_recovered = (
    event_c.event_id
    in recovered
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


assert a_recovered is True
assert b_recovered is False
assert c_recovered is True


print()
print(
    "=== P11.17-08 QUARANTINE INVALID EVENT ==="
)

tampered_raw = json.dumps(
    tampered_record,
    ensure_ascii=False,
    sort_keys=True,
    separators=(
        ",",
        ":",
    ),
).encode(
    "utf-8"
)


quarantine_record = (
    vault.quarantine(
        raw_record=tampered_raw,
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


assert (
    quarantine_record[
        "status"
    ]
    == "QUARANTINED"
)

assert (
    quarantine_record[
        "event_id"
    ]
    == event_b.event_id
)


print()
print(
    "=== P11.17-09 FORCE RECONCILIATION ==="
)

pending_after_quarantine = (
    spool.pending_records()
)

pending_ids_after_quarantine = [
    record.get("event_id")
    for record in pending_after_quarantine
]


print(
    "PENDING_IDS_AFTER_QUARANTINE=",
    pending_ids_after_quarantine,
)


print(
    "B_PENDING=",
    event_b.event_id
    in pending_ids_after_quarantine,
)


assert (
    event_b.event_id
    not in pending_ids_after_quarantine
)


print()
print(
    "=== P11.17-10 RESTART SIMULATION ==="
)

spool_after_restart = (
    DurableEventSpool(
        ROOT / "spool",
        quarantine_vault=vault,
    )
)


restart_pending = (
    spool_after_restart.pending_records()
)

restart_pending_ids = [
    record.get("event_id")
    for record in restart_pending
]


print(
    "RESTART_PENDING_IDS=",
    restart_pending_ids,
)

print(
    "B_PENDING_AFTER_RESTART=",
    event_b.event_id
    in restart_pending_ids,
)


assert (
    event_b.event_id
    not in restart_pending_ids
)


print()
print(
    "=== P11.17-11 ACK STATE ==="
)

acked_ids = (
    spool_after_restart._read_ack_ids()
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


print()
print(
    "=== P11.17-12 SECOND RECOVERY ==="
)

second_recovered = []


def second_callback(
    event: SecurityEvent,
) -> bool:

    second_recovered.append(
        event.event_id
    )

    print(
        "SECOND_RECOVERY_EVENT=",
        event.event_id,
    )

    return True


second_count = (
    spool_after_restart.replay_events(
        second_callback
    )
)


print(
    "SECOND_RECOVERY_COUNT=",
    second_count,
)

print(
    "SECOND_RECOVERED_IDS=",
    second_recovered,
)


assert (
    event_b.event_id
    not in second_recovered
)


print()
print(
    "=== P11.17-13 QUARANTINE EVIDENCE ==="
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

assert evidence_valid is True


print()
print(
    "=== P11.17-14 TERMINAL STATE INVARIANTS ==="
)

final_pending = (
    spool_after_restart.pending_records()
)

final_pending_ids = {
    record.get("event_id")
    for record in final_pending
}


final_acked_ids = (
    spool_after_restart._read_ack_ids()
)

final_quarantine_records = (
    vault.list_records()
)

final_quarantine_event_ids = {
    record.get("event_id")
    for record
    in final_quarantine_records
}


print(
    "FINAL_PENDING_IDS=",
    sorted(
        final_pending_ids
    ),
)

print(
    "FINAL_ACKED_IDS=",
    sorted(
        final_acked_ids
    ),
)

print(
    "FINAL_QUARANTINED_IDS=",
    sorted(
        final_quarantine_event_ids
    ),
)


assert (
    event_a.event_id
    not in final_pending_ids
)

assert (
    event_b.event_id
    not in final_pending_ids
)

assert (
    event_c.event_id
    not in final_pending_ids
)

assert (
    event_a.event_id
    in final_acked_ids
)

assert (
    event_c.event_id
    in final_acked_ids
)

assert (
    event_b.event_id
    not in final_acked_ids
)

assert (
    event_b.event_id
    in final_quarantine_event_ids
)


print()
print(
    "=== P11.17-15 NO BAD TRANSITION ==="
)

bad_transition_1 = (
    event_b.event_id
    in final_acked_ids
)

bad_transition_2 = (
    event_b.event_id
    in final_pending_ids
)

bad_transition_3 = (
    event_b.event_id
    in second_recovered
)


print(
    "B_ACKED=",
    bad_transition_1,
)

print(
    "B_PENDING=",
    bad_transition_2,
)

print(
    "B_REDELIVERED=",
    bad_transition_3,
)


assert bad_transition_1 is False
assert bad_transition_2 is False
assert bad_transition_3 is False


print()
print(
    "=== P11.17-16 HEALTH ==="
)

print(
    "VAULT_HEALTH=",
    vault.health_check(),
)

print(
    "SPOOL_HEALTH=",
    spool_after_restart.get_stats(),
)


print()
print(
    "=== P11.17-17 FINAL ASSERTIONS ==="
)

print(
    "VALID_A_RECOVERED=",
    a_recovered,
)

print(
    "VALID_C_RECOVERED=",
    c_recovered,
)

print(
    "TAMPERED_B_BLOCKED=",
    not b_recovered,
)

print(
    "TAMPERED_B_NOT_ACKED=",
    event_b.event_id
    not in final_acked_ids,
)

print(
    "TAMPERED_B_NOT_PENDING=",
    event_b.event_id
    not in final_pending_ids,
)

print(
    "TAMPERED_B_NOT_REDELIVERED=",
    event_b.event_id
    not in second_recovered,
)

print(
    "QUARANTINE_PERSISTED=",
    event_b.event_id
    in final_quarantine_event_ids,
)

print(
    "EVIDENCE_VERIFIED=",
    evidence_valid,
)

print(
    "RESTART_SAFE=",
    event_b.event_id
    not in restart_pending_ids,
)

print(
    "VALID_EVENTS_NOT_BLOCKED=",
    (
        event_a.event_id
        in final_acked_ids
        and
        event_c.event_id
        in final_acked_ids
    ),
)


print()
print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)