from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent.event import SecurityEvent
from agent.state import (
    EventState,
    EventStateIntegrityError,
)


def make_event(
    event_type="P11_18_C_TEST",
    value=87,
):
    return SecurityEvent(
        event_type=event_type,
        severity="WARNING",
        value=value,
        source="P11.18-C",
        message="EventState adversarial test",
        confidence=0.95,
        host_id="host-p11-18-c",
        sensor_id="sensor-p11-18-c",
    )


print()
print("=== P11.18-C EVENT STATE HARDENING ===")


# =========================================================
# 01 NORMAL LIFECYCLE
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    state = EventState(
        state_path
    )

    event = make_event()

    assert (
        state.update(event)
        == "NEW"
    )

    assert (
        state.get_state(
            event.event_type
        )["state"]
        == "ACTIVE"
    )

    print(
        "01_NORMAL_LIFECYCLE=PASS"
    )


# =========================================================
# 02 UPDATE PERSISTENCE
# =========================================================

    event2 = make_event(
        value=91
    )

    assert (
        state.update(event2)
        == "UPDATE"
    )

    current = state.get_state(
        event.event_type
    )

    assert (
        current["occurrence_count"]
        == 2
    )

    assert (
        current["value"]
        == 91
    )

    print(
        "02_UPDATE_PERSISTENCE=PASS"
    )


# =========================================================
# 03 RESTART
# =========================================================

    restarted = EventState(
        state_path
    )

    restored = restarted.get_state(
        event.event_type
    )

    assert restored is not None

    assert (
        restored["occurrence_count"]
        == 2
    )

    assert (
        restored["value"]
        == 91
    )

    print(
        "03_RESTART_PERSISTENCE=PASS"
    )


# =========================================================
# 04 RECOVERY
# =========================================================

    recovered = restarted.recover(
        event.event_type
    )

    assert recovered is not None

    assert (
        restarted.get_state(
            event.event_type
        )
        is None
    )

    restarted_after_recovery = EventState(
        state_path
    )

    assert (
        restarted_after_recovery
        .get_state(
            event.event_type
        )
        is None
    )

    print(
        "04_RECOVERY_PERSISTENCE=PASS"
    )


# =========================================================
# 05 CORRUPTED JSON MUST REJECT
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    state_path.write_text(
        "{ INVALID JSON",
        encoding="utf-8",
    )

    corruption_rejected = False

    try:
        EventState(
            state_path
        )

    except EventStateIntegrityError as exc:

        corruption_rejected = True

        print(
            "05_CORRUPTION_REJECTED=PASS"
        )

        print(
            "CORRUPTION_REASON=",
            str(exc),
        )

    assert corruption_rejected


# =========================================================
# 06 INVALID ROOT SCHEMA
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    state_path.write_text(
        json.dumps(
            ["not", "a", "dict"]
        ),
        encoding="utf-8",
    )

    rejected = False

    try:
        EventState(
            state_path
        )

    except EventStateIntegrityError:
        rejected = True

    assert rejected

    print(
        "06_INVALID_ROOT_SCHEMA=PASS"
    )


# =========================================================
# 07 INVALID EVENT STATE SCHEMA
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    malformed = {
        "HIGH_MEMORY_USAGE": {
            "state": "ACTIVE",
            "lifecycle": "UPDATE",
            "severity": "WARNING",
        }
    }

    state_path.write_text(
        json.dumps(
            malformed
        ),
        encoding="utf-8",
    )

    rejected = False

    try:
        EventState(
            state_path
        )

    except EventStateIntegrityError:
        rejected = True

    assert rejected

    print(
        "07_INVALID_STATE_SCHEMA=PASS"
    )


# =========================================================
# 08 INVALID LIFECYCLE
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    malformed = {
        "TEST": {
            "state": "ACTIVE",
            "lifecycle": "FORGED",
            "severity": "WARNING",
            "value": 1,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
            "occurrence_count": 1,
        }
    }

    state_path.write_text(
        json.dumps(
            malformed
        ),
        encoding="utf-8",
    )

    rejected = False

    try:
        EventState(
            state_path
        )

    except EventStateIntegrityError:
        rejected = True

    assert rejected

    print(
        "08_INVALID_LIFECYCLE=PASS"
    )


# =========================================================
# 09 DEFENSIVE READ COPY
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    state = EventState(
        state_path
    )

    event = make_event()

    state.update(event)

    external = state.get_state(
        event.event_type
    )

    external["severity"] = "CRITICAL"
    external["occurrence_count"] = 999

    actual = state.get_state(
        event.event_type
    )

    assert (
        actual["severity"]
        == "WARNING"
    )

    assert (
        actual["occurrence_count"]
        == 1
    )

    print(
        "09_DEFENSIVE_READ_COPY=PASS"
    )


# =========================================================
# 10 DEFENSIVE ALL-STATES COPY
# =========================================================

    all_states = (
        state.get_all_states()
    )

    all_states[
        event.event_type
    ]["occurrence_count"] = 9999

    actual = state.get_state(
        event.event_type
    )

    assert (
        actual["occurrence_count"]
        == 1
    )

    print(
        "10_DEFENSIVE_ALL_STATES_COPY=PASS"
    )


# =========================================================
# 11 UPDATE FAILURE ROLLBACK
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    state = EventState(
        state_path
    )

    event = make_event()

    state.update(event)

    before = state.get_state(
        event.event_type
    )

    original_save = state._save

    def failing_save(*args, **kwargs):
        raise OSError(
            "SIMULATED_PERSISTENCE_FAILURE"
        )

    state._save = failing_save

    failed = False

    try:
        state.update(
            make_event(value=999)
        )

    except OSError:
        failed = True

    finally:
        state._save = original_save

    assert failed

    after = state.get_state(
        event.event_type
    )

    assert (
        after == before
    )

    print(
        "11_UPDATE_FAILURE_ROLLBACK=PASS"
    )


# =========================================================
# 12 RECOVERY FAILURE ROLLBACK
# =========================================================

with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    state = EventState(
        state_path
    )

    event = make_event()

    state.update(event)

    original_save = state._save

    def failing_save(*args, **kwargs):
        raise OSError(
            "SIMULATED_RECOVERY_PERSISTENCE_FAILURE"
        )

    state._save = failing_save

    failed = False

    try:
        state.recover(
            event.event_type
        )

    except OSError:
        failed = True

    finally:
        state._save = original_save

    assert failed

    still_active = state.get_state(
        event.event_type
    )

    assert still_active is not None

    assert (
        still_active["state"]
        == "ACTIVE"
    )

    # Disk must also still contain the event.
    restarted = EventState(
        state_path
    )

    disk_state = restarted.get_state(
        event.event_type
    )

    assert disk_state is not None

    print(
        "12_RECOVERY_FAILURE_ROLLBACK=PASS"
    )


# =========================================================
# 13 FINAL RESULT
# =========================================================

print()
print("=== P11.18-C RESULT ===")

print(
    "CORRUPTION_FAIL_CLOSED=True"
)

print(
    "SCHEMA_VALIDATION=True"
)

print(
    "TRANSACTIONAL_UPDATE=True"
)

print(
    "TRANSACTIONAL_RECOVERY=True"
)

print(
    "DEFENSIVE_READS=True"
)

print(
    "ATOMIC_PERSISTENCE=True"
)

print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)
