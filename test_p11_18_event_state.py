from pathlib import Path
import tempfile
import json

from agent.event import SecurityEvent
from agent.state import EventState


def make_event(
    event_type="P11_18_TEST",
    severity="WARNING",
    value=87,
):
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        value=value,
        source="P11.18Test",
        message="EventState security test",
        confidence=0.95,
        host_id="host-p11-18",
        sensor_id="sensor-p11-18",
    )


print("=== P11.18 EVENT STATE SECURITY TEST ===")


with tempfile.TemporaryDirectory() as temp_dir:

    state_path = (
        Path(temp_dir)
        / "state.json"
    )

    # =====================================================
    # 01 INITIAL STATE
    # =====================================================

    state = EventState(
        state_path
    )

    assert state.get_all_states() == {}

    print(
        "01_INITIAL_STATE=PASS"
    )

    # =====================================================
    # 02 NEW EVENT
    # =====================================================

    event = make_event()

    lifecycle = state.update(
        event
    )

    assert lifecycle == "NEW"

    current = state.get_state(
        event.event_type
    )

    assert current is not None
    assert current["state"] == "ACTIVE"
    assert current["lifecycle"] == "NEW"
    assert current["occurrence_count"] == 1

    print(
        "02_NEW_EVENT=PASS"
    )

    # =====================================================
    # 03 UPDATE SAME EVENT TYPE
    # =====================================================

    event2 = make_event(
        value=91
    )

    lifecycle2 = state.update(
        event2
    )

    assert lifecycle2 == "UPDATE"

    current2 = state.get_state(
        event.event_type
    )

    assert current2["state"] == "ACTIVE"
    assert current2["lifecycle"] == "UPDATE"
    assert current2["occurrence_count"] == 2
    assert current2["value"] == 91

    print(
        "03_UPDATE_EVENT=PASS"
    )

    # =====================================================
    # 04 THIRD UPDATE
    # =====================================================

    event3 = make_event(
        value=95
    )

    lifecycle3 = state.update(
        event3
    )

    assert lifecycle3 == "UPDATE"

    current3 = state.get_state(
        event.event_type
    )

    assert current3["occurrence_count"] == 3
    assert current3["value"] == 95

    print(
        "04_MULTIPLE_UPDATE=PASS"
    )

    # =====================================================
    # 05 RESTART / PERSISTENCE
    # =====================================================

    del state

    restarted = EventState(
        state_path
    )

    restored = restarted.get_state(
        event.event_type
    )

    assert restored is not None
    assert restored["state"] == "ACTIVE"
    assert restored["occurrence_count"] == 3
    assert restored["value"] == 95

    print(
        "05_RESTART_PERSISTENCE=PASS"
    )

    # =====================================================
    # 06 RECOVERY
    # =====================================================

    recovered = restarted.recover(
        event.event_type
    )

    assert recovered is not None
    assert recovered["state"] == "ACTIVE"

    assert (
        restarted.get_state(
            event.event_type
        )
        is None
    )

    print(
        "06_RECOVERY=PASS"
    )

    # =====================================================
    # 07 UNKNOWN RECOVERY
    # =====================================================

    unknown = restarted.recover(
        "DOES_NOT_EXIST"
    )

    assert unknown is None

    print(
        "07_UNKNOWN_RECOVERY=PASS"
    )

    # =====================================================
    # 08 RESTART AFTER RECOVERY
    # =====================================================

    restarted_again = EventState(
        state_path
    )

    assert (
        restarted_again.get_all_states()
        == {}
    )

    print(
        "08_RECOVERY_PERSISTENCE=PASS"
    )

    # =====================================================
    # 09 CORRUPTED STATE FILE
    # =====================================================

    with state_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            "{ INVALID JSON"
        )

    corrupted = EventState(
        state_path
    )

    print(
        "09_CORRUPTED_STATE_LOAD="
        "OBSERVED"
    )

    print(
        "CORRUPTED_STATE_RESULT=",
        corrupted.get_all_states()
    )


print()
print(
    "P11.18 BASIC TEST COMPLETE"
)