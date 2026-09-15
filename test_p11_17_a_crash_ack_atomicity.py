from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from agent.event import SecurityEvent
from agent.quarantine.vault import SecureQuarantineVault
from agent.storage.durable_spool import DurableEventSpool


# ============================================================
# P11.17-A
# CRASH / ACK ATOMICITY
#
# Security goal:
#
#   delivery
#       ↓
#   consumer success
#       ↓
#   ACK boundary
#       ↓
#   simulated process crash
#       ↓
#   ACK MUST NOT EXIST
#       ↓
#   event MUST remain pending
#       ↓
#   restart
#       ↓
#   event MUST be recoverable
#       ↓
#   successful recovery
#       ↓
#   durable ACK
#
# Important:
#
# The crash snapshot is evaluated BEFORE recovery.
# Final ACK state is evaluated separately AFTER recovery.
# ============================================================


ROOT = Path(
    tempfile.mkdtemp(
        prefix="cyberdefender_p11_17_a_"
    )
)


def cleanup() -> None:
    shutil.rmtree(
        ROOT,
        ignore_errors=True,
    )


try:

    # ========================================================
    # P11.17-A-01 CREATE COMPONENTS
    # ========================================================

    print()
    print(
        "=== P11.17-A-01 CREATE COMPONENTS ==="
    )

    vault = SecureQuarantineVault(
        ROOT / "quarantine"
    )

    print(
        "VAULT_HEALTH=",
        vault.health_check(),
    )

    spool = DurableEventSpool(
        ROOT / "spool",
        quarantine_vault=vault,
    )

    print(
        "SPOOL_STATS=",
        spool.get_stats(),
    )

    # ========================================================
    # P11.17-A-02 CREATE EVENT
    # ========================================================

    print()
    print(
        "=== P11.17-A-02 CREATE EVENT ==="
    )

    # IMPORTANT:
    #
    # This constructor matches the current CyberDefender
    # SecurityEvent API:
    #
    # event_type
    # severity
    # value
    # source
    # message
    # confidence
    # host_id
    # sensor_id
    #
    # Do NOT use data= or payload= here.

    event = SecurityEvent(
        event_type="P11_17_A_CRASH_TEST",
        severity="HIGH",
        value=1.0,
        source="P11.17-A",
        message="CRASH ACK ATOMICITY TEST",
        confidence=1.0,
        host_id="P11-17-A-HOST",
        sensor_id="P11-17-A-SENSOR",
    )

    event_id = event.event_id

    print(
        "EVENT_ID=",
        event_id,
    )

    # ========================================================
    # P11.17-A-03 APPEND
    # ========================================================

    print()
    print(
        "=== P11.17-A-03 APPEND ==="
    )

    appended = spool.append(
        event
    )

    pending_before_crash = (
        spool.pending_records()
    )

    pending_before_ids = {
        record.get("event_id")
        for record
        in pending_before_crash
    }

    print(
        "APPENDED=",
        appended,
    )

    print(
        "PENDING_BEFORE_CRASH=",
        len(
            pending_before_crash
        ),
    )

    assert appended is True

    assert (
        event_id
        in pending_before_ids
    )

    # ========================================================
    # P11.17-A-04 INJECT ACK CRASH
    # ========================================================

    print()
    print(
        "=== P11.17-A-04 INJECT ACK CRASH ==="
    )

    original_ack = spool.ack

    ack_called = {
        "value": False
    }

    crash_observed = {
        "value": False
    }

    crash_exception = {
        "value": None
    }

    first_delivery = []

    def crash_ack(
        ack_event_id: str,
    ) -> bool:

        ack_called["value"] = True

        print(
            "ACK_ATTEMPT_EVENT_ID=",
            ack_event_id,
        )

        print(
            "SIMULATED_CRASH=ACK_BOUNDARY"
        )

        crash_observed[
            "value"
        ] = True

        crash_exception[
            "value"
        ] = (
            "SIMULATED_PROCESS_CRASH_DURING_ACK"
        )

        # IMPORTANT:
        #
        # We intentionally do NOT call original_ack().
        #
        # Therefore no durable ACK can be produced
        # at the simulated crash boundary.
        raise RuntimeError(
            "SIMULATED_PROCESS_CRASH_DURING_ACK"
        )

    spool.ack = crash_ack

    # ========================================================
    # P11.17-A-05 FIRST DELIVERY
    # ========================================================

    print()
    print(
        "=== P11.17-A-05 FIRST DELIVERY ==="
    )

    def first_callback(
        received_event: SecurityEvent,
    ) -> bool:

        print(
            "CALLBACK_EVENT=",
            received_event.event_id,
        )

        first_delivery.append(
            received_event.event_id
        )

        # Consumer processing succeeds.
        #
        # DurableEventSpool then attempts ACK.
        return True

    first_replay_count = 0

    try:

        first_replay_count = (
            spool.replay_events(
                first_callback
            )
        )

    except RuntimeError as exc:

        # This branch is possible if replay_events()
        # propagates the ACK exception.

        crash_observed[
            "value"
        ] = True

        crash_exception[
            "value"
        ] = str(exc)

        print(
            "PROCESS_CRASH_SIMULATED=",
            True,
        )

        print(
            "CRASH_REASON=",
            str(exc),
        )

        first_replay_count = 0

    # ========================================================
    # IMPORTANT:
    #
    # replay_events() may intentionally catch callback/ACK
    # failures internally.
    #
    # Therefore crash_observed is taken from the injected
    # ACK function itself, NOT from whether an exception
    # escaped replay_events().
    # ========================================================

    print(
        "FIRST_REPLAY_COUNT=",
        first_replay_count,
    )

    print(
        "CRASH_OBSERVED=",
        crash_observed["value"],
    )

    print(
        "CRASH_EXCEPTION_RAISED=",
        crash_exception["value"]
        is not None,
    )

    print(
        "FIRST_DELIVERY_IDS=",
        first_delivery,
    )

    print(
        "ACK_WAS_CALLED=",
        ack_called["value"],
    )

    # ========================================================
    # P11.17-A-06 EXACT CRASH SNAPSHOT
    # ========================================================

    print()
    print(
        "=== P11.17-A-06 STATE AFTER SIMULATED CRASH ==="
    )

    pending_after_crash = (
        spool.pending_records()
    )

    pending_ids_after_crash = {
        record.get("event_id")
        for record
        in pending_after_crash
    }

    acked_after_crash_ids = (
        spool._read_ack_ids()
    )

    acked_after_crash = (
        event_id
        in acked_after_crash_ids
    )

    event_still_pending = (
        event_id
        in pending_ids_after_crash
    )

    # THIS is the authoritative crash snapshot.

    no_ack_during_crash = (
        acked_after_crash
        is False
    )

    print(
        "PENDING_AFTER_CRASH=",
        sorted(
            pending_ids_after_crash
        ),
    )

    print(
        "EVENT_STILL_PENDING=",
        event_still_pending,
    )

    print(
        "ACKED_AFTER_CRASH=",
        acked_after_crash,
    )

    print(
        "NO_ACK_DURING_CRASH_SNAPSHOT=",
        no_ack_during_crash,
    )

    # ========================================================
    # P11.17-A-07 SIMULATED PROCESS RESTART
    # ========================================================

    print()
    print(
        "=== P11.17-A-07 SIMULATED PROCESS RESTART ==="
    )

    # Restore original ACK implementation on old object.
    spool.ack = original_ack

    # Create a completely new DurableEventSpool instance.
    #
    # This simulates process restart.

    spool_after_restart = (
        DurableEventSpool(
            ROOT / "spool",
            quarantine_vault=vault,
        )
    )

    restart_pending = (
        spool_after_restart.pending_records()
    )

    restart_pending_ids = {
        record.get("event_id")
        for record
        in restart_pending
    }

    restart_acked_ids = (
        spool_after_restart._read_ack_ids()
    )

    print(
        "RESTART_PENDING_IDS=",
        sorted(
            restart_pending_ids
        ),
    )

    print(
        "RESTART_ACKED_IDS=",
        sorted(
            restart_acked_ids
        ),
    )

    # ========================================================
    # P11.17-A-08 RECOVERY AFTER CRASH
    # ========================================================

    print()
    print(
        "=== P11.17-A-08 RECOVERY AFTER CRASH ==="
    )

    second_delivery = []

    def recovery_callback(
        received_event: SecurityEvent,
    ) -> bool:

        print(
            "RECOVERY_CALLBACK_EVENT=",
            received_event.event_id,
        )

        second_delivery.append(
            received_event.event_id
        )

        # Recovery processing succeeds.
        return True

    recovery_count = (
        spool_after_restart.replay_events(
            recovery_callback
        )
    )

    print(
        "RECOVERY_COUNT=",
        recovery_count,
    )

    print(
        "RECOVERY_IDS=",
        second_delivery,
    )

    # ========================================================
    # P11.17-A-09 FINAL STATE
    # ========================================================

    print()
    print(
        "=== P11.17-A-09 FINAL STATE ==="
    )

    final_pending = (
        spool_after_restart.pending_records()
    )

    final_pending_ids = {
        record.get("event_id")
        for record
        in final_pending
    }

    final_acked_ids = (
        spool_after_restart._read_ack_ids()
    )

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
        "FIRST_DELIVERY_COUNT=",
        len(
            first_delivery
        ),
    )

    print(
        "SECOND_DELIVERY_COUNT=",
        len(
            second_delivery
        ),
    )

    # ========================================================
    # P11.17-A-10 AT-LEAST-ONCE ANALYSIS
    # ========================================================

    print()
    print(
        "=== P11.17-A-10 AT-LEAST-ONCE ANALYSIS ==="
    )

    delivered_at_least_once = (
        event_id
        in first_delivery
        or
        event_id
        in second_delivery
    )

    delivered_twice = (
        first_delivery.count(
            event_id
        )
        +
        second_delivery.count(
            event_id
        )
        >= 2
    )

    acked_final = (
        event_id
        in final_acked_ids
    )

    pending_final = (
        event_id
        in final_pending_ids
    )

    print(
        "DELIVERED_AT_LEAST_ONCE=",
        delivered_at_least_once,
    )

    print(
        "DUPLICATE_DELIVERY_OBSERVED=",
        delivered_twice,
    )

    print(
        "ACKED_FINAL=",
        acked_final,
    )

    print(
        "PENDING_FINAL=",
        pending_final,
    )

    # ========================================================
    # P11.17-A-11 SAFETY INVARIANTS
    # ========================================================

    print()
    print(
        "=== P11.17-A-11 SAFETY INVARIANTS ==="
    )

    ack_boundary_reached = (
        ack_called["value"]
        is True
    )

    restart_did_not_lose_event = (
        (
            event_id
            in restart_pending_ids
        )
        or
        (
            event_id
            in restart_acked_ids
        )
    )

    no_silent_loss = (
        restart_did_not_lose_event
    )

    final_terminal_state_valid = (
        acked_final
        and
        not pending_final
    )

    no_dual_terminal_state = not (
        (
            event_id
            in final_acked_ids
        )
        and
        (
            event_id
            in final_pending_ids
        )
    )

    recovery_delivery_valid = (
        len(second_delivery)
        == 1
        and
        second_delivery[0]
        == event_id
    )

    at_least_once_valid = (
        delivered_at_least_once
    )

    print(
        "ACK_BOUNDARY_REACHED=",
        ack_boundary_reached,
    )

    print(
        "NO_ACK_DURING_CRASH=",
        no_ack_during_crash,
    )

    print(
        "RESTART_DID_NOT_LOSE_EVENT=",
        restart_did_not_lose_event,
    )

    print(
        "NO_SILENT_EVENT_LOSS=",
        no_silent_loss,
    )

    print(
        "FINAL_TERMINAL_STATE_VALID=",
        final_terminal_state_valid,
    )

    print(
        "NO_DUAL_TERMINAL_STATE=",
        no_dual_terminal_state,
    )

    print(
        "RECOVERY_DELIVERY_VALID=",
        recovery_delivery_valid,
    )

    print(
        "AT_LEAST_ONCE_VALID=",
        at_least_once_valid,
    )

    # ========================================================
    # P11.17-A-12 STORAGE HEALTH
    # ========================================================

    print()
    print(
        "=== P11.17-A-12 STORAGE HEALTH ==="
    )

    final_spool_stats = (
        spool_after_restart.get_stats()
    )

    final_vault_health = (
        vault.health_check()
    )

    print(
        "FINAL_SPOOL_STATS=",
        final_spool_stats,
    )

    print(
        "FINAL_VAULT_HEALTH=",
        final_vault_health,
    )

    # ========================================================
    # P11.17-A-13 FINAL ASSERTIONS
    # ========================================================

    print()
    print(
        "=== P11.17-A-13 FINAL ASSERTIONS ==="
    )

    # --------------------------------------------------------
    # ACK attempt really happened.
    # --------------------------------------------------------

    assert (
        ack_called["value"]
        is True
    )

    # --------------------------------------------------------
    # Crash boundary really happened.
    # --------------------------------------------------------

    assert (
        crash_observed["value"]
        is True
    )

    # --------------------------------------------------------
    # First delivery happened exactly once.
    # --------------------------------------------------------

    assert (
        len(first_delivery)
        == 1
    )

    assert (
        first_delivery[0]
        == event_id
    )

    # --------------------------------------------------------
    # MOST IMPORTANT:
    #
    # At the exact crash snapshot there MUST NOT be an ACK.
    #
    # This is intentionally NOT checked against final state.
    # --------------------------------------------------------

    assert (
        no_ack_during_crash
        is True
    )

    # --------------------------------------------------------
    # Event MUST still exist after crash.
    # --------------------------------------------------------

    assert (
        event_still_pending
        is True
    )

    # --------------------------------------------------------
    # Restart MUST preserve event.
    # --------------------------------------------------------

    assert (
        event_id
        in restart_pending_ids
    )

    # --------------------------------------------------------
    # Restart MUST NOT magically ACK it.
    # --------------------------------------------------------

    assert (
        event_id
        not in restart_acked_ids
    )

    # --------------------------------------------------------
    # Recovery MUST deliver it.
    # --------------------------------------------------------

    assert (
        recovery_delivery_valid
        is True
    )

    # --------------------------------------------------------
    # Final ACK is expected after successful recovery.
    # --------------------------------------------------------

    assert (
        acked_final
        is True
    )

    # --------------------------------------------------------
    # Final pending must be false.
    # --------------------------------------------------------

    assert (
        pending_final
        is False
    )

    # --------------------------------------------------------
    # No dual terminal state.
    # --------------------------------------------------------

    assert (
        no_dual_terminal_state
        is True
    )

    # --------------------------------------------------------
    # No silent loss.
    # --------------------------------------------------------

    assert (
        no_silent_loss
        is True
    )

    # --------------------------------------------------------
    # At-least-once guarantee.
    # --------------------------------------------------------

    assert (
        at_least_once_valid
        is True
    )

    # --------------------------------------------------------
    # Storage health.
    # --------------------------------------------------------

    assert (
        final_vault_health[
            "status"
        ]
        == "HEALTHY"
    )

    # ========================================================
    # SUCCESS REPORT
    # ========================================================

    print()
    print(
        "=== P11.17-A RESULT ==="
    )

    print(
        "CRASH_BOUNDARY_REACHED=",
        ack_boundary_reached,
    )

    print(
        "ACK_ABSENT_AT_CRASH=",
        no_ack_during_crash,
    )

    print(
        "EVENT_PRESERVED_ACROSS_CRASH=",
        restart_did_not_lose_event,
    )

    print(
        "RECOVERY_DELIVERY_VALID=",
        recovery_delivery_valid,
    )

    print(
        "FINAL_ACK_VALID=",
        acked_final,
    )

    print(
        "FINAL_PENDING_FALSE=",
        not pending_final,
    )

    print(
        "NO_DUAL_TERMINAL_STATE=",
        no_dual_terminal_state,
    )

    print(
        "NO_SILENT_EVENT_LOSS=",
        no_silent_loss,
    )

    print(
        "AT_LEAST_ONCE_DELIVERY=",
        at_least_once_valid,
    )

    print()
    print(
        "ALL_ASSERTIONS_PASS=True"
    )

    print(
        "TEST_COMPLETE=True"
    )

finally:

    cleanup()