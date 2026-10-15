from __future__ import annotations

import copy
import threading

import agent.service_diagnostics as diagnostics
from agent.service_crash_guard import CrashPolicy, fresh_record
from agent.service_lifecycle import run_guarded_service


class MemoryStore:
    def __init__(self):
        self.record = fresh_record("CyberDefenderAgent")

    def load(self):
        return copy.deepcopy(self.record)

    def write(self, record):
        record = copy.deepcopy(record)
        record["revision"] += 1
        self.record = copy.deepcopy(record)
        return record

    def close(self):
        pass


class UnavailableObserver:
    """Protected-log sink documented as possibly unavailable (notify contract)."""

    def __init__(self):
        self.calls = 0

    def __call__(self, service, state):
        self.calls += 1
        raise OSError("PROTECTED_LOG_UNAVAILABLE")


def policy():
    return CrashPolicy(attempts=3, stable_seconds=10, stable_checks=3, cooldown_seconds=5, probes=1)


# Capture the fallback diagnostic sink: the test must never write into the
# real protected ProgramData store, and swallowed errors must be logged.
log_calls = []
_real_log = diagnostics.write_service_log

def capture_log(service, message, *, exc=None, exit_reason=None):
    log_calls.append((service, message, type(exc).__name__ if exc is not None else None))

diagnostics.write_service_log = capture_log
try:
    # Positive: a valid healthy attempt ending in an SCM stop must never be
    # counted as a failed start, even when the diagnostics observer is down.
    store = MemoryStore()
    observer = UnavailableObserver()
    stop_event = threading.Event()
    attempts_run = []

    def run_attempt_valid_stop(guard):
        attempts_run.append("attempt")
        guard.progress(healthy=True)
        stop_event.set()  # SCM stop arrives during the attempt.
        return None       # windows_service returns None for a valid stop.

    try:
        run_guarded_service(
            "CyberDefenderAgent", stop_event, run_attempt_valid_stop,
            policy=policy(), store_factory=lambda: store,
            boot_factory=lambda: "boot-a", observer=observer,
            clock=lambda: 0.0,
        )
        escaped = None
    except Exception as exc:
        escaped = exc

    record = store.load()
    assert attempts_run == ["attempt"], attempts_run
    assert escaped is None, f"observer failure escaped the guarded loop: {escaped!r}"
    assert record["cumulative_failures"] == 0, record
    assert record["recent_failures"] == [], record
    assert record["clean_stop"] is True, record
    assert any(msg == "OBSERVER_FAILED" and cat == "OSError" for _, msg, cat in log_calls), log_calls
    print("PASS | valid stopped attempt is not counted as a failed start")

    # Negative: a genuine attempt crash must still be counted exactly once.
    store2 = MemoryStore()
    stop2 = threading.Event()
    crash_attempts = []

    def run_attempt_crash(guard):
        crash_attempts.append("attempt")
        stop2.set()  # SCM stop requested; the attempt itself crashed first.
        raise RuntimeError("SIMULATED_ATTEMPT_CRASH")

    run_guarded_service(
        "CyberDefenderAgent", stop2, run_attempt_crash,
        policy=policy(), store_factory=lambda: store2,
        boot_factory=lambda: "boot-b", observer=UnavailableObserver(),
        clock=lambda: 0.0,
    )

    record2 = store2.load()
    assert crash_attempts == ["attempt"], crash_attempts
    assert record2["cumulative_failures"] == 1, record2
    assert record2["recent_failures"][-1]["code"] == "ATTEMPT_FAILED", record2
    print("PASS | genuine attempt failure is still counted exactly once")

    # Negative: BaseException from the observer must still propagate.
    stop3 = threading.Event()

    def exiting_observer(service, state):
        raise SystemExit("OBSERVER_SHUTDOWN")

    raised = None
    try:
        run_guarded_service(
            "CyberDefenderAgent", stop3, lambda guard: None,
            policy=policy(), store_factory=lambda: MemoryStore(),
            boot_factory=lambda: "boot-c", observer=exiting_observer,
            clock=lambda: 0.0,
        )
    except SystemExit as exc:
        raised = exc
    assert raised is not None, "SystemExit from observer must propagate"
    assert not any(cat == "SystemExit" for _, _, cat in log_calls), log_calls
    print("PASS | SystemExit from observer propagates and is never swallowed")
finally:
    diagnostics.write_service_log = _real_log
print("RESULT: PASS")
