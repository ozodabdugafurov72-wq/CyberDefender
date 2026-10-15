from __future__ import annotations

import threading
import time

from agent.service_watchdog import ProgressWatchdog

# Positive: an observer Exception must not terminate the watchdog thread,
# hide later real transitions, or fabricate a HEALTHY state.
received = []
first_call = threading.Event()
delivered_after_failure = threading.Event()

def flaky_callback(state):
    received.append(state)
    if len(received) == 1:
        first_call.set()
        raise OSError("PROTECTED_LOG_UNAVAILABLE")
    if state == "HEALTHY":
        delivered_after_failure.set()

watchdog = ProgressWatchdog(deadline=60.0, clock=time.monotonic)
stop = threading.Event()
watchdog.begin()
thread = threading.Thread(target=watchdog.monitor, args=(stop, flaky_callback), daemon=True)
thread.start()
assert first_call.wait(timeout=5), received
assert "HEALTHY" not in received, received  # no manufactured HEALTHY
watchdog.progress(True)  # only real progress may produce HEALTHY
assert delivered_after_failure.wait(timeout=8), received
assert thread.is_alive(), "observer failure terminated the watchdog thread"
stop.set()
thread.join(timeout=3)
assert not thread.is_alive()
assert "STALLED" not in received, received  # safety states stay consistent
print("PASS | observer Exception does not terminate the watchdog thread")

# Negative: BaseException from the callback must propagate, never swallowed.
observed_errors = []
real_hook = threading.excepthook
threading.excepthook = lambda args: observed_errors.append(args.exc_value)
try:
    def exiting_callback(state):
        raise SystemExit("WATCHDOG_SHUTDOWN")

    watchdog2 = ProgressWatchdog(deadline=60.0, clock=time.monotonic)
    stop2 = threading.Event()
    watchdog2.begin()
    thread2 = threading.Thread(target=watchdog2.monitor, args=(stop2, exiting_callback), daemon=True)
    thread2.start()
    thread2.join(timeout=5)
    assert not thread2.is_alive(), "monitor thread must end on BaseException"
    assert any(isinstance(e, SystemExit) for e in observed_errors), observed_errors
finally:
    threading.excepthook = real_hook
print("PASS | SystemExit from callback propagates out of the monitor thread")
print("RESULT: PASS")
