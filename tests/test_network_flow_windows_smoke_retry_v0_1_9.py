from __future__ import annotations

import subprocess

from tests.test_network_flow_live_windows_v0_1_7 import collect_with_bounded_retry


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


class TimeoutThenSuccessInventory:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self):
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=3.0)
        return {"ok": True}


class AlwaysTimeoutInventory:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self):
        self.calls += 1
        raise subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=3.0)


class NonTimeoutFailureInventory:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self):
        self.calls += 1
        raise RuntimeError("REAL_DEFECT")


def main() -> int:
    sleeps: list[float] = []
    inv = TimeoutThenSuccessInventory()
    snapshot, attempts = collect_with_bounded_retry(
        inv,
        label="fixture-transient",
        attempts=3,
        retry_delay_seconds=0.25,
        sleep_fn=sleeps.append,
    )
    check(snapshot == {"ok": True}, "transient timeout recovers with a valid snapshot")
    check(attempts == 2 and inv.calls == 2, "transient timeout consumes exactly one bounded retry")
    check(sleeps == [0.25], "bounded retry delay is explicit and deterministic")

    inv2 = AlwaysTimeoutInventory()
    sleeps2: list[float] = []
    try:
        collect_with_bounded_retry(
            inv2,
            label="fixture-persistent",
            attempts=3,
            retry_delay_seconds=0.1,
            sleep_fn=sleeps2.append,
        )
    except subprocess.TimeoutExpired:
        persistent_raised = True
    else:
        persistent_raised = False
    check(persistent_raised, "persistent Windows timeout is not hidden")
    check(inv2.calls == 3, "persistent timeout retry count is capped at three attempts")
    check(sleeps2 == [0.1, 0.1], "persistent timeout uses only bounded inter-attempt delays")

    inv3 = NonTimeoutFailureInventory()
    try:
        collect_with_bounded_retry(
            inv3,
            label="fixture-real-defect",
            attempts=3,
            retry_delay_seconds=0.1,
            sleep_fn=lambda _: None,
        )
    except RuntimeError as exc:
        immediate = str(exc) == "REAL_DEFECT"
    else:
        immediate = False
    check(immediate, "non-timeout defect is surfaced immediately")
    check(inv3.calls == 1, "non-timeout defect is never retried or masked")

    print("RESULT: PASS=8 FAIL=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
