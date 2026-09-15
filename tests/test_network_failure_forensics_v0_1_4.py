from __future__ import annotations

import time

from agent.network.async_inventory import AsyncPassiveNetworkInventory


failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"PASS | {message}")
    else:
        failures.append(message)
        print(f"FAIL | {message}")


def wait_until(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


class RecoveringCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("INTENTIONAL_FAILURE_DETAIL")
        return {
            "schema": "fixture.network",
            "mode": "PASSIVE_ONLY",
            "authority": "NONE",
            "authoritative": False,
            "active_scan_enabled": False,
            "sampled_at": time.time(),
            "summary": {"observed_peers_online": 1},
            "devices": [],
            "connections": [],
        }

    def health_check(self):
        return {"status": "HEALTHY", "authority": "NONE"}


class AlwaysGoodCollector:
    def collect(self):
        return {
            "schema": "fixture.network",
            "mode": "PASSIVE_ONLY",
            "authority": "NONE",
            "authoritative": False,
            "active_scan_enabled": False,
            "sampled_at": time.time(),
            "summary": {},
            "devices": [],
            "connections": [],
        }


def main() -> int:
    collector = RecoveringCollector()
    worker = AsyncPassiveNetworkInventory(collector, deadline_seconds=1.0)

    worker.request_sample()
    check(wait_until(lambda: worker.integration_state()["completed"] >= 1), "initial good network sample completes")

    worker.request_sample()
    check(wait_until(lambda: worker.integration_state()["completed"] >= 2), "intentional network failure is observed")
    failed = worker.integration_state()
    check(failed["failures_total"] == 1, "failure total is retained")
    check(failed["consecutive_failures"] == 1, "consecutive failure count increments")
    check(failed["last_failure_type"] == "RuntimeError", "last failure type is retained")
    check(failed["last_failure_reason"] == "INTENTIONAL_FAILURE_DETAIL", "bounded failure reason is retained")
    check(failed["last_failure_at"] is not None, "last failure timestamp is retained")
    check(failed["last_error"] == "RuntimeError", "current error remains observable until recovery")
    check(worker.health_check()["status"] == "DEGRADED", "current collector failure degrades only network telemetry health")

    worker.request_sample()
    check(wait_until(lambda: worker.integration_state()["completed"] >= 3), "collector recovers on a later sample")
    recovered = worker.integration_state()
    check(recovered["last_error"] is None, "current error clears after successful recovery")
    check(recovered["consecutive_failures"] == 0, "consecutive failure count resets after recovery")
    check(recovered["failures_total"] == 1, "historical failure total survives recovery")
    check(recovered["last_failure_type"] == "RuntimeError", "historical failure type survives recovery")
    check(recovered["last_failure_reason"] == "INTENTIONAL_FAILURE_DETAIL", "historical failure reason survives recovery")
    check(worker.health_check()["status"] == "HEALTHY", "recovered network telemetry returns to healthy")
    worker.close()

    stale_worker = AsyncPassiveNetworkInventory(AlwaysGoodCollector(), deadline_seconds=1.0)
    stale_worker.stale_after_seconds = 0.05
    stale_worker.request_sample()
    check(wait_until(lambda: stale_worker.integration_state()["completed"] >= 1), "stale fixture receives initial success")
    time.sleep(0.08)
    stale_state = stale_worker.integration_state()
    check(stale_state["stale"] is True, "last-good sample becomes explicitly stale after threshold")
    check(stale_state["last_success_age_seconds"] >= 0.05, "last-success age is explicit telemetry")
    check(stale_worker.health_check()["status"] == "DEGRADED", "stale optional telemetry is observable without core authorization impact")
    stale_worker.close()

    if failures:
        print(f"RESULT: FAIL={len(failures)}")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
