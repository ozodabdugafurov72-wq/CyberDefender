from __future__ import annotations

import threading
import time

from agent.main import CyberDefenderRuntime
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


class SlowCollector:
    def __init__(self, delay: float = 0.30) -> None:
        self.delay = delay
        self.calls = 0

    def collect(self):
        self.calls += 1
        time.sleep(self.delay)
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


class SequenceCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self):
        self.calls += 1
        if self.calls == 1:
            return {
                "schema": "fixture.network",
                "mode": "PASSIVE_ONLY",
                "authority": "NONE",
                "authoritative": False,
                "active_scan_enabled": False,
                "sampled_at": 123.0,
                "summary": {"observed_peers_online": 1},
                "devices": [{"ip_address": "10.0.0.1"}],
                "connections": [],
            }
        raise RuntimeError("INTENTIONAL_NETWORK_FIXTURE_FAILURE")

    def health_check(self):
        return {"status": "HEALTHY", "authority": "NONE"}


class GateCollector:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def collect(self):
        self.calls += 1
        self.started.set()
        self.release.wait(5.0)
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


def main() -> int:
    # --------------------------------------------------------
    # 1. Runtime path must not wait for a slow collector.
    # --------------------------------------------------------
    slow = SlowCollector(0.35)
    worker = AsyncPassiveNetworkInventory(slow, deadline_seconds=1.0)
    runtime = CyberDefenderRuntime.__new__(CyberDefenderRuntime)
    runtime.network_inventory = worker
    runtime.last_network_inventory = None
    runtime.network_inventory_failures = 0
    runtime.network_inventory_sample_every_cycles = 5
    runtime.cycle_count = 1

    started = time.perf_counter()
    result = CyberDefenderRuntime.update_network_inventory(runtime)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    check(result is None, "first non-blocking request does not fabricate a completed sample")
    check(elapsed_ms < 100.0, "runtime network update returns without waiting for slow collection")
    check(wait_until(lambda: worker.get_latest_snapshot() is not None), "background worker publishes completed last-good snapshot")

    runtime.cycle_count = 2
    started = time.perf_counter()
    result = CyberDefenderRuntime.update_network_inventory(runtime)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    check(isinstance(result, dict), "runtime consumes latest completed passive snapshot")
    check(elapsed_ms < 100.0, "consuming completed snapshot remains bounded/non-blocking")
    integration = result.get("runtime_integration", {}) if isinstance(result, dict) else {}
    check(integration.get("mode") == "ASYNC_BOUNDED", "dashboard snapshot exposes async bounded integration mode")
    check(integration.get("authority") == "NONE", "async worker grants no authority")
    worker.close()

    # --------------------------------------------------------
    # 2. Failure must preserve previous good evidence.
    # --------------------------------------------------------
    sequence = SequenceCollector()
    worker = AsyncPassiveNetworkInventory(sequence, deadline_seconds=1.0)
    worker.request_sample()
    check(wait_until(lambda: worker.integration_state()["completed"] >= 1), "first sequence sample completes")
    first = worker.get_latest_snapshot()
    worker.request_sample()
    check(wait_until(lambda: worker.integration_state()["completed"] >= 2), "failed follow-up sample is observed")
    after_failure = worker.get_latest_snapshot()
    state = worker.integration_state()
    check(state["failures"] == 1, "background collection failure counter increments")
    check(after_failure is not None and after_failure.get("sampled_at") == first.get("sampled_at"), "failure preserves last good snapshot")
    check(worker.health_check()["status"] == "DEGRADED", "optional network worker failure is explicitly observable")
    worker.close()

    # --------------------------------------------------------
    # 3. Pending work is coalesced to one follow-up request.
    # --------------------------------------------------------
    gate = GateCollector()
    worker = AsyncPassiveNetworkInventory(gate, deadline_seconds=1.0)
    worker.request_sample()
    check(gate.started.wait(1.0), "gate collector entered first in-flight collection")
    accepted = [worker.request_sample() for _ in range(20)]
    check(sum(1 for x in accepted if x) <= 1, "burst requests create at most one pending refresh")
    check(worker.integration_state()["coalesced"] >= 19, "excess refresh requests are coalesced")
    gate.release.set()
    check(wait_until(lambda: worker.integration_state()["completed"] >= 2), "single coalesced follow-up refresh completes")
    check(gate.calls == 2, "bounded worker executes only initial plus one coalesced collection")
    worker.close()

    # --------------------------------------------------------
    # 4. Deadline overrun must be observable without blocking caller.
    # --------------------------------------------------------
    gate = GateCollector()
    worker = AsyncPassiveNetworkInventory(gate, deadline_seconds=0.25, close_join_seconds=0.05)
    worker.request_sample()
    check(gate.started.wait(1.0), "deadline fixture collection starts")
    time.sleep(0.30)
    health = worker.health_check()
    check(health["status"] == "DEGRADED", "deadline overrun degrades only network telemetry health")
    check(health["worker"]["deadline_exceeded"] is True, "deadline overrun is explicit telemetry")

    started = time.perf_counter()
    worker.close()
    close_ms = (time.perf_counter() - started) * 1000.0
    check(close_ms < 250.0, "close remains bounded even while optional collector is stuck")
    check(worker.close_incomplete is True, "bounded close reports unfinished daemon worker instead of blocking")
    gate.release.set()

    # --------------------------------------------------------
    # 5. Static authority boundaries.
    # --------------------------------------------------------
    health = worker.health_check()
    check(health["authority"] == "NONE", "worker health keeps authority NONE")
    check(health["active_scan_enabled"] is False, "worker cannot enable active scanning")
    check(health["packet_injection"] is False, "worker exposes no packet injection")
    check(health["firewall_mutation"] is False, "worker exposes no firewall mutation")

    if failures:
        print(f"RESULT: FAIL={len(failures)}")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
