from __future__ import annotations

from agent.main import CyberDefenderRuntime
from agent.network.passive_inventory import WindowsPassiveNetworkProvider


class RecordingWorker:
    def __init__(self) -> None:
        self.requests = 0

    def request_sample(self) -> bool:
        self.requests += 1
        return True

    def get_latest_snapshot(self):
        return None

    def integration_state(self):
        return {"failures": self.requests, "authority": "NONE"}


def check(condition: bool, message: str, failures: list[str]) -> None:
    if condition:
        print(f"PASS | {message}")
    else:
        failures.append(message)
        print(f"FAIL | {message}")


def main() -> int:
    failures: list[str] = []
    worker = RecordingWorker()
    runtime = CyberDefenderRuntime.__new__(CyberDefenderRuntime)
    runtime.network_inventory = worker
    runtime.last_network_inventory = None
    runtime.network_inventory_failures = 0
    runtime.network_inventory_sample_every_cycles = 5
    runtime.cycle_count = 1

    CyberDefenderRuntime.update_network_inventory(runtime)
    check(worker.requests == 1, "startup schedules one passive refresh", failures)

    for cycle in (2, 3, 4):
        runtime.cycle_count = cycle
        CyberDefenderRuntime.update_network_inventory(runtime)
    check(worker.requests == 1, "repeated failed startup samples are cadence-bounded", failures)

    runtime.cycle_count = 6
    CyberDefenderRuntime.update_network_inventory(runtime)
    check(worker.requests == 2, "next refresh occurs at the configured cadence", failures)

    timeout = float(WindowsPassiveNetworkProvider.POWERSHELL_TIMEOUT_SECONDS)
    check(timeout == 8.0, "Windows snapshot timeout covers observed cold-start variance", failures)
    check(0.0 < timeout <= 10.0, "Windows snapshot timeout remains finite and bounded", failures)

    if failures:
        print(f"RESULT: FAIL={len(failures)}")
        return 1
    print("RESULT: PASS=5 FAIL=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
