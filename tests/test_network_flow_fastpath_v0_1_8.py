from __future__ import annotations

import inspect
import time

from agent.network.async_inventory import AsyncPassiveNetworkInventory
from agent.network.passive_inventory import PassiveNetworkInventory


PASS = 0
FAIL = 0


def check(condition: bool, label: str) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS | {label}")
    else:
        FAIL += 1
        print(f"FAIL | {label}")


class FastCollector:
    def __init__(self) -> None:
        self.collects = 0
        self.fast_reads = 0

    def collect(self):
        self.collects += 1
        return {
            "schema": "cyberdefender.network-inventory.v0.1.8",
            "summary": {"flow_sequence": 1},
            "flow_telemetry": {"sequence": 1, "aggregate": {}},
        }

    def fast_flow_snapshot(self):
        self.fast_reads += 1
        return {
            "schema": "cyberdefender.interface-flow-continuity.v0.1.8",
            "sequence": 100 + self.fast_reads,
            "sample_age_seconds": 0.1,
            "aggregate": {
                "active_interfaces": 1,
                "baseline_ready": True,
                "rx_bytes_per_second": float(100 + self.fast_reads),
                "tx_bytes_per_second": float(50 + self.fast_reads),
                "window_5s": {
                    "rx_bytes_per_second_avg": 99.0,
                    "tx_bytes_per_second_avg": 49.0,
                },
            },
            "continuity": {"coverage_percent": 100.0, "gap_events": 0},
            "authority": "NONE",
            "authoritative": False,
        }

    @staticmethod
    def merge_fast_flow(snapshot, flow):
        snapshot["flow_telemetry"] = flow
        snapshot.setdefault("summary", {})["flow_sequence"] = flow["sequence"]
        return snapshot

    def health_check(self):
        return {"status": "HEALTHY", "authority": "NONE"}


class MemoryOnlySampler:
    def snapshot(self, active):
        return {"sequence": 7, "authority": "NONE", "aggregate": {"active_interfaces": len(active)}}

    def close(self):
        return None


def main() -> int:
    collector = FastCollector()
    worker = AsyncPassiveNetworkInventory(collector, deadline_seconds=2.0)
    try:
        worker.request_sample()
        deadline = time.time() + 2.0
        while worker.completed < 1 and time.time() < deadline:
            time.sleep(0.01)
        check(worker.completed == 1, "one heavy inventory collection completes")
        before = collector.collects
        first = worker.get_latest_snapshot()
        second = worker.get_latest_snapshot()
        check(first is not None and second is not None, "latest snapshots remain available")
        check(collector.collects == before == 1, "fast flow refresh does not trigger another heavy inventory collection")
        check(int(second["flow_telemetry"]["sequence"]) > int(first["flow_telemetry"]["sequence"]), "flow evidence can refresh between heavy inventory samples")
        check(second["fast_flow_refresh"]["mode"] == "MEMORY_ONLY", "fast path is explicitly memory-only")
        check(second["fast_flow_refresh"]["authority"] == "NONE", "fast path grants no authority")
        check(second["runtime_integration"]["mode"] == "ASYNC_BOUNDED", "bounded async inventory model is preserved")
    finally:
        worker.close()

    # The production fast-flow accessor itself must remain memory-only.
    source = inspect.getsource(PassiveNetworkInventory.fast_flow_snapshot)
    forbidden = ("provider.collect", "powershell", "subprocess", "net_connections", "Get-DnsClientCache", "net_io_counters")
    check(not any(token in source for token in forbidden), "production fast-flow accessor performs no OS/network collection")
    check("snapshot" in source, "production fast-flow accessor snapshots bounded in-memory sampler state")

    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
