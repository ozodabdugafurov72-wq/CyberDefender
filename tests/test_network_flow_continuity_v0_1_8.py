from __future__ import annotations

import inspect

from agent.network.flow_continuity import PassiveInterfaceFlowSampler, _default_counter_reader


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


class ManualClock:
    def __init__(self) -> None:
        self.mono = 0.0
        self.wall = 1000.0

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += seconds


class Reader:
    def __init__(self) -> None:
        self.rows = [{
            "interface": "Wi-Fi",
            "bytes_sent": 1000,
            "bytes_recv": 2000,
            "packets_sent": 10,
            "packets_recv": 20,
            "errin": 0,
            "errout": 0,
            "dropin": 0,
            "dropout": 0,
        }]

    def __call__(self):
        return [dict(row) for row in self.rows]


def main() -> int:
    clock = ManualClock()
    reader = Reader()
    sampler = PassiveInterfaceFlowSampler(
        counter_reader=reader,
        cadence_seconds=1.0,
        history_seconds=60,
        wall_clock=clock.time,
        monotonic_clock=clock.monotonic,
        autostart=False,
    )

    check(sampler.sample_once(), "first bounded sample succeeds")
    first = sampler.snapshot({"wi-fi"})
    check(first["schema"] == "cyberdefender.interface-flow-continuity.v0.1.9", "v0.1.9 continuity schema is explicit")
    check(first["mode"] == "PASSIVE_INTERFACE_CONTINUOUS_COUNTERS", "continuous local-counter mode is explicit")
    check(first["aggregate"]["baseline_ready"] is False, "first sample is warm-up only")
    check(first["packet_capture"] is False, "packet capture remains disabled")
    check(first["per_connection_byte_attribution"] is False, "per-connection byte attribution remains disabled")
    check(first["authority"] == "NONE", "flow continuity grants no authority")

    clock.advance(1.0)
    reader.rows[0].update(bytes_sent=2000, bytes_recv=4000, packets_sent=20, packets_recv=40)
    check(sampler.sample_once(), "second sample succeeds")

    clock.advance(1.0)
    reader.rows[0].update(bytes_sent=3500, bytes_recv=7000, packets_sent=35, packets_recv=70)
    check(sampler.sample_once(), "third sample succeeds")
    third = sampler.snapshot({"wi-fi"})
    agg = third["aggregate"]
    check(agg["baseline_ready"] is True, "continuous baseline is ready")
    check(agg["instant_tx_bytes_per_second"] == 1500.0, "instant TX rate uses latest 1s delta")
    check(agg["instant_rx_bytes_per_second"] == 3000.0, "instant RX rate uses latest 1s delta")
    check(agg["window_5s"]["tx_bytes_per_second_avg"] == 1250.0, "5s TX rolling mean retains both valid intervals")
    check(agg["window_5s"]["rx_bytes_per_second_avg"] == 2500.0, "5s RX rolling mean retains both valid intervals")
    check(third["continuity"]["coverage_percent"] == 100.0, "gap-free sampling coverage is 100 percent")
    check(third["continuity"]["gap_events"] == 0, "gap-free sampling reports no gaps")
    check(third["sequence"] == 3, "monotonic sequence is explicit")

    # Simulate a scheduling/sleep gap. The sampler may still derive a bounded
    # average rate for a modest gap, but the discontinuity must never disappear.
    clock.advance(4.0)
    reader.rows[0].update(bytes_sent=7500, bytes_recv=15000, packets_sent=75, packets_recv=150)
    check(sampler.sample_once(), "post-gap sample succeeds")
    gap = sampler.snapshot({"wi-fi"})
    check(gap["continuity"]["gap_events"] == 1, "sampling discontinuity is explicitly counted")
    check(gap["continuity"]["missed_slots_estimate"] >= 3, "missed cadence slots are estimated")
    check(gap["continuity"]["coverage_percent"] < 100.0, "coverage does not fabricate perfect continuity after a gap")
    check(float(gap["continuity"]["max_gap_seconds_observed"]) >= 4.0, "maximum observed gap is retained")

    # Counter rollback must create a new baseline rather than a negative/wrapped rate.
    clock.advance(1.0)
    reader.rows[0].update(bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2)
    check(sampler.sample_once(), "counter-reset sample succeeds")
    reset = sampler.snapshot({"wi-fi"})
    row = reset["interfaces"][0]
    check(row["counter_reset"] is True, "counter rollback is explicit")
    check(row["baseline_ready"] is False, "counter reset suppresses misleading rate")
    check(row["tx_bytes_per_second"] == 0.0 and row["rx_bytes_per_second"] == 0.0, "counter reset never fabricates negative or wrapped throughput")

    # Staleness is explicit; we never keep calling old evidence fresh.
    clock.advance(4.0)
    stale = sampler.snapshot({"wi-fi"})
    check(stale["stale"] is True, "old flow evidence becomes explicitly stale")
    check(stale["status"] == "DEGRADED", "stale continuity is degraded, not silently healthy")

    source = inspect.getsource(_default_counter_reader)
    forbidden = ("sniff", "pcap", "WinDivert", "Resolve-DnsName", "Test-Connection", "Test-NetConnection", "socket.connect")
    check("net_io_counters" in source, "fast sampler reads local cumulative interface counters")
    check(not any(token in source for token in forbidden), "fast sampler contains no capture/probe/active-network primitive")

    sampler.close()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
