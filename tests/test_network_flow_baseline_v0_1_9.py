from __future__ import annotations

import inspect

from agent.network.flow_baseline import FlowBaselineAnalyzer
from agent.network.flow_continuity import PassiveInterfaceFlowSampler


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


def agg(rx: float, tx: float, ready: bool = True) -> dict:
    return {
        "baseline_ready": ready,
        "rx_bytes_per_second": rx,
        "tx_bytes_per_second": tx,
    }


def main() -> int:
    analyzer = FlowBaselineAnalyzer(
        min_samples=5,
        max_samples=20,
        min_continuity_percent=95.0,
        absolute_floor_bps=1024.0,
        median_multiplier=2.0,
        mad_multiplier=4.0,
    )

    warm = analyzer.analyze(
        [agg(1000, 800), agg(1100, 900), agg(900, 700)],
        coverage_percent=100.0,
        stale=False,
        sequence=3,
    )
    check(warm["schema"] == "cyberdefender.flow-baseline.v0.1.9", "v0.1.9 baseline schema is explicit")
    check(warm["status"] == "WARMING", "insufficient history remains warming")
    check(warm["anomaly_candidate"] is False, "warming baseline cannot emit anomaly candidate")
    check(warm["authority"] == "NONE" and warm["authorization"] == "NOT_GRANTED", "baseline analysis grants no authority")
    check(warm["creates_incident"] is False and warm["changes_risk"] is False, "baseline analysis cannot create incident or change risk")

    normal_samples = [agg(1000, 800), agg(1050, 820), agg(980, 790), agg(1020, 810), agg(1010, 805), agg(990, 795)]
    normal = analyzer.analyze(normal_samples, coverage_percent=100.0, stale=False, sequence=6)
    check(normal["status"] == "READY", "robust baseline becomes ready after minimum prior samples")
    check(normal["confidence_percent"] == 100.0, "clean complete evidence reaches full evidence-quality confidence")
    check(normal["rx"]["candidate"] is False and normal["tx"]["candidate"] is False, "normal variation is not an anomaly candidate")
    check(normal["method"]["newest_sample_excluded_from_training"] is True, "newest sample never trains its own threshold")

    spike_samples = normal_samples[:-1] + [agg(250000, 220000)]
    spike = analyzer.analyze(spike_samples, coverage_percent=100.0, stale=False, sequence=6)
    check(spike["status"] == "READY", "spike evaluation keeps baseline ready")
    check(spike["anomaly_candidate"] is True, "large deviation becomes observation-only candidate")
    check(spike["rx"]["candidate"] is True and spike["tx"]["candidate"] is True, "directional candidates are explicit")
    check(spike["candidate_semantics"] == "CORRELATION_EVIDENCE_ONLY_NOT_MALICIOUS_VERDICT", "candidate is not a malicious verdict")
    check(spike["semantics"]["high_traffic"] == "NOT_EQUIVALENT_TO_MALICIOUS_ACTIVITY", "high traffic is never equated with malicious activity")

    low_quality = analyzer.analyze(spike_samples, coverage_percent=50.0, stale=False, sequence=6)
    check(low_quality["status"] == "DEGRADED", "poor continuity degrades baseline state")
    check(low_quality["confidence_percent"] == 50.0, "continuity bounds evidence confidence")
    check(low_quality["anomaly_candidate"] is False, "low-quality evidence cannot raise anomaly candidate")

    stale = analyzer.analyze(spike_samples, coverage_percent=100.0, stale=True, sequence=6)
    check(stale["status"] == "DEGRADED" and stale["confidence_percent"] == 0.0, "stale evidence fails closed to zero confidence")
    check(stale["anomaly_candidate"] is False, "stale evidence cannot raise candidate")

    # Integration proof: sampler publishes baseline analysis without any extra I/O.
    class Clock:
        def __init__(self): self.mono = 0.0; self.wall = 1000.0
        def monotonic(self): return self.mono
        def time(self): return self.wall
        def advance(self, s): self.mono += s; self.wall += s

    class Reader:
        def __init__(self): self.sent = 1000; self.recv = 2000
        def __call__(self):
            return [{"interface":"Wi-Fi","bytes_sent":self.sent,"bytes_recv":self.recv,"packets_sent":10,"packets_recv":20,"errin":0,"errout":0,"dropin":0,"dropout":0}]

    clock = Clock(); reader = Reader()
    sampler = PassiveInterfaceFlowSampler(counter_reader=reader, cadence_seconds=1.0, wall_clock=clock.time, monotonic_clock=clock.monotonic, autostart=False)
    for _ in range(18):
        sampler.sample_once(); clock.advance(1.0); reader.sent += 1000; reader.recv += 2000
    snap = sampler.snapshot({"wi-fi"})
    check(snap["schema"] == "cyberdefender.interface-flow-continuity.v0.1.9", "sampler publishes v0.1.9 continuity schema")
    check(snap["baseline_analysis"]["status"] == "READY", "sampler integration reaches robust baseline readiness")
    check(snap["baseline_analysis"]["observation_only"] is True, "integrated baseline remains observation only")
    sampler.close()

    source = inspect.getsource(FlowBaselineAnalyzer)
    forbidden = ("socket", "subprocess", "powershell", "Resolve-DnsName", "Test-NetConnection", "pcap", "sniff")
    check(not any(token.lower() in source.lower() for token in forbidden), "baseline analyzer performs no OS/network collection")

    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
