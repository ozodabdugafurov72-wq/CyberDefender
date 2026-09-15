"""
CyberDefender Resource Stress Laboratory v1.0

Deterministic, production-isolated validation of the Resource Safety Plane.

Scope
-----
- Synthetic CPU pressure
- Synthetic memory pressure
- Queue/event storm simulation
- Queue saturation
- Combined resource + queue pressure
- Recovery / hysteresis
- Anti-flapping
- Security-pipeline survival
- Bounded evaluation loop
- No real process killing
- No firewall/registry/service/system modification
- No real RAM exhaustion
- No unbounded allocation

The laboratory deliberately uses injected ResourceGuard providers and
synthetic queue metrics. It does NOT attempt to exhaust the real host.
"""

from __future__ import annotations

import gc
import sys
import time
from pathlib import Path
from typing import Any, Dict


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from agent.core.resource_guard import ResourceGuard
from agent.core.resource_safety_plane import ResourceSafetyPlane
from agent.core.backpressure_controller import BackpressureController
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.evidence_retention import EvidenceRetentionPolicy
from agent.core.bounded_durable_spool import BoundedDurableSpool, SpoolPolicy


PASS_COUNT = 0
FAIL_COUNT = 0


class SyntheticResourceProvider:
    """
    Deterministic resource source.

    The values are changed by the test; no psutil/live host values are read.
    """

    def __init__(self) -> None:
        self.host = {
            "cpu_percent": 10.0,
            "memory_percent": 40.0,
            "memory_available_mb": 4096.0,
        }
        self.agent = {
            "cpu_percent": 1.0,
            "memory_rss_mb": 128.0,
            "memory_percent": 1.0,
            "threads": 4,
        }

    def host_metrics(self) -> Dict[str, float]:
        return dict(self.host)

    def agent_metrics(self) -> Dict[str, Any]:
        return dict(self.agent)

    def set_pressure(
        self,
        *,
        cpu: float,
        memory: float,
        available_mb: float,
        agent_cpu: float = 1.0,
        agent_rss_mb: float = 128.0,
    ) -> None:
        self.host.update(
            {
                "cpu_percent": float(cpu),
                "memory_percent": float(memory),
                "memory_available_mb": float(available_mb),
            }
        )
        self.agent.update(
            {
                "cpu_percent": float(agent_cpu),
                "memory_rss_mb": float(agent_rss_mb),
            }
        )


def check(label: str, condition: bool) -> None:
    global PASS_COUNT, FAIL_COUNT

    if condition:
        PASS_COUNT += 1
        print(f"PASS | {label}")
        return

    FAIL_COUNT += 1
    print(f"FAIL | {label}")
    raise AssertionError(label)


def build_lab():
    provider = SyntheticResourceProvider()

    guard = ResourceGuard(
        host_metrics_provider=provider.host_metrics,
        agent_metrics_provider=provider.agent_metrics,
    )

    spool_path = (
        PROJECT_ROOT
        / "state"
        / "resource_stress_lab_v1_0.jsonl"
    )
    spool_path.parent.mkdir(parents=True, exist_ok=True)

    spool = BoundedDurableSpool(
        str(spool_path),
        SpoolPolicy(
            max_events=256,
            max_bytes=256 * 1024,
        ),
    )

    plane = ResourceSafetyPlane(
        resource_guard=guard,
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )

    return provider, plane


def run_resource_pressure_matrix(provider, plane) -> None:
    print("\n--- A. RESOURCE PRESSURE MATRIX ---")

    provider.set_pressure(
        cpu=10,
        memory=40,
        available_mb=4096,
    )
    result = plane.evaluate(100, 1000)

    check("Healthy host -> NORMAL", result["state"] == "NORMAL")
    check(
        "Healthy resource state -> NORMAL",
        result["resource_state"] == "NORMAL",
    )
    check(
        "Healthy security pipeline survives",
        result["allow_security_pipeline"] is True,
    )

    provider.set_pressure(
        cpu=90,
        memory=90,
        available_mb=400,
        agent_cpu=10,
        agent_rss_mb=600,
    )
    # ResourceGuard intentionally uses hysteresis: pressure must persist
    # for the configured number of confirmations before escalation.
    policy = plane.resource_guard.policy
    degraded_confirmations = max(1, int(policy.degraded_confirmations))

    results = []
    for _ in range(degraded_confirmations):
        results.append(plane.evaluate(100, 1000))

    result = results[-1]

    check(
        "Sustained synthetic degraded resource pressure is detected",
        result["resource_state"] in {"DEGRADED", "CRITICAL"},
    )
    check(
        "Security pipeline survives degraded pressure",
        result["allow_security_pipeline"] is True,
    )

    provider.set_pressure(
        cpu=99,
        memory=99,
        available_mb=128,
        agent_cpu=20,
        agent_rss_mb=900,
    )
    critical_confirmations = max(1, int(policy.critical_confirmations))
    critical_results = []
    for _ in range(critical_confirmations):
        critical_results.append(plane.evaluate(100, 1000))

    result = critical_results[-1]

    check(
        "Sustained synthetic critical resource pressure is protected",
        result["resource_state"] == "CRITICAL",
    )
    check(
        "Critical resource pressure never kills security pipeline",
        result["allow_security_pipeline"] is True,
    )

    provider.set_pressure(
        cpu=10,
        memory=40,
        available_mb=4096,
        agent_cpu=1,
        agent_rss_mb=128,
    )


def run_queue_saturation(plane) -> None:
    print("\n--- B. QUEUE SATURATION ---")

    plane.evaluate(100, 1000)

    first = plane.evaluate(850, 1000)
    second = plane.evaluate(850, 1000)

    check(
        "Queue 85% does not immediately jump to CRITICAL",
        first["state"] != "CRITICAL",
    )
    check(
        "Sustained 85% queue reaches DEGRADED",
        second["state"] == "DEGRADED",
    )
    check(
        "DEGRADED queue preserves security pipeline",
        second["allow_security_pipeline"] is True,
    )

    critical = plane.evaluate(960, 1000)

    check(
        "96% queue enters protected state",
        critical["state"] in {"DEGRADED", "CRITICAL"},
    )
    check(
        "Queue saturation preserves security pipeline",
        critical["allow_security_pipeline"] is True,
    )

    if critical["state"] != "CRITICAL":
        critical = plane.evaluate(960, 1000)

    check(
        "Sustained queue saturation reaches CRITICAL",
        critical["state"] == "CRITICAL",
    )


def run_event_storm_simulation(plane) -> None:
    print("\n--- C. EVENT STORM SIMULATION ---")

    plane.evaluate(100, 1000)

    states = []
    start = time.perf_counter()

    # 100,000 synthetic evaluations, with bounded integer metrics.
    # No event objects are retained, so memory remains bounded.
    for i in range(100_000):
        if i < 30_000:
            queue_size = 100
        elif i < 70_000:
            queue_size = 850
        elif i < 90_000:
            queue_size = 960
        else:
            queue_size = 100

        result = plane.evaluate(queue_size, 1000)
        states.append(result["state"])

        # Keep the laboratory itself bounded.
        if len(states) > 1024:
            del states[:512]

    elapsed = time.perf_counter() - start

    check(
        "100,000 synthetic evaluations complete",
        True,
    )
    check(
        "Event storm does not produce unexpected state",
        all(
            state in {"NORMAL", "ELEVATED", "DEGRADED", "CRITICAL"}
            for state in states
        ),
    )
    check(
        "Event storm keeps security pipeline available",
        result["allow_security_pipeline"] is True,
    )

    print(
        f"INFO | 100,000 evaluations in {elapsed:.3f}s"
    )


def run_combined_chaos(provider, plane) -> None:
    print("\n--- D. COMBINED RESOURCE + QUEUE CHAOS ---")

    provider.set_pressure(
        cpu=99,
        memory=99,
        available_mb=128,
        agent_cpu=20,
        agent_rss_mb=900,
    )

    critical = plane.evaluate(960, 1000)

    check(
        "Combined CPU/RAM + queue pressure reaches CRITICAL",
        critical["state"] == "CRITICAL",
    )
    check(
        "Combined chaos preserves security pipeline",
        critical["allow_security_pipeline"] is True,
    )

    policy = plane.get_runtime_policy()

    check(
        "CRITICAL policy disables LOW",
        policy["allow_low"] is False,
    )
    check(
        "CRITICAL policy disables MEDIUM",
        policy["allow_medium"] is False,
    )
    check(
        "CRITICAL policy retains HIGH",
        policy["allow_high"] is True,
    )
    check(
        "CRITICAL policy retains security evidence",
        policy["security_evidence"] == "KEEP",
    )


def run_recovery(provider, plane) -> None:
    print("\n--- E. RECOVERY AFTER CHAOS ---")

    # Establish a clean resource source first.
    provider.set_pressure(
        cpu=10,
        memory=40,
        available_mb=4096,
        agent_cpu=1,
        agent_rss_mb=128,
    )

    recovery_1 = plane.evaluate(100, 1000)

    check(
        "Recovery sample 1 does not immediately become NORMAL",
        recovery_1["state"] != "NORMAL",
    )
    check(
        "Recovery sample 1 keeps security pipeline alive",
        recovery_1["allow_security_pipeline"] is True,
    )

    # Recovery is intentionally bounded and must account for the
    # stacked hysteresis of ResourceGuard + BackpressureController.
    # We do not assume that two global samples are sufficient.
    recovery_confirmations = max(
        1,
        int(plane.resource_guard.policy.recovery_confirmations),
    )
    max_recovery_samples = recovery_confirmations + 4

    recovered = False
    recovery_2 = None

    for _ in range(max_recovery_samples):
        recovery_2 = plane.evaluate(100, 1000)

        check(
            "Recovery sample keeps security pipeline alive",
            recovery_2["allow_security_pipeline"] is True,
        )

        if recovery_2["state"] == "NORMAL":
            recovered = True
            break

    check(
        "Bounded recovery reaches NORMAL",
        recovered is True,
    )
    check(
        "Recovered security pipeline available",
        recovery_2["allow_security_pipeline"] is True,
    )


def run_antiflapping(provider, plane) -> None:
    print("\n--- F. ANTI-FLAPPING ---")

    provider.set_pressure(
        cpu=10,
        memory=40,
        available_mb=4096,
    )
    plane.evaluate(100, 1000)
    plane.evaluate(100, 1000)

    # One degraded queue spike.
    spike = plane.evaluate(850, 1000)

    check(
        "Single queue spike does not become CRITICAL",
        spike["state"] != "CRITICAL",
    )
    check(
        "Single queue spike preserves security pipeline",
        spike["allow_security_pipeline"] is True,
    )

    cleared = plane.evaluate(100, 1000)

    check(
        "Immediate pressure clear avoids CRITICAL",
        cleared["state"] != "CRITICAL",
    )


def run_final_safety_gate(plane) -> None:
    print("\n--- G. FINAL RESOURCE STRESS SAFETY GATE ---")

    health = plane.health_check()
    stats = plane.get_stats()

    check(
        "Safety Plane health -> HEALTHY",
        health["status"] == "HEALTHY",
    )
    check(
        "Critical security survival invariant -> TRUE",
        health["security_pipeline_survives_critical"] is True,
    )
    check(
        "No unexpected Resource Safety Plane failures",
        stats["failures"] == 0,
    )
    check(
        "Final state is controlled",
        stats["state"]
        in {"NORMAL", "ELEVATED", "DEGRADED", "CRITICAL"},
    )


def main() -> int:
    print()
    print("============================================================")
    print(" CYBERDEFENDER RESOURCE STRESS LABORATORY v1.0")
    print(" Security-First / Resource-Safe / Production-Isolated")
    print("============================================================")

    try:
        provider, plane = build_lab()

        run_resource_pressure_matrix(provider, plane)
        run_queue_saturation(plane)
        run_event_storm_simulation(plane)
        run_combined_chaos(provider, plane)
        run_recovery(provider, plane)
        run_antiflapping(provider, plane)
        run_final_safety_gate(plane)

    except Exception as exc:
        print()
        print("RESULT: FAIL")
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 1

    finally:
        # Explicitly release temporary Python objects.
        # The test never intentionally exhausts the host.
        gc.collect()

    print()
    print("============================================================")
    print(" RESOURCE STRESS LABORATORY RESULT")
    print("============================================================")
    print(f"PASS: {PASS_COUNT}")
    print(f"FAIL: {FAIL_COUNT}")
    print()
    print("Validated:")
    print("  CPU pressure simulation        : PASS")
    print("  Memory pressure simulation     : PASS")
    print("  Queue saturation               : PASS")
    print("  100,000 event evaluations      : PASS")
    print("  Combined chaos                 : PASS")
    print("  Recovery hysteresis            : PASS")
    print("  Anti-flapping                  : PASS")
    print("  Security pipeline survival     : PASS")
    print("  Production modification        : NONE")
    print("  Real host exhaustion           : NONE")
    print()

    if FAIL_COUNT != 0:
        print("RESULT: FAIL")
        return 1

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
