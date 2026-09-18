from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Callable

from agent.network.passive_inventory import PassiveNetworkInventory


def collect_with_bounded_retry(
    inventory: Any,
    *,
    label: str,
    attempts: int = 3,
    retry_delay_seconds: float = 0.35,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, Any], int]:
    """Collect a live Windows snapshot with bounded retry for transient CIM delay.

    This helper is intentionally test-only. Production collection remains fail-fast
    at the provider boundary and is already isolated behind AsyncPassiveNetworkInventory,
    which preserves last-good evidence on collection failure. We retry only the known
    transient subprocess.TimeoutExpired condition; any other exception is surfaced
    immediately so the source gate cannot hide real defects.
    """
    bounded_attempts = max(1, min(int(attempts), 3))
    delay = max(0.0, min(float(retry_delay_seconds), 1.0))
    last_timeout: subprocess.TimeoutExpired | None = None

    for attempt in range(1, bounded_attempts + 1):
        try:
            snapshot = inventory.collect()
            if not isinstance(snapshot, dict):
                raise RuntimeError("NETWORK_LIVE_SMOKE_INVALID_SNAPSHOT")
            if attempt > 1:
                print(
                    "INFO | Windows snapshot recovered after transient timeout "
                    f"| label={label} | attempt={attempt}/{bounded_attempts}"
                )
            return snapshot, attempt
        except subprocess.TimeoutExpired as exc:
            last_timeout = exc
            print(
                "WARN | transient Windows network snapshot timeout "
                f"| label={label} | attempt={attempt}/{bounded_attempts} "
                f"| timeout={getattr(exc, 'timeout', None)}"
            )
            if attempt < bounded_attempts and delay > 0:
                sleep_fn(delay)

    assert last_timeout is not None
    raise last_timeout


def main() -> int:
    if os.name != "nt":
        print("SKIP | Windows live flow smoke is Windows-only")
        print("RESULT: PASS")
        return 0

    inventory = PassiveNetworkInventory(max_devices=64, max_connections=64)
    try:
        first, first_attempts = collect_with_bounded_retry(inventory, label="first")
        time.sleep(1.0)
        second, second_attempts = collect_with_bounded_retry(inventory, label="second")
    finally:
        inventory.close()

    flow1 = first.get("flow_telemetry", {})
    flow2 = second.get("flow_telemetry", {})
    interfaces = flow2.get("interfaces", []) if isinstance(flow2.get("interfaces"), list) else []
    aggregate = flow2.get("aggregate", {}) if isinstance(flow2.get("aggregate"), dict) else {}
    baseline = flow2.get("baseline_analysis", {}) if isinstance(flow2.get("baseline_analysis"), dict) else {}

    checks = [
        (second.get("schema") == "cyberdefender.network-inventory.v0.1.9", "live outer schema v0.1.9"),
        (flow2.get("status") in {"HEALTHY", "STARTING"}, "live continuous interface flow telemetry available"),
        (flow2.get("mode") == "PASSIVE_INTERFACE_CONTINUOUS_COUNTERS", "live flow mode uses continuous counter sampler"),
        (float(flow2.get("cadence_seconds", 0) or 0) > 0, "continuous flow cadence is explicit"),
        (len(interfaces) >= 1, "local interface counters observed"),
        (int(aggregate.get("active_interfaces", 0) or 0) >= 1, "active default-route interface included"),
        (flow2.get("packet_capture") is False, "packet capture remains disabled"),
        (flow2.get("per_connection_byte_attribution") is False, "per-connection byte attribution remains disabled"),
        (flow2.get("authority") == "NONE", "flow authority remains NONE"),
        ("coverage_percent" in (flow2.get("continuity") or {}), "sampling continuity coverage is observable"),
        ("gap_events" in (flow2.get("continuity") or {}), "sampling gaps are observable"),
        (baseline.get("schema") == "cyberdefender.flow-baseline.v0.1.9", "robust flow baseline analysis is observable"),
        (baseline.get("authority") == "NONE" and baseline.get("authorization") == "NOT_GRANTED", "flow baseline grants no authority"),
        (baseline.get("status") in {"WARMING", "READY", "DEGRADED"}, "flow baseline state is explicit"),
        (all(float(row.get("tx_bytes_per_second", 0) or 0) >= 0 for row in interfaces), "transmit rates are non-negative"),
        (all(float(row.get("rx_bytes_per_second", 0) or 0) >= 0 for row in interfaces), "receive rates are non-negative"),
        (first.get("active_scan_enabled") is False and second.get("active_scan_enabled") is False, "active scan remains disabled"),
    ]
    failed = 0
    for ok, label in checks:
        if ok:
            print(f"PASS | {label}")
        else:
            failed += 1
            print(f"FAIL | {label}")

    print(f"WINDOWS_SNAPSHOT_FIRST_ATTEMPTS={first_attempts}")
    print(f"WINDOWS_SNAPSHOT_SECOND_ATTEMPTS={second_attempts}")
    print("WINDOWS_SNAPSHOT_RETRY_POLICY=TIMEOUT_ONLY_BOUNDED_3")
    print(f"FLOW_INTERFACES={len(interfaces)}")
    print(f"FLOW_ACTIVE_INTERFACES={aggregate.get('active_interfaces', 0)}")
    print(f"FLOW_BASELINE_READY={aggregate.get('baseline_ready', False)}")
    print(f"FLOW_RX_BPS={aggregate.get('rx_bytes_per_second', 0)}")
    print(f"FLOW_TX_BPS={aggregate.get('tx_bytes_per_second', 0)}")
    print(f"FLOW_SEQUENCE={flow2.get('sequence', 0)}")
    print(f"FLOW_COVERAGE={((flow2.get('continuity') or {}).get('coverage_percent', 0))}")
    print(f"FLOW_GAPS={((flow2.get('continuity') or {}).get('gap_events', 0))}")
    print(f"FLOW_BASELINE_STATUS={baseline.get('status', 'UNKNOWN')}")
    print(f"FLOW_BASELINE_CONFIDENCE={baseline.get('confidence_percent', 0)}")
    print(f"FLOW_BASELINE_SAMPLES={baseline.get('baseline_samples', 0)}")
    print("RESULT: PASS" if failed == 0 else f"RESULT: FAIL={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
