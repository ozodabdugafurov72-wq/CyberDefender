from __future__ import annotations

import os
import time

from agent.network.passive_inventory import PassiveNetworkInventory


def main() -> int:
    if os.name != "nt":
        print("SKIP | Windows live flow smoke is Windows-only")
        print("RESULT: PASS")
        return 0

    inventory = PassiveNetworkInventory(max_devices=64, max_connections=64)
    try:
        first = inventory.collect()
        time.sleep(1.0)
        second = inventory.collect()
    finally:
        inventory.close()

    flow1 = first.get("flow_telemetry", {})
    flow2 = second.get("flow_telemetry", {})
    interfaces = flow2.get("interfaces", []) if isinstance(flow2.get("interfaces"), list) else []
    aggregate = flow2.get("aggregate", {}) if isinstance(flow2.get("aggregate"), dict) else {}

    checks = [
        (second.get("schema") == "cyberdefender.network-inventory.v0.1.8", "live outer schema v0.1.8"),
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

    print(f"FLOW_INTERFACES={len(interfaces)}")
    print(f"FLOW_ACTIVE_INTERFACES={aggregate.get('active_interfaces', 0)}")
    print(f"FLOW_BASELINE_READY={aggregate.get('baseline_ready', False)}")
    print(f"FLOW_RX_BPS={aggregate.get('rx_bytes_per_second', 0)}")
    print(f"FLOW_TX_BPS={aggregate.get('tx_bytes_per_second', 0)}")
    print(f"FLOW_SEQUENCE={flow2.get('sequence', 0)}")
    print(f"FLOW_COVERAGE={((flow2.get('continuity') or {}).get('coverage_percent', 0))}")
    print(f"FLOW_GAPS={((flow2.get('continuity') or {}).get('gap_events', 0))}")
    print("RESULT: PASS" if failed == 0 else f"RESULT: FAIL={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
