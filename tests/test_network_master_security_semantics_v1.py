from __future__ import annotations

import subprocess

from agent.network.active_verification import BoundedNetworkVerifier, NetworkVerificationPolicy
from agent.network.passive_inventory import PassiveNetworkInventory
from agent.correlation.engine import CorrelationEngine
from dashboard_owner.server import dedupe_events


failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"PASS | {message}")
    else:
        failures.append(message)
        print(f"FAIL | {message}")


class FixtureProvider:
    def __init__(self) -> None:
        self.round = 0

    def collect(self):
        self.round += 1
        gateway_mac = "AA-BB-CC-DD-EE-01" if self.round == 1 else "AA-BB-CC-DD-EE-99"
        return {
            "interfaces": [{"name": "Ethernet", "is_up": True, "addresses": []}],
            "active_networks": [{
                "InterfaceAlias": "Ethernet",
                "InterfaceIndex": 4,
                "IPv4Address": "10.20.30.10",
                "PrefixLength": 24,
                "Gateway": "10.20.30.1",
            }],
            "neighbors": [
                {
                    "InterfaceAlias": "Ethernet",
                    "IPAddress": "10.20.30.1",
                    "LinkLayerAddress": gateway_mac,
                    "State": "Reachable",
                    "hostname": "gateway.lab",
                },
                {
                    "InterfaceAlias": "Ethernet",
                    "IPAddress": "10.20.30.20",
                    "LinkLayerAddress": "AA-BB-CC-DD-EE-20",
                    "State": "Reachable",
                    "endpoint_id": "endpoint-a",
                    "hostname": "PC-JDU",
                },
                {
                    "InterfaceAlias": "Ethernet",
                    "IPAddress": "10.20.30.21",
                    "LinkLayerAddress": "AA-BB-CC-DD-EE-21",
                    "State": "Reachable",
                    "endpoint_id": "endpoint-b",
                    "hostname": "PC-JDU",
                },
                {
                    "InterfaceAlias": "Ethernet",
                    "IPAddress": "10.20.30.40",
                    "LinkLayerAddress": "AA-BB-CC-DD-EE-40",
                    "State": "Reachable",
                },
                {
                    "InterfaceAlias": "Ethernet",
                    "IPAddress": "10.20.30.40",
                    "LinkLayerAddress": "AA-BB-CC-DD-EE-41",
                    "State": "Reachable",
                },
            ],
            "connections": [],
            "dns_cache": {"entries": [{"ip_address": "10.20.30.20", "name": "pc-jdu-a.lab"}]},
        }


def main() -> int:
    # Construction and disabled verification do not invoke subprocess/network APIs.
    calls: list[tuple] = []
    original_run = subprocess.run
    subprocess.run = lambda *args, **kwargs: calls.append((args, kwargs))  # type: ignore[assignment]
    try:
        verifier = BoundedNetworkVerifier()
        report = verifier.verify([{"ip_address": "10.20.30.20", "source": "PASSIVE_INVENTORY"}])
    finally:
        subprocess.run = original_run
    check(report["status"] == "DISABLED", "active verification is disabled by default")
    check(calls == [], "import/construct/disabled verification performs zero network actions")

    policy = NetworkVerificationPolicy.from_mapping(
        {
            "schema": NetworkVerificationPolicy.SCHEMA,
            "enabled": True,
            "operator_approved": True,
            "approval_ref": "LAB-REVIEW-1",
            "allowed_cidrs": ["10.20.30.0/24"],
            "active_probe": False,
            "operation_budget_seconds": 0.25,
        },
        admission_check=lambda payload: True,
    )

    class TickingClock:
        def __init__(self) -> None:
            self.value = 0.0

        def __call__(self) -> float:
            self.value += 0.1
            return self.value

    clock = TickingClock()
    bounded = BoundedNetworkVerifier(policy, resolver=lambda *args: {"status": "NO_MATCH"}, clock=lambda: 1000.0, monotonic_clock=clock)
    budget_report = bounded.verify(
        {"ip_address": f"10.20.30.{n}", "source": "PASSIVE_INVENTORY", "online": True} for n in range(20, 40)
    )
    check(budget_report["status"] == "DEGRADED", "operation budget failure is explicit and fail-closed")
    check(len(budget_report["results"]) < 20, "verification work is bounded by an operation budget")
    check(budget_report["authority"] == "NONE" and budget_report["authorization"] == "NOT_GRANTED", "active evidence grants no authority")

    inventory = PassiveNetworkInventory(provider=FixtureProvider(), max_devices=64, max_connections=64)
    first = inventory.collect()
    devices = first["devices"]
    check(
        {row.get("endpoint_id") for row in devices if row.get("endpoint_id")} == {"endpoint-a", "endpoint-b"},
        "duplicate hostnames remain independent by canonical endpoint_id",
    )
    peer = next(row for row in devices if row.get("endpoint_id") == "endpoint-a")
    check(peer["identity_state"] == "IDENTIFIED" and peer["trust_state"] == "UNVERIFIED", "identity and trust are separate dimensions")
    check(peer["observed_name"] == "pc-jdu-a.lab" and peer["identity_evidence"][-1] == "REVERSE_DNS", "observed DNS name retains provenance without becoming trust")
    check(peer["presence_state"] == "ACTIVE" and peer["user_binding"]["status"] == "UNKNOWN", "presence and user binding remain independent")
    check(any(item["type"] == "IP_MAC_CONFLICT" for item in first["anomaly_evidence"]), "IP/MAC conflict produces evidence")
    check(any(item["type"] == "UNENROLLED_ACTIVE_DEVICE" for item in first["anomaly_evidence"]), "unseen active peer produces evidence only")
    second = inventory.collect()
    check(any(item["type"] == "GATEWAY_IDENTITY_CHANGED" for item in second["anomaly_evidence"]), "gateway MAC change produces segment-scoped evidence")
    check(all(item["authorization"] == "NOT_GRANTED" for item in second["anomaly_evidence"]), "anomaly evidence cannot authorize action")
    inventory.close()

    groups = dedupe_events([
        {"event_type": "HIGH_PROCESS_COUNT", "severity": "HIGH", "endpoint_id": "A", "source": "Detector", "value": 341, "message": "Processlar soni yuqori: 341", "timestamp": 1},
        {"event_type": "HIGH_PROCESS_COUNT", "severity": "HIGH", "endpoint_id": "A", "source": "Detector", "value": 341, "message": "Running processlar soni yuqori: 341", "timestamp": 2},
        {"event_type": "HIGH_PROCESS_COUNT", "severity": "HIGH", "endpoint_id": "B", "source": "Detector", "value": 341, "message": "same text", "timestamp": 3},
    ])
    check(len(groups) == 2 and sorted(group["count"] for group in groups) == [1, 2], "stable event grouping ignores wording and preserves endpoint separation")
    check(all("authorization" not in group and "authority" not in group for group in groups), "event grouping remains read-model only")
    lifecycle_groups = dedupe_events([
        {"event_type": "HIGH_MEMORY_USAGE", "severity": "HIGH", "endpoint_id": "A", "source": "SystemObserver", "value": 90, "message": "pressure", "timestamp": 10},
        {"event_type": "HIGH_MEMORY_USAGE_RECOVERED", "severity": "INFO", "endpoint_id": "A", "source": "EventState", "value": 0, "message": "recovered", "timestamp": 11},
    ])
    check(
        len(lifecycle_groups) == 1
        and lifecycle_groups[0]["event_code"] == "HIGH_MEMORY_USAGE"
        and lifecycle_groups[0]["current_state"] == "RECOVERED"
        and lifecycle_groups[0]["active_now"] is False
        and lifecycle_groups[0]["count"] == 2
        and set(lifecycle_groups[0]["sources"]) == {"SystemObserver", "EventState"},
        "event family identity is separate from lifecycle state",
    )

    engine = CorrelationEngine()
    active = engine.ingest({"event_type": "DETECTION", "event_id": "e1", "timestamp": 10, "data": {"type": "HIGH_MEMORY_USAGE", "severity": "HIGH", "source": "Detector", "value": 90, "message": "pressure"}}, strict=True)
    recovered = engine.ingest({"event_type": "DETECTION", "event_id": "e2", "timestamp": 11, "data": {"type": "HIGH_MEMORY_USAGE_RECOVERED", "severity": "INFO", "source": "EventState", "value": 0, "message": "recovered"}}, strict=True)
    check(active["active_now"] is True and recovered["active_now"] is False, "recovery clears current active state")
    check(recovered["event_count"] == 2 and recovered["recovered_at"] == 11, "recovery preserves forensic occurrence history")

    race = BoundedNetworkVerifier()
    check(race.health_check()["authorization"] == "NOT_GRANTED", "verification health has no authorization capability")

    if failures:
        print(f"RESULT: FAIL={len(failures)}")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
