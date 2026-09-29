from __future__ import annotations

import json
import time
from pathlib import Path

from agent.network.active_verification import (
    BoundedNetworkVerifier,
    NetworkVerificationPolicy,
    NetworkVerificationPolicyError,
)
from agent.network.async_inventory import AsyncPassiveNetworkInventory
from agent.network.passive_inventory import PassiveNetworkInventory


failures: list[str] = []
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if condition:
        print(f"PASS | {message}")
    else:
        failures.append(message)
        print(f"FAIL | {message}")


def enabled_policy(**overrides):
    payload = {
        "schema": "cyberdefender.network-verification-policy.v0.1",
        "enabled": True,
        "operator_approved": True,
        "approval_ref": "LAB-OBS-001",
        "allowed_cidrs": ["192.168.1.0/24"],
        "dns_resolution": True,
        "active_probe": True,
        "probe_methods": ["ICMP"],
        "resolver_addresses": ["192.168.1.1"],
        "max_targets": 4,
        "max_dns_queries": 4,
        "max_probes": 4,
        "timeout_seconds": 0.5,
        "cooldown_seconds": 30.0,
    }
    payload.update(overrides)
    return NetworkVerificationPolicy.from_mapping(payload, admission_check=lambda _payload: True)


class FixtureProvider:
    def collect(self):
        return {
            "interfaces": [],
            "active_networks": [
                {
                    "InterfaceAlias": "Wi-Fi",
                    "InterfaceIndex": 7,
                    "IPv4Address": "192.168.1.10",
                    "PrefixLength": 24,
                    "Gateway": "192.168.1.1",
                }
            ],
            "neighbors": [
                {
                    "InterfaceAlias": "Wi-Fi",
                    "IPAddress": "192.168.1.20",
                    "LinkLayerAddress": "AA-BB-CC-DD-EE-20",
                    "State": "Reachable",
                },
                {
                    "InterfaceAlias": "Wi-Fi",
                    "IPAddress": "192.168.1.30",
                    "LinkLayerAddress": "AA-BB-CC-DD-EE-30",
                    "State": "Reachable",
                },
            ],
            "connections": [],
            "flow_counters": [],
        }


def main() -> int:
    disabled = BoundedNetworkVerifier()
    calls = {"dns": 0, "probe": 0}

    def forbidden_dns(*_args):
        calls["dns"] += 1
        return {"status": "RESOLVED", "hostname": "should-not-run.example"}

    def forbidden_probe(*_args):
        calls["probe"] += 1
        return {"status": "REACHABLE"}

    disabled.resolver = forbidden_dns
    disabled.prober = forbidden_probe
    report = disabled.verify([{"ip_address": "192.168.1.20", "trust": "UNKNOWN", "source": "NEIGHBOR_CACHE", "online": True}])
    check(report["status"] == "DISABLED", "verification is disabled by default")
    check(calls == {"dns": 0, "probe": 0}, "disabled policy performs no DNS or active probe")
    check(report["authority"] == "NONE" and report["authorization"] == "NOT_GRANTED", "disabled report grants no authority")

    try:
        NetworkVerificationPolicy.from_mapping({"schema": NetworkVerificationPolicy.SCHEMA, "enabled": True})
    except NetworkVerificationPolicyError as exc:
        check(str(exc) == "NETWORK_POLICY_CIDRS_REQUIRED", "enabled policy requires an allowlisted CIDR")
    else:
        check(False, "enabled policy rejects missing CIDRs")

    try:
        enabled_policy(allowed_cidrs=["0.0.0.0/0"])
    except NetworkVerificationPolicyError as exc:
        check(str(exc) == "NETWORK_POLICY_PUBLIC_NETWORK", "public scan scope is rejected")
    else:
        check(False, "public scan scope cannot be admitted")

    try:
        enabled_policy(operator_approved=False)
    except NetworkVerificationPolicyError as exc:
        check(str(exc) == "NETWORK_POLICY_OPERATOR_APPROVAL_REQUIRED", "operator approval is required")
    else:
        check(False, "missing operator approval cannot enable probes")

    try:
        NetworkVerificationPolicy.from_mapping({
            "schema": "cyberdefender.network-verification-policy.v0.1",
            "enabled": True,
            "operator_approved": True,
            "approval_ref": "LAB-OBS-001",
            "allowed_cidrs": ["192.168.1.0/24"],
            "dns_resolution": False,
            "active_probe": True,
            "probe_methods": ["ICMP"],
        })
    except NetworkVerificationPolicyError as exc:
        check(str(exc) == "NETWORK_POLICY_ADMISSION_REQUIRED", "raw policy cannot bypass admission")
    else:
        check(False, "raw policy without admission is rejected")

    dns_calls: list[tuple[str, float, tuple[str, ...]]] = []
    probe_calls: list[tuple[str, str, float]] = []

    def resolver(ip, timeout, servers):
        dns_calls.append((ip, timeout, servers))
        return {"status": "RESOLVED", "hostname": "jdu4-lab.example"}

    def prober(ip, method, timeout):
        probe_calls.append((ip, method, timeout))
        return {"status": "REACHABLE"}

    verifier = BoundedNetworkVerifier(enabled_policy(), resolver=resolver, prober=prober, clock=lambda: 100.0)
    first = verifier.verify([
        {"device_id": "mac:aa", "ip_address": "192.168.1.20", "trust": "UNKNOWN", "source": "NEIGHBOR_CACHE", "online": True},
        {"device_id": "mac:bb", "ip_address": "192.168.1.30", "trust": "DENIED", "source": "NEIGHBOR_CACHE", "online": True},
        {"device_id": "mac:outside", "ip_address": "10.0.0.20", "trust": "UNKNOWN", "source": "NEIGHBOR_CACHE", "online": True},
    ])
    by_ip = {row["ip_address"]: row for row in first["results"]}
    check(first["active_scan_enabled"] and first["dns_resolution"], "approved policy enables bounded DNS and active verification")
    check(len(dns_calls) == 2 and len(probe_calls) == 2, "only allowlisted targets are queried and probed")
    check(by_ip["192.168.1.20"]["observed_name"] == "jdu4-lab.example", "resolved device name is retained as observation")
    check(by_ip["192.168.1.20"]["classification"] == "OBSERVED_UNVERIFIED", "UNKNOWN remains unverified after active evidence")
    check(by_ip["192.168.1.30"]["verification_state"] == "SUSPICIOUS_UNAUTHORIZED", "explicitly denied device is surfaced as suspicious")
    check(by_ip["10.0.0.20"]["verification_state"] == "REVIEW_REQUIRED", "out-of-scope target fails closed")
    untrusted = verifier.verify([{"ip_address": "192.168.1.21", "trust": "UNKNOWN"}])
    check(untrusted["results"][0]["admission_reason"] == "OBSERVATION_NOT_ADMITTED", "untrusted input cannot bypass target admission")
    check(all(row["authority"] == "NONE" and row["authorization"] == "NOT_GRANTED" for row in first["results"]), "verification evidence never grants authority")
    check(first["bounds"]["max_targets"] == 4 and first["bounds"]["max_probes"] == 4, "verification bounds are published")

    bounded = BoundedNetworkVerifier(enabled_policy(max_targets=2), resolver=resolver, prober=prober, clock=lambda: 500.0)
    bounded_result = bounded.verify(
        ({"ip_address": f"192.168.1.{20 + index}", "trust": "UNKNOWN", "source": "NEIGHBOR_CACHE", "online": True} for index in range(100))
    )
    check(len(bounded_result["results"]) <= 2 and bounded_result["targets_examined"] <= 2, "target iteration is bounded before network work")

    dns_before_cooldown = len(dns_calls)
    probe_before_cooldown = len(probe_calls)
    second = verifier.verify([{"ip_address": "192.168.1.20", "trust": "UNKNOWN", "source": "NEIGHBOR_CACHE", "online": True}])
    check(len(dns_calls) == dns_before_cooldown and len(probe_calls) == probe_before_cooldown, "cooldown prevents duplicate active work")
    check(second["results"][0]["verification_state"] == "COOLDOWN", "cooldown state is explicit")

    now = [131.0]
    verifier.clock = lambda: now[0]
    third = verifier.verify([{"ip_address": "192.168.1.20", "trust": "UNKNOWN", "source": "NEIGHBOR_CACHE", "online": True}])
    check(third["results"][0]["verification_state"] == "OBSERVED", "verification resumes after bounded cooldown")

    now[0] = 162.0
    inventory = PassiveNetworkInventory(provider=FixtureProvider(), verifier=verifier)
    snapshot = inventory.collect()
    inventory.close()
    devices = {row["ip_address"]: row for row in snapshot["devices"]}
    check(snapshot["mode"] == "PASSIVE_PLUS_BOUNDED_VERIFICATION", "inventory advertises optional verification mode")
    check(devices["192.168.1.20"]["observed_name"] == "jdu4-lab.example", "inventory exposes observed DNS name")
    check(devices["192.168.1.20"]["trust"] == "UNKNOWN", "active evidence cannot promote trust")
    check(snapshot["authority"] == "NONE" and snapshot["unknown_is_unauthorized"] is False, "inventory remains non-authoritative")

    async_verifier = BoundedNetworkVerifier(enabled_policy(), resolver=resolver, prober=prober, clock=lambda: 1000.0)
    async_collector = PassiveNetworkInventory(provider=FixtureProvider(), verifier=async_verifier)
    worker = AsyncPassiveNetworkInventory(async_collector, deadline_seconds=1.0)
    try:
        worker.request_sample()
        deadline = time.monotonic() + 2.0
        while worker.integration_state()["completed"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        async_health = worker.health_check()
        check(async_health["active_scan_enabled"] is True and async_health["dns_resolution"] is True, "async wrapper propagates approved verification capability")
    finally:
        worker.close()

    serialized = json.dumps(first, sort_keys=True)
    check("LAB-OBS-001" not in serialized, "approval reference is not exported in evidence")
    check("password" not in serialized.lower() and "secret" not in serialized.lower(), "verification evidence contains no secrets")

    source = (Path(__file__).parents[1] / "agent" / "network" / "active_verification.py").read_text(encoding="utf-8")
    check("firewall" in source and "NOT_GRANTED" in source, "source preserves no-firewall and no-authority boundaries")
    check("socket.connect" not in source and "nmap" not in source, "verifier contains no arbitrary socket or port scanner")

    if failures:
        print(f"RESULT: FAIL={len(failures)} ASSERTIONS={checks}")
        return 1
    print(f"RESULT: PASS ASSERTIONS={checks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
