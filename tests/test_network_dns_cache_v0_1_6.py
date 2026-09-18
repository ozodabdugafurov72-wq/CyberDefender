from __future__ import annotations

import inspect

from agent.network.dns_cache import WindowsDnsCacheReader
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


class FixtureProvider:
    def collect(self):
        return {
            "interfaces": [],
            "active_networks": [
                {
                    "InterfaceAlias": "Wi-Fi",
                    "InterfaceIndex": 9,
                    "IPv4Address": "10.0.0.10",
                    "PrefixLength": 24,
                    "Gateway": "10.0.0.1",
                }
            ],
            "neighbors": [
                {
                    "InterfaceAlias": "Wi-Fi",
                    "InterfaceIndex": 9,
                    "IPAddress": "10.0.0.1",
                    "LinkLayerAddress": "02-11-22-33-44-55",
                    "State": "Reachable",
                }
            ],
            "connections": [
                {
                    "local_ip": "10.0.0.10",
                    "local_port": 50123,
                    "remote_ip": "203.0.113.10",
                    "remote_port": 443,
                    "status": "ESTABLISHED",
                    "pid": 777,
                    "process": {
                        "attribution_status": "RESOLVED",
                        "pid": 777,
                        "technical_name": "fixture.exe",
                        "authority": "NONE",
                        "authorization": "NOT_GRANTED",
                    },
                },
                {
                    "local_ip": "10.0.0.10",
                    "local_port": 50124,
                    "remote_ip": "198.51.100.20",
                    "remote_port": 443,
                    "status": "ESTABLISHED",
                    "pid": 778,
                },
            ],
            "dns_cache": {
                "schema": "cyberdefender.dns-cache-observation.v0.1.6",
                "status": "HEALTHY",
                "available": True,
                "version": "0.1.6.1",
                "raw_rows_observed": 5,
                "entries_observed": 5,
                "unique_names": 5,
                "unique_ips": 2,
                "entries": [
                    {"name": "api.example.com", "ip_address": "203.0.113.10"},
                    {"name": "cdn.example.com", "ip_address": "203.0.113.10"},
                    {"name": "auth.example.com", "ip_address": "203.0.113.10"},
                    {"name": "fourth.example.com", "ip_address": "203.0.113.10"},
                    {"name": "fifth.example.com", "ip_address": "203.0.113.10"},
                    {"name": "not a valid domain", "ip_address": "203.0.113.10"},
                    {"name": "other.example.com", "ip_address": "192.0.2.55"},
                ],
            },
            "process_attribution": {"authority": "NONE"},
        }


def main() -> int:
    inventory = PassiveNetworkInventory(provider=FixtureProvider())
    snap = inventory.collect()

    check(snap["schema"] == "cyberdefender.network-inventory.v0.1.7", "v0.1.7 network schema is explicit")
    check(snap["dns_resolution"] is False, "active DNS resolution remains disabled")
    check(snap["dns_cache_observation"] is True, "passive DNS cache observation is explicit")
    check(snap["external_dns_queries"] is False, "DNS correlation performs no external query")
    check(snap["reverse_dns_lookup"] is False, "reverse DNS lookup remains disabled")

    first = snap["connections"][0]
    second = snap["connections"][1]
    names = first["dns"]["names"]
    check("api.example.com" in names, "cached DNS name correlates to matching remote IP")
    check(len(names) <= 4, "per-connection DNS names are bounded")
    check(first["dns"]["source"] == "WINDOWS_DNS_CACHE", "DNS evidence source is explicit")
    check(first["dns"]["passive"] is True, "DNS correlation is passive evidence")
    check(first["dns"]["authority"] == "NONE", "DNS evidence grants no authority")
    check(first["dns"]["authorization"] == "NOT_GRANTED", "DNS evidence cannot authorize actions")
    check(second["dns"]["names"] == [], "no DNS cache match is not fabricated")
    check(second["dns"]["source"] == "NO_MATCH", "no-match semantics are explicit")

    dns = snap["dns_cache"]
    check(dns["available"] is True, "DNS cache health is observable")
    check(dns["schema"] == "cyberdefender.dns-cache-runtime.v0.1.6.1", "DNS runtime hotfix schema is explicit")
    check(dns["reader_version"] == "0.1.6.1", "DNS reader hotfix version is visible")
    check(dns["raw_rows_observed"] == 5, "raw DNS cache row count is observable")
    check(dns["correlated_connections"] == 1, "correlated connection count is explicit")
    check(snap["summary"]["dns_correlated_connections"] == 1, "summary exposes DNS correlation count")

    source = inspect.getsource(WindowsDnsCacheReader)
    check("Get-DnsClientCache" in source, "Windows local DNS cache reader is explicit")
    check("Resolve-DnsName" not in source.split("script =", 1)[-1], "reader does not invoke active Resolve-DnsName")
    check("nslookup" not in source.lower().split("script =", 1)[-1], "reader does not invoke nslookup")

    health = inventory.health_check()
    check(health["authority"] == "NONE", "network health retains authority NONE")
    check(health["external_dns_queries"] is False, "health surface exposes external DNS queries disabled")

    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
