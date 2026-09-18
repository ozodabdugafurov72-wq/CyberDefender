from __future__ import annotations

from pathlib import Path

from agent.network.passive_inventory import PassiveNetworkInventory


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


class FixtureProvider:
    def __init__(self) -> None:
        self.round = 0

    def collect(self):
        self.round += 1
        interfaces = [
            {
                "name": "Wi-Fi",
                "is_up": True,
                "speed_mbps": 1200,
                "addresses": [
                    {"family": "AF_INET", "address": "192.168.1.10"},
                    {"family": "AF_INET6", "address": "fe80::10%7"},
                ],
            }
        ]
        active_networks = [
            {
                "InterfaceAlias": "Wi-Fi",
                "InterfaceIndex": 7,
                "IPv4Address": "192.168.1.10",
                "PrefixLength": 24,
                "Gateway": "192.168.1.1",
            }
        ]
        if self.round == 1:
            neighbors = [
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.1", "LinkLayerAddress": "AA-BB-CC-DD-EE-01", "State": "Reachable"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.20", "LinkLayerAddress": "AA-BB-CC-DD-EE-20", "State": "Reachable"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.30", "LinkLayerAddress": "AA-BB-CC-DD-EE-30", "State": "Stale"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.40", "LinkLayerAddress": "AA-BB-CC-DD-EE-40", "State": "Reachable"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "224.0.0.1", "LinkLayerAddress": "01-00-5E-00-00-01", "State": "Permanent"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.255", "LinkLayerAddress": "FF-FF-FF-FF-FF-FF", "State": "Permanent"},
                {"InterfaceAlias": "Ethernet", "IPAddress": "10.10.10.1", "LinkLayerAddress": "AA-BB-CC-DD-EE-55", "State": "Reachable"},
            ]
        else:
            neighbors = [
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.1", "LinkLayerAddress": "AA-BB-CC-DD-EE-01", "State": "Reachable"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.20", "LinkLayerAddress": "AA-BB-CC-DD-EE-20", "State": "Reachable"},
                {"InterfaceAlias": "Wi-Fi", "IPAddress": "255.255.255.255", "LinkLayerAddress": "FF-FF-FF-FF-FF-FF", "State": "Permanent"},
            ]
        connections = [
            {"local_ip": "192.168.1.10", "local_port": 54000, "remote_ip": "192.168.1.20", "remote_port": 443, "status": "ESTABLISHED", "pid": 123},
            {"local_ip": "192.168.1.10", "local_port": 54001, "remote_ip": "8.8.8.8", "remote_port": 443, "status": "ESTABLISHED", "pid": 124},
        ]
        return {"interfaces": interfaces, "active_networks": active_networks, "neighbors": neighbors, "connections": connections}


def main() -> int:
    clock = iter([1000.0, 1010.0]).__next__
    provider = FixtureProvider()
    inventory = PassiveNetworkInventory(
        provider=provider,
        trust_registry={
            "mac:aa:bb:cc:dd:ee:20": {"status": "AUTHORIZED", "label": "Managed laptop"},
            "mac:aa:bb:cc:dd:ee:30": {"status": "DENIED", "label": "Blocked lab device"},
            "mac:aa:bb:cc:dd:ee:40": {
                "status": "AUTHORIZED",
                "label": "Managed phone",
                "user_id": "claimed-user",
                "user_verified": False,
            },
        },
        max_devices=16,
        max_connections=16,
        clock=clock,
    )

    first = inventory.collect()
    check(first["mode"] == "PASSIVE_ONLY", "network inventory is passive-only")
    check(first["authority"] == "NONE" and first["authoritative"] is False, "network inventory is non-authoritative")
    check(first["active_scan_enabled"] is False, "active scanning remains disabled")
    check(first["packet_injection"] is False and first["firewall_mutation"] is False, "no packet injection or firewall mutation is exposed")
    check(first["unknown_is_unauthorized"] is False, "UNKNOWN is not silently treated as unauthorized")
    check(first["user_identity_inference"] is False, "user identity inference from network identity is disabled")
    check(first["schema"] == "cyberdefender.network-inventory.v0.1.7", "v0.1.7 schema is explicit")
    check(first["summary"]["local_endpoint_count"] == 1, "local endpoint is counted separately from neighbors")
    check(first["summary"]["observed_peers_online"] == 4, "only active-scope unicast neighbor identities are current peers")
    check(first["summary"]["gateways_observed"] == 1, "default gateway is classified separately")
    check(first["summary"]["other_peers_observed"] == 3, "non-gateway peers remain visible")
    check(first["hotspot_client_count"] is None and first["hotspot_client_count_authoritative"] is False, "hotspot client count is unavailable without AP evidence")
    check(first["summary"]["authorized"] == 2, "explicit authorized peer rules are applied")
    check(first["summary"]["denied"] == 1, "explicit denied peer rule is applied")
    check(first["summary"]["connections_total"] == 2, "passive local connection evidence is retained")
    check(all(isinstance(row.get("process"), dict) for row in first["connections"]), "connection schema reserves bounded process attribution evidence")
    check(all(row["process"].get("authority") == "NONE" for row in first["connections"]), "process attribution grants no authority")

    by_ip = {row["ip_address"]: row for row in first["devices"]}
    check("192.168.1.255" not in by_ip and "224.0.0.1" not in by_ip and "10.10.10.1" not in by_ip, "broadcast, multicast, and inactive-interface rows are not peers")
    check(by_ip["192.168.1.1"]["role"] == "GATEWAY", "gateway role is visible")
    check(by_ip["192.168.1.20"]["trust"] == "AUTHORIZED", "authorized device is visible")
    check(by_ip["192.168.1.30"]["trust"] == "DENIED", "denied device is visible")
    check(by_ip["192.168.1.40"]["user_identity"]["status"] == "UNKNOWN", "unverified user claim is not promoted")
    check(by_ip["192.168.1.40"]["user_identity"]["user_id"] is None, "unverified user identifier is redacted from identity binding")
    check(all(row.get("passive") is True for row in first["devices"]), "all device evidence is explicitly passive")
    check(all(row.get("passive") is True for row in first["connections"]), "all connection evidence is explicitly passive")
    check(first["count_semantics"]["devices_total"] == "OBSERVED_NEIGHBOR_IDENTITIES_NOT_CONNECTED_CLIENTS", "neighbor count cannot be presented as connected-client count")

    second = inventory.collect()
    by_ip2 = {row["ip_address"]: row for row in second["devices"]}
    check(by_ip2["192.168.1.30"]["online"] is False and by_ip2["192.168.1.30"]["neighbor_state"] == "STALE", "missing prior device becomes stale instead of being silently erased")
    check(by_ip2["192.168.1.20"]["first_seen"] == 1000.0 and by_ip2["192.168.1.20"]["last_seen"] == 1010.0, "first/last seen continuity is preserved in memory")
    check(second["bounds"]["max_devices"] == 16 and second["bounds"]["max_connections"] == 16, "inventory bounds are explicit")

    health = inventory.health_check()
    check(health["status"] == "HEALTHY", "passive inventory health remains healthy after valid samples")
    check(health["dashboard_direct_os_access"] is False, "dashboard direct OS access invariant is explicit")
    check(health["active_scan_enabled"] is False, "health surface exposes active scan disabled")

    source = (Path(__file__).parents[1] / "agent" / "network" / "passive_inventory.py").read_text(encoding="utf-8")
    forbidden = ("Test-Connection", "Test-NetConnection", "ping.exe", "nmap", "SendARP", "socket.connect")
    check(not any(token in source for token in forbidden), "collector source contains no active-probe primitives")
    check("Get-NetNeighbor" in source, "Windows neighbor-cache observation is explicit")

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
