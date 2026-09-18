from __future__ import annotations

import inspect

from agent.network.flow_telemetry import InterfaceFlowTracker
from agent.network.passive_inventory import PassiveNetworkInventory, WindowsPassiveNetworkProvider


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
    def __init__(self) -> None:
        self.round = 0

    def collect(self):
        self.round += 1
        if self.round == 1:
            wifi = {"interface": "Wi-Fi", "bytes_sent": 1000, "bytes_recv": 5000, "packets_sent": 10, "packets_recv": 50, "errin": 0, "errout": 0, "dropin": 0, "dropout": 0}
            eth = {"interface": "Ethernet", "bytes_sent": 9000, "bytes_recv": 12000, "packets_sent": 90, "packets_recv": 120, "errin": 0, "errout": 0, "dropin": 0, "dropout": 0}
        else:
            wifi = {"interface": "Wi-Fi", "bytes_sent": 3000, "bytes_recv": 11000, "packets_sent": 30, "packets_recv": 110, "errin": 0, "errout": 0, "dropin": 0, "dropout": 0}
            eth = {"interface": "Ethernet", "bytes_sent": 19000, "bytes_recv": 22000, "packets_sent": 190, "packets_recv": 220, "errin": 0, "errout": 0, "dropin": 0, "dropout": 0}
        return {
            "interfaces": [],
            "active_networks": [{"InterfaceAlias": "Wi-Fi", "InterfaceIndex": 9, "IPv4Address": "10.0.0.10", "PrefixLength": 24, "Gateway": "10.0.0.1"}],
            "neighbors": [],
            "connections": [{"local_ip": "10.0.0.10", "local_port": 50000, "remote_ip": "203.0.113.10", "remote_port": 443, "status": "ESTABLISHED", "pid": 777}],
            "dns_cache": {"status": "HEALTHY", "available": True, "entries": [], "entries_observed": 0, "unique_names": 0, "unique_ips": 0},
            "flow_counters": [wifi, eth],
            "process_attribution": {"authority": "NONE"},
        }


def main() -> int:
    flow_clock = iter([10.0, 12.0]).__next__
    tracker = InterfaceFlowTracker(clock=flow_clock)
    inventory = PassiveNetworkInventory(provider=FixtureProvider(), flow_tracker=tracker)

    first = inventory.collect()
    check(first["schema"] == "cyberdefender.network-inventory.v0.1.7", "v0.1.7 outer network schema is explicit")
    check(first["flow_telemetry_observation"] is True, "passive interface flow telemetry is explicit")
    check(first["packet_capture"] is False, "packet capture remains disabled")
    check(first["per_connection_byte_attribution"] is False, "per-connection byte attribution is explicitly unavailable")
    flow1 = first["flow_telemetry"]
    check(flow1["mode"] == "PASSIVE_INTERFACE_COUNTERS", "flow mode is passive interface counters")
    check(flow1["authority"] == "NONE" and flow1["authoritative"] is False, "flow evidence grants no authority")
    check(flow1["aggregate"]["active_interfaces"] == 1, "aggregate scope is limited to active default-route interface")
    check(flow1["aggregate"]["baseline_ready"] is False, "first sample is an explicit warm-up baseline")
    check(flow1["aggregate"]["rx_bytes_per_second"] == 0.0, "first sample fabricates no receive rate")
    check(flow1["aggregate"]["tx_bytes_per_second"] == 0.0, "first sample fabricates no transmit rate")

    second = inventory.collect()
    flow2 = second["flow_telemetry"]
    check(flow2["aggregate"]["baseline_ready"] is True, "second sample enables delta-rate baseline")
    check(flow2["aggregate"]["rx_bytes_per_second"] == 3000.0, "receive rate is derived from active-interface counter delta")
    check(flow2["aggregate"]["tx_bytes_per_second"] == 1000.0, "transmit rate is derived from active-interface counter delta")
    check(second["summary"]["flow_rx_bytes_per_second"] == 3000.0, "summary exposes passive receive rate")
    check(second["summary"]["flow_tx_bytes_per_second"] == 1000.0, "summary exposes passive transmit rate")
    check(second["summary"]["flow_active_interfaces"] == 1, "summary exposes active flow scope")
    check(second["count_semantics"]["flow_rates"] == "ACTIVE_INTERFACE_COUNTER_DELTAS_NOT_PER_CONNECTION_BYTES", "flow rate semantics reject per-connection interpretation")
    check(all("bytes_sent" not in row and "bytes_recv" not in row for row in second["connections"]), "connection rows do not fabricate byte attribution")

    reset_clock = iter([20.0, 22.0]).__next__
    reset = InterfaceFlowTracker(clock=reset_clock)
    reset.observe([{"interface": "Wi-Fi", "bytes_sent": 5000, "bytes_recv": 5000}], active_interfaces={"wi-fi"})
    reset_result = reset.observe([{"interface": "Wi-Fi", "bytes_sent": 100, "bytes_recv": 200}], active_interfaces={"wi-fi"})
    check(reset_result["interfaces"][0]["counter_reset"] is True, "counter rollback is detected as reset")
    check(reset_result["interfaces"][0]["baseline_ready"] is False, "counter reset cannot produce a rate")
    check(reset_result["interfaces"][0]["delta_bytes_recv"] == 0, "counter reset never creates negative or wrapped delta")

    source = inspect.getsource(WindowsPassiveNetworkProvider._flow_counters)
    check("net_io_counters" in source, "provider uses local OS interface counters")
    forbidden = ("sniff", "pcap", "WinDivert", "Resolve-DnsName", "Test-Connection", "Test-NetConnection", "socket.connect")
    check(not any(token in source for token in forbidden), "flow collector contains no capture/probe/active-network primitive")

    health = inventory.health_check()
    check(health["flow_telemetry_observation"] is True, "health exposes flow telemetry capability")
    check(health["packet_capture"] is False, "health exposes packet capture disabled")
    check(health["per_connection_byte_attribution"] is False, "health exposes no per-connection byte attribution")
    check(health["authority"] == "NONE", "network health authority remains NONE")

    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
