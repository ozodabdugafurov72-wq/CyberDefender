from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
from urllib.request import urlopen

from dashboard_owner import server


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_admin_network_") as td:
        root = Path(td)
        (root / "state").mkdir()
        (root / "logs").mkdir()

        network = {
            "schema": "cyberdefender.network-inventory.v0.1.2",
            "version": "0.1.2",
            "mode": "PASSIVE_ONLY",
            "authority": "NONE",
            "authoritative": False,
            "active_scan_enabled": False,
            "packet_injection": False,
            "firewall_mutation": False,
            "user_identity_inference": False,
            "unknown_is_unauthorized": False,
            "hotspot_client_count": None,
            "hotspot_client_count_authoritative": False,
            "hotspot_client_count_reason": "AP_CONTROLLER_EVIDENCE_UNAVAILABLE",
            "sampled_at": time.time(),
            "summary": {
                "local_endpoint_count": 1,
                "observed_peers_total": 2,
                "observed_peers_online": 1,
                "gateways_observed": 1,
                "other_peers_observed": 0,
                "devices_total": 2,
                "online": 1,
                "connections_total": 5,
                "authorized": 1,
                "unknown": 0,
                "denied": 0,
                "revoked": 0,
            },
            "count_semantics": {
                "devices_total": "OBSERVED_NEIGHBOR_IDENTITIES_NOT_CONNECTED_CLIENTS",
                "hotspot_client_count": "UNAVAILABLE_WITHOUT_AP_CONTROLLER_EVIDENCE",
            },
            "active_networks": [{"interface":"Wi-Fi","interface_index":9,"local_ipv4":"10.28.239.128","prefix_length":24,"gateway":"10.28.239.252","role":"DEFAULT_ROUTE"}],
            "devices": [
                {"device_id":"mac:06:94:e9:22:9f:21","ip_address":"10.28.239.252","mac_address":"06:94:E9:22:9F:21","interface":"Wi-Fi","neighbor_state":"REACHABLE","online":True,"trust":"AUTHORIZED","label":"Phone hotspot gateway","user_identity":{"status":"UNKNOWN","user_id":None},"role":"GATEWAY","source":"NEIGHBOR_CACHE","passive":True},
                {"device_id":"mac:aa:bb:cc:dd:ee:02","ip_address":"192.168.1.30","mac_address":"AA:BB:CC:DD:EE:02","interface":"Wi-Fi","neighbor_state":"STALE","online":False,"trust":"UNKNOWN","label":None,"user_identity":{"status":"UNKNOWN","user_id":None},"role":"PEER","source":"NEIGHBOR_CACHE","passive":True},
            ],
            "connections": [],
        }

        snapshot = {
            "publisher": {"component":"RuntimeStatePublisher","sequence":7,"generated_at":time.time()},
            "runtime": {
                "running": True,
                "status": "HEALTHY",
                "cycle_count": 7,
                "component_failures": 0,
                "network_inventory": network,
            },
            "health": {
                "runtime": {"status":"HEALTHY"},
                "safety_core": {"status":"SAFE"},
                "resource_guard": {"status":"HEALTHY","state":"NORMAL"},
                "network_inventory": {"component":"PassiveNetworkInventory","status":"HEALTHY","version":"0.1.2","mode":"PASSIVE_ONLY","authority":"NONE","authoritative":False,"active_scan_enabled":False,"hotspot_client_count_authoritative":False},
                "policy_engine": {"status":"HEALTHY"},
                "independent_verifier": {"status":"HEALTHY"},
                "authorization_gate": {"status":"HEALTHY","dry_run_only":True},
                "action_gateway": {"status":"HEALTHY","real_world_effect":False},
            },
            "observation": {"cpu_percent":5.0,"memory_percent":50.0,"process_count":200},
            "incidents": [],
        }

        state_file = root / "state" / "dashboard_runtime.json"
        state_file.write_text(json.dumps(snapshot), encoding="utf-8")
        server.STATE_FILE = state_file
        server.LOG_FILE = root / "logs" / "events.jsonl"
        server.DATA_DB_FILE = root / "state" / "data.db"
        server.DISTRIBUTION_DB_FILE = root / "state" / "distribution.db"

        owner = server.build_state()
        check(owner["network_inventory"]["mode"] == "PASSIVE_ONLY", "Owner read model carries runtime-owned passive network inventory")

        admin = server.build_admin_state()
        check(admin["read_only"] is True and admin["authoritative"] is False, "Admin surface remains read-only and non-authoritative")
        check(admin["network_inventory"]["summary"]["observed_peers_online"] == 1, "Admin state exposes current observed-peer summary")
        check(admin["network_inventory"]["summary"]["local_endpoint_count"] == 1, "Admin state separates local endpoint from peers")
        check(admin["network_inventory"]["hotspot_client_count"] is None, "Admin state does not fabricate hotspot client count")
        check(admin["network_inventory"]["active_scan_enabled"] is False, "Admin state cannot present active scan as enabled")
        check(admin["network_inventory"]["unknown_is_unauthorized"] is False, "Admin state preserves UNKNOWN != unauthorized")

        html = (server.ADMIN_STATIC / "index.html").read_text(encoding="utf-8")
        js = (server.ADMIN_STATIC / "admin.js").read_text(encoding="utf-8")
        check("NETWORK & DEVICES" in html and "Passive Network Observations" in html, "Admin UI contains Network & Devices surface")
        check("HOTSPOT CLIENTS" in html and "OBSERVED PEERS" in html, "Admin UI separates AP client count from neighbor evidence")
        check("NO PING" in html and "NO PORT SCAN" in html and "UNKNOWN ≠ UNAUTHORIZED" in html, "Admin UI declares passive-only safety boundaries")
        check("d.network_inventory" in js and "networkDevices" in js, "Admin JS consumes only API network inventory state")
        check("Get-NetNeighbor" not in js and "fetch(\"/admin/api/state\"" in js, "Admin browser code has no direct OS telemetry path")

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            with urlopen(f"http://127.0.0.1:{port}/admin/api/state", timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8"))
                check(response.status == 200, "/admin/api/state remains available")
                check(payload["network_inventory"]["summary"]["authorized"] == 1, "Admin API returns passive device trust telemetry")
                check(payload["network_inventory"]["authority"] == "NONE", "Network inventory API grants no authority")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=3)

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
