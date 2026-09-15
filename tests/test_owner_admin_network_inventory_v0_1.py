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
            "schema": "cyberdefender.network-inventory.v0.1",
            "version": "0.1",
            "mode": "PASSIVE_ONLY",
            "authority": "NONE",
            "authoritative": False,
            "active_scan_enabled": False,
            "packet_injection": False,
            "firewall_mutation": False,
            "user_identity_inference": False,
            "unknown_is_unauthorized": False,
            "sampled_at": time.time(),
            "summary": {
                "devices_total": 3,
                "online": 2,
                "connections_total": 5,
                "local": 1,
                "authorized": 1,
                "unknown": 1,
                "denied": 0,
                "revoked": 0,
            },
            "devices": [
                {"device_id":"mac:aa:bb:cc:dd:ee:01","ip_address":"192.168.1.20","mac_address":"AA:BB:CC:DD:EE:01","interface":"Wi-Fi","neighbor_state":"REACHABLE","online":True,"trust":"AUTHORIZED","label":"Managed laptop","user_identity":{"status":"UNKNOWN","user_id":None},"source":"NEIGHBOR_CACHE","passive":True},
                {"device_id":"mac:aa:bb:cc:dd:ee:02","ip_address":"192.168.1.30","mac_address":"AA:BB:CC:DD:EE:02","interface":"Wi-Fi","neighbor_state":"STALE","online":False,"trust":"UNKNOWN","label":None,"user_identity":{"status":"UNKNOWN","user_id":None},"source":"NEIGHBOR_CACHE","passive":True},
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
                "network_inventory": {"component":"PassiveNetworkInventory","status":"HEALTHY","version":"0.1","mode":"PASSIVE_ONLY","authority":"NONE","authoritative":False,"active_scan_enabled":False},
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
        check(admin["network_inventory"]["summary"]["devices_total"] == 3, "Admin state exposes bounded device summary")
        check(admin["network_inventory"]["active_scan_enabled"] is False, "Admin state cannot present active scan as enabled")
        check(admin["network_inventory"]["unknown_is_unauthorized"] is False, "Admin state preserves UNKNOWN != unauthorized")

        html = (server.ADMIN_STATIC / "index.html").read_text(encoding="utf-8")
        js = (server.ADMIN_STATIC / "admin.js").read_text(encoding="utf-8")
        check("NETWORK & DEVICES" in html and "Passive Network Inventory" in html, "Admin UI contains Network & Devices surface")
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
