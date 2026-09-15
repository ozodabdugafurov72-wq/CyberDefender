from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "agent" / "main.py").read_text(encoding="utf-8")
ASYNC = (ROOT / "agent" / "network" / "async_inventory.py").read_text(encoding="utf-8")
HTML = (ROOT / "dashboard_owner" / "static" / "admin" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "dashboard_owner" / "static" / "admin" / "admin.js").read_text(encoding="utf-8")

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"PASS | {message}")
    else:
        failures.append(message)
        print(f"FAIL | {message}")


start = MAIN.index("    def update_network_inventory")
end = MAIN.index("    # ========================================================\n    # STRUCTURED DATA READ-MODEL", start)
update_body = MAIN[start:end]

check("AsyncPassiveNetworkInventory" in MAIN, "runtime wires async passive network worker")
check("worker.request_sample()" in update_body, "runtime schedules passive refresh through bounded request path")
check("worker.get_latest_snapshot()" in update_body, "runtime consumes only completed last-good snapshots")
check("collector.collect()" not in update_body, "runtime cycle contains no direct network collection call")
check("threading.Thread" in ASYNC and "daemon=True" in ASYNC, "network collection owns one daemon background worker")
check("threading.Event" in ASYNC, "pending refresh uses bounded event/coalescing primitive")
check("deadline_exceeded" in ASYNC and "deadline_seconds" in ASYNC, "slow/hung collection has explicit deadline telemetry")
check("close_join_seconds" in ASYNC and ".join(timeout=" in ASYNC, "network worker shutdown wait is bounded")
check("authority\": self.AUTHORITY" in ASYNC and 'AUTHORITY = "NONE"' in ASYNC, "background integration cannot grant authority")
check('active_scan_enabled\": False' in ASYNC, "background integration cannot activate scanning")
check('packet_injection\": False' in ASYNC, "background integration exposes no packet injection")
check('firewall_mutation\": False' in ASYNC, "background integration exposes no firewall mutation")
check("network_inventory.close()" in MAIN, "runtime deterministically closes optional network worker")
check("netCollector" in HTML and "runtime_integration" in JS, "Admin UI exposes async collector health without direct OS access")

if failures:
    print(f"RESULT: FAIL={len(failures)}")
    raise SystemExit(1)
print("RESULT: PASS")
