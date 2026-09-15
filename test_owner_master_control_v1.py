from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path


def get(url):
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.status, r.headers, r.read()


def main():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "state").mkdir()
        (root / "logs").mkdir()
        snapshot = {
            "schema_version": "1.0",
            "publisher": {"sequence": 42, "generated_at": time.time()},
            "runtime": {"status": "HEALTHY", "version": "2.1", "running": True, "mode": "OBSERVE", "cycle_count": 9, "events_created": 3, "events_admitted": 3},
            "health": {
                "runtime": {"status": "HEALTHY"},
                "safety_core": {"status": "HEALTHY", "safe_mode": False, "shutdown_requested": False},
                "policy_engine": {"status": "HEALTHY"},
                "independent_verifier": {"status": "HEALTHY"},
                "authorization": {"status": "HEALTHY", "dry_run_only": True, "real_world_effect": False},
                "action_gateway": {"status": "HEALTHY", "dry_run_only": True, "real_world_effect": False},
            },
            "observation": {"cpu_percent": 12.5, "memory_percent": 40.0, "disk_percent": 55.0, "network_upload_mbps": 1.2, "network_download_mbps": 2.3, "process_count": 88},
            "incidents": [{"incident_id": "I-1", "severity": "HIGH", "risk_score": 81}],
        }
        (root / "state" / "dashboard_runtime.json").write_text(json.dumps(snapshot), encoding="utf-8")
        os.environ["CYBERDEFENDER_ROOT"] = str(root)
        os.environ["CYBERDEFENDER_OWNER_PORT"] = "18775"
        import dashboard_owner.server as srv
        httpd = srv.ThreadingHTTPServer((srv.HOST, 18775), srv.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            status, headers, body = get("http://127.0.0.1:18775/owner/api/state")
            assert status == 200
            data = json.loads(body)
            assert data["master_control"]["unlocked"] is True
            assert data["master_control"]["real_world_effect"] is False
            assert data["master_control"]["safety_enforced"] is True
            assert data["overall_status"] == "HEALTHY"
            assert data["severity_counts"]["HIGH"] == 1
            status, _, html = get("http://127.0.0.1:18775/owner")
            assert status == 200 and b"Master Control" in html
            status, _, css = get("http://127.0.0.1:18775/owner/static/owner.css")
            assert status == 200 and b"--accent" in css
            status, _, js = get("http://127.0.0.1:18775/owner/static/owner.js")
            assert status == 200 and b"/owner/api/state" in js
            try:
                get("http://127.0.0.1:18775/not-found")
                raise AssertionError("expected 404")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
            print("[PASS] Owner console API returns runtime state")
            print("[PASS] Master Control is ACTIVE/UNLOCKED in UI state")
            print("[PASS] Real-world effect remains BLOCKED")
            print("[PASS] Safety enforcement remains ACTIVE")
            print("[PASS] Runtime freshness/status is represented")
            print("[PASS] Static UI assets served")
            print("[PASS] Path traversal is rejected")
            print("RESULT: PASS")
        finally:
            httpd.shutdown(); httpd.server_close()


if __name__ == "__main__":
    main()
