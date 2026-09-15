from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.data.sqlite_repository import SQLiteDataRepository
from dashboard_owner import server


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def get_json(base: str, path: str) -> dict:
    with urlopen(base + path, timeout=3.0) as response:
        check(response.headers.get("X-Frame-Options") == "DENY", f"Security headers present on {path}")
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    old_state, old_log, old_db = server.STATE_FILE, server.LOG_FILE, server.DATA_DB_FILE
    with tempfile.TemporaryDirectory(prefix="cd_p08_api_") as td:
        root = Path(td)
        state_dir = root / "state"
        log_dir = root / "logs"
        data_dir = state_dir / "data"
        state_dir.mkdir(parents=True)
        log_dir.mkdir(parents=True)
        data_dir.mkdir(parents=True)

        db = data_dir / "cyberdefender.db"
        repo = SQLiteDataRepository(db)
        try:
            repo.sync_cycle(
                endpoint={
                    "endpoint_id": "endpoint-api",
                    "hostname": "api-host",
                    "scope": "LOCAL_ENDPOINT",
                    "runtime_version": "2.4",
                    "mode": "OBSERVE",
                    "runtime_status": "HEALTHY",
                    "resource_state": "NORMAL",
                    "cpu_percent": 5.0,
                    "memory_percent": 55.0,
                    "available_memory_mb": 5000,
                    "process_count": 180,
                    "last_cycle": 3,
                },
                incidents=[{
                    "incident_id": "INC-API-001",
                    "correlation_key": "agent-local:DemoSecurity",
                    "severity": "HIGH",
                    "risk_score": 75,
                    "event_count": 1,
                    "created_at": 1000.0,
                    "updated_at": 1000.0,
                    "detections": [{"type": "PROCESS_CHAIN_ANOMALY", "severity": "HIGH", "source": "RuleEngine", "timestamp": 1000.0, "message": "demo"}],
                }],
                risk={"overall_risk_level": "HIGH", "overall_risk_score": 75},
                policy={"outcome": "OBSERVE_ONLY", "recommendation": "OBSERVE", "authorization": "NOT_GRANTED"},
                verification={"outcome": "VERIFIED", "verified": True, "authorization": "NOT_GRANTED"},
            )
        finally:
            repo.close()

        snapshot = {
            "publisher": {"sequence": 1, "generated_at": time.time()},
            "runtime": {"running": True, "status": "HEALTHY", "cycle_count": 3, "component_failures": 0},
            "health": {
                "runtime": {"status": "HEALTHY"},
                "safety_core": {"status": "SAFE", "safe_mode": False},
                "resource_guard": {"status": "HEALTHY", "state": "NORMAL"},
                "policy_engine": {"status": "HEALTHY"},
                "independent_verifier": {"status": "HEALTHY"},
                "authorization_gate": {"status": "HEALTHY", "dry_run_only": True},
                "action_gateway": {"status": "HEALTHY", "real_world_effect": False},
                "data_repository": {"status": "HEALTHY", "version": "1.1", "schema_version": 1, "authoritative": False},
            },
            "observation": {"cpu_percent": 5.0, "memory_percent": 55.0, "memory_available_mb": 5000, "process_count": 180},
            "incidents": [],
        }
        (state_dir / "dashboard_runtime.json").write_text(json.dumps(snapshot), encoding="utf-8")
        (log_dir / "events.jsonl").write_text("", encoding="utf-8")

        server.STATE_FILE = state_dir / "dashboard_runtime.json"
        server.LOG_FILE = log_dir / "events.jsonl"
        server.DATA_DB_FILE = db

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            state = get_json(base, "/owner/api/state")
            check(state["schema"] == "cyberdefender.owner-master-control.v3.5", "Owner state API exposes P0.8 schema v3.5")
            check(state["demo_operations"]["synthetic_only"] is True, "State API advertises synthetic-only demo operations")
            check(state["data_store"]["owner_read_model"]["read_only"] is True, "State API exposes read-only SQL query posture")

            listing = get_json(base, "/owner/api/incidents?severity=HIGH&class=SECURITY&q=DemoSecurity")
            check(listing["count"] == 1 and listing["incidents"][0]["incident_id"] == "INC-API-001", "Incident search/filter API queries SQLite history")

            detail = get_json(base, "/owner/api/incidents/" + quote("INC-API-001"))
            check(len(detail["incident"]["evidence_timeline"]) == 1, "Incident API returns evidence timeline")

            endpoint = get_json(base, "/owner/api/endpoint")
            check(endpoint["endpoint"]["hostname"] == "api-host", "Endpoint API returns structured endpoint details")
            check(endpoint["endpoint"]["recent_decisions"][0]["verification_authorization"] == "NOT_GRANTED", "Endpoint decision history preserves authorization boundary")

            demo = get_json(base, "/owner/api/demo/critical-threat")
            check(demo["synthetic"] is True and demo["real_world_effect"] is False, "Critical-threat API is synthetic and non-mutating")
            check(demo["policy"]["authorization"] == "NOT_GRANTED", "Critical-threat API never grants policy authorization")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2.0)
            server.STATE_FILE, server.LOG_FILE, server.DATA_DB_FILE = old_state, old_log, old_db

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
