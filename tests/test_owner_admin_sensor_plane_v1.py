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
    with tempfile.TemporaryDirectory(prefix="cd_owner_admin_") as td:
        root = Path(td)
        (root / "state").mkdir(); (root / "logs").mkdir()
        snapshot = {
            "publisher": {"component":"RuntimeStatePublisher","sequence":42,"generated_at":time.time()},
            "runtime": {"running":True,"status":"HEALTHY","cycle_count":42,"component_failures":0,
                        "process_sensor_mode":"RUST_CANARY","rust_process_canary_enabled":True,
                        "rust_process_canary_failures":0,"rust_process_shadow_enabled":False},
            "health": {
                "runtime":{"status":"HEALTHY"}, "safety_core":{"status":"SAFE"},
                "resource_guard":{"status":"HEALTHY","state":"NORMAL"},
                "process_sensor":{"sensor":"ProcessSensor","status":"HEALTHY","version":"1.0"},
                "process_graph":{"component":"ProcessGraph","status":"HEALTHY","version":"1.6"},
                "process_sensor_authority":{"component":"ProcessSensorAuthorityController","status":"HEALTHY",
                    "mode":"RUST_CANARY","authoritative_sensor":"ProcessSensor","compiled_primary_enabled":False},
                "rust_process_shadow":{"component":"RustProcessShadowProbe","status":"DISABLED","mode":"SHADOW_ONLY"},
                "rust_process_canary":{"component":"RustProcessCanary","status":"HEALTHY","sensor_version":"0.5.1",
                    "mode":"RUST_CANARY","authoritative":False,"authoritative_sensor":"ProcessSensor",
                    "promotion_bound":False,"binary_trusted":True,"sample_count":7,"success_count":7,"failure_count":0,
                    "last_sample_age_seconds":1.5,"last_sample_latency_ms":12.3,"candidate_ready":True,
                    "readiness_reason":"CANARY_PARITY_GATE_PASS",
                    "supervisor":{"protocol":"cd.sensor.ipc.v1","status":"HEALTHY","generation":2,"sequence":9,
                        "sensor_epoch":"epoch-2","sensor_pid":1234,"child_alive":True,"launch_binding_verified":True,
                        "direct_pid_verified":True,"restart_count":1,"failures":1,"last_error":None},
                    "comparison":{"verdict":"ENRICHMENT_ALIGNED_WITH_COVERAGE_GAPS","common_processes":250,
                        "identity_disagreements":{"count":0},"parent_disagreements":{"count":0},
                        "canonical_name_conflicts":{"count":0},"known_system_name_aliases":{"count":2},
                        "fields":{
                            "exe":{"matches":246,"mismatches":0,"missing":0,"coverage_rate":1.0,"parity_rate":1.0},
                            "username":{"matches":249,"exact_matches":248,"sid_backed_display_variants":1,"mismatches":0,"missing":1,"coverage_rate":0.996,"parity_rate":1.0,
                                "display_variant_examples":[{"pid":4,"python_username":"NT AUTHORITY\\SYSTEM","rust_username":"NT AUTHORITY\\LOCALIZED-SYSTEM","rust_sid":"S-1-5-18","classification":"SID_BACKED_USERNAME_DISPLAY_VARIANT"}]},
                            "cmdline":{"matches":245,"mismatches":0,"missing":1,"coverage_rate":0.996,"parity_rate":1.0}}},
                    "snapshot_summary":{"process_count":251,"partial":True,"skipped":1,"coverage_safe":True,
                        "extra_enrichment":{"sid":{"collected":249,"total":251,"coverage_rate":0.992032},
                            "session_id":{"collected":251,"total":251,"coverage_rate":1.0},
                            "integrity_level":{"collected":249,"total":251,"coverage_rate":0.992032}}}},
                "risk_engine":{"status":"HEALTHY"},"policy_engine":{"status":"HEALTHY"},
                "independent_verifier":{"status":"HEALTHY"},
                "authorization_gate":{"status":"HEALTHY","dry_run_only":True},
                "action_gateway":{"status":"HEALTHY","real_world_effect":False},
            },
            "observation":{"cpu_percent":5.0,"memory_percent":50.0,"process_count":251},
            "incidents":[],
        }
        state_file = root / "state" / "dashboard_runtime.json"
        state_file.write_text(json.dumps(snapshot), encoding="utf-8")
        server.STATE_FILE = state_file
        server.LOG_FILE = root / "logs" / "events.jsonl"
        server.DATA_DB_FILE = root / "state" / "data.db"
        server.DISTRIBUTION_DB_FILE = root / "state" / "distribution.db"

        owner = server.build_state(); sp = owner["sensor_plane"]
        check(owner["ui_revision"] == "owner-v3.6-sensor-plane", "Owner dashboard exposes v3.6 sensor-plane revision")
        check(sp["mode"] == "RUST_CANARY", "Owner state exposes RUST_CANARY mode")
        check(sp["authoritative_sensor"] == "ProcessSensor", "Owner state preserves Python source of truth")
        check(sp["primary_lock"] == "CLOSED", "Owner state exposes closed Rust primary lock")
        check(sp["canary"]["status"] == "HEALTHY" and sp["canary"]["candidate_ready"], "Owner state exposes healthy canary readiness")
        check(sp["ipc"]["launch_binding_verified"] and sp["ipc"]["direct_pid_verified"], "Owner state exposes IPC trust bindings")
        check(sp["parity"]["identity_disagreements"] == 0 and sp["parity"]["exe"]["mismatches"] == 0, "Owner state exposes zero critical parity disagreement")
        check(sp["parity"]["username"]["sid_backed_display_variants"] == 1, "Owner state exposes SID-backed username display variants")
        check(sp["parity"]["username"]["mismatches"] == 0, "SID-backed username display variant is not presented as a hard mismatch")
        check(sp["invariants"]["rust_enters_process_graph"] is False, "Owner state exposes no Rust graph edge")
        check(sp["invariants"]["rust_grants_authorization"] is False, "Owner state exposes no Rust authorization edge")

        admin = server.build_admin_state()
        check(admin["schema"] == "cyberdefender.admin-operations.v1", "Admin technical state schema is stable")
        check(admin["read_only"] is True and admin["authoritative"] is False, "Admin surface is explicitly read-only/non-authoritative")
        check(admin["sensor_plane"]["canary"]["authoritative"] is False, "Admin cannot present canary as authority")

        admin_html = (server.ADMIN_STATIC / "index.html").read_text(encoding="utf-8")
        owner_html = (server.STATIC / "index.html").read_text(encoding="utf-8")
        check("ADMIN OPERATIONS · READ ONLY" in admin_html, "Admin UI visibly declares read-only semantics")
        check("no operating-system action path" in admin_html, "Admin UI declares no OS action path")
        check('id="sensor-plane"' in owner_html and 'href="/admin"' in owner_html, "Owner UI contains sensor authority and Admin navigation")

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
        try:
            port = httpd.server_address[1]
            with urlopen(f"http://127.0.0.1:{port}/admin", timeout=3) as r:
                check(r.status == 200 and b"Admin Operations" in r.read(), "/admin is served by the existing OwnerUI HTTP service")
            with urlopen(f"http://127.0.0.1:{port}/admin/api/state", timeout=3) as r:
                payload = json.loads(r.read().decode("utf-8"))
                check(payload["schema"] == "cyberdefender.admin-operations.v1", "/admin/api/state returns technical telemetry")
                check(payload["sensor_plane"]["authoritative_sensor"] == "ProcessSensor", "Admin API cannot bypass process authority")
            with urlopen(f"http://127.0.0.1:{port}/owner", timeout=3) as r:
                check(r.status == 200 and b"Process Sensor Plane" in r.read(), "strengthened /owner remains served on the same 24/7 service")
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=3)

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
