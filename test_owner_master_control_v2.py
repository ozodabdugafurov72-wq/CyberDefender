from __future__ import annotations
import json, os, tempfile, time
from pathlib import Path
from urllib.request import urlopen, Request


def check(condition, label):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


def write_state(root: Path):
    (root / "state").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)
    now = time.time()
    snapshot = {
        "schema_version":"1.0",
        "publisher":{"component":"RuntimeStatePublisher","sequence":42,"generated_at":now},
        "runtime":{"status":"HEALTHY","version":"2.1","running":True,"cycle_count":12,"cycle_failures":0,"component_failures":0,"events_created":24,"events_admitted":24,"events_rejected":0,"risk":{"overall_score":100,"overall_risk":"CRITICAL"}},
        "health":{
            "runtime":{"status":"HEALTHY"},
            "safety_core":{"component":"SafetyCore","version":"2.2","status":"SAFE","safe_mode":False,"shutdown_requested":False,"fail_closed":True},
            "resource_guard":{"status":"DEGRADED"},
            "policy_engine":{"status":"HEALTHY"},
            "independent_verifier":{"status":"HEALTHY"},
            "authorization_gate":{"status":"HEALTHY","dry_run_only":True},
            "action_gateway":{"status":"HEALTHY","real_world_effect":False},
            "risk_engine":{"status":"HEALTHY","overall_score":100,"overall_risk":"CRITICAL"},
            "event_bus":{"status":"HEALTHY"},
            "attack_graph":{"status":"HEALTHY"},
        },
        "observation":{"cpu_percent":21.2,"memory_percent":93.4,"disk_percent":77.0,"process_count":272,"available_memory_mb":520.0},
        "incidents":[{"incident_id":"INC-TEST","severity":"CRITICAL","risk_score":60,"key":"agent-local:SystemObserver","timestamp":now}],
    }
    (root / "state" / "dashboard_runtime.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (root / "logs" / "events.jsonl").write_text(json.dumps({"event_type":"HIGH_MEMORY_USAGE","severity":"WARNING","timestamp":now,"message":"Memory usage high"})+"\n", encoding="utf-8")


def main():
    from dashboard_owner import server
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); write_state(root)
        server.ROOT = root; server.STATE_FILE = root / "state" / "dashboard_runtime.json"; server.LOG_FILE = root / "logs" / "events.jsonl"
        data = server.build_state()
        check(data["schema"] == "cyberdefender.owner-master-control.v2", "v2 schema")
        check(data["master_control"]["unlocked"] is True, "Master Control is ACTIVE-capable / UNLOCKED")
        check(data["master_control"]["real_world_effect"] is False, "Real-world effect remains BLOCKED")
        check(data["master_control"]["safety_enforced"] is True, "Safety enforcement remains ACTIVE")
        check(data["safety"]["status"] == "SAFE", "Safety Core is exposed as SAFE")
        check(data["security_posture"] == "CRITICAL", "Security posture is separated from runtime health")
        check(data["resource_state"]["status"] == "DEGRADED", "Resource pressure is visible separately")
        check(any(x["name"] == "Safety Core" for x in data["components"]), "Safety Core appears in component matrix")
        check(data["governance"]["dashboard_direct_os_access"] is False, "Dashboard has no direct OS access")
        check(data["governance"]["ai_privileged_authority"] == "NONE", "AI privileged authority is NONE")
        check(data["governance"]["human_approval_for_l6"] is True, "L6 requires human approval")
        check(data["runtime_freshness"]["available"] is True and data["runtime_freshness"]["stale"] is False, "Runtime freshness is represented")
        check(len(data["events"]) == 1, "Evidence stream is bounded and readable")
        print("RESULT: PASS")

if __name__ == "__main__":
    main()
