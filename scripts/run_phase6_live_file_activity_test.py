from __future__ import annotations

"""Guarded installed-service Phase 6 live filesystem validation.

The default invocation is read-only and reports that the live test was not
executed.  ``--execute`` is required before this script may create the fixed
lab root, marker files, harmless plaintext fixtures, or evidence.  It never
uses synthetic telemetry: the simulator's callback is deliberately omitted,
so only the installed Agent's FileActivityCollector can observe the changes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from agent.sensors.file_activity_collector import (
    DEFAULT_LAB_FILE_ACTIVITY_ROOT,
    FILE_ACTIVITY_CANARY_MARKER,
    FILE_ACTIVITY_CANARY_MARKER_FILENAME,
    QUARANTINE_CANARY_MARKER,
    QUARANTINE_CANARY_MARKER_FILENAME,
    LAB_AUTO_QUARANTINE_ENABLE_MARKER,
    LAB_AUTO_QUARANTINE_ENABLE_MARKER_FILENAME,
    LAB_FILE_ACTIVITY_ENABLE_MARKER,
    LAB_FILE_ACTIVITY_ENABLE_MARKER_FILENAME,
)
from scripts.simulate_ransomware_behavior_v1 import simulate_ransomware_behavior


DEFAULT_STATE = Path(r"C:\ProgramData\CyberDefender\state\dashboard_runtime.json")
DEFAULT_EVIDENCE = Path(r"C:\CD\EVIDENCE")
DEFAULT_OUTSIDE_ROOT = Path(r"C:\CD\LAB\LiveRansomwareOutside")
SERVICES = (
    "CyberDefenderAgent",
    "CyberDefenderControlPlane",
    "CyberDefenderOwnerUI",
)


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _service_state(name: str) -> str:
    if os.name != "nt":
        return "UNAVAILABLE_NON_WINDOWS"
    try:
        completed = subprocess.run(
            ["sc.exe", "query", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "QUERY_FAILED"
    if completed.returncode != 0:
        return "NOT_FOUND"
    for line in completed.stdout.splitlines():
        if "STATE" in line and "RUNNING" in line.upper():
            return "RUNNING"
        if "STATE" in line and "STOPPED" in line.upper():
            return "STOPPED"
    return "UNKNOWN"


def _read_dashboard(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError):
        return {}


def _marker_contract(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise RuntimeError("lab root symlink/reparse is not allowed")
    (root / FILE_ACTIVITY_CANARY_MARKER_FILENAME).write_text(
        FILE_ACTIVITY_CANARY_MARKER,
        encoding="utf-8",
    )
    (root / QUARANTINE_CANARY_MARKER_FILENAME).write_text(
        QUARANTINE_CANARY_MARKER,
        encoding="utf-8",
    )
    (root / LAB_FILE_ACTIVITY_ENABLE_MARKER_FILENAME).write_text(
        LAB_FILE_ACTIVITY_ENABLE_MARKER,
        encoding="utf-8",
    )
    (root / LAB_AUTO_QUARANTINE_ENABLE_MARKER_FILENAME).write_text(
        LAB_AUTO_QUARANTINE_ENABLE_MARKER,
        encoding="utf-8",
    )


def run_live(*, execute: bool, state_path: Path, evidence_root: Path, timeout: int) -> dict[str, Any]:
    if not execute:
        return {
            "status": "NOT_EXECUTED",
            "reason": "read-only default; pass --execute only with explicit operator approval",
            "root": str(DEFAULT_LAB_FILE_ACTIVITY_ROOT),
            "simulator_event_injection": False,
            "production_authorization": "NOT_GRANTED",
        }
    if os.name != "nt":
        raise RuntimeError("installed-service live validation requires Windows")
    root = DEFAULT_LAB_FILE_ACTIVITY_ROOT
    outside_root = DEFAULT_OUTSIDE_ROOT
    if root != Path(r"C:\CD\LAB\LiveRansomwareTest"):
        raise RuntimeError("fixed lab root contract changed")
    before_services = {name: _service_state(name) for name in SERVICES}
    _marker_contract(root)
    dashboard_before = _read_dashboard(state_path)

    # No callback is supplied: the simulator performs only harmless local
    # filesystem operations and the installed Agent must observe them itself.
    simulator_events = simulate_ransomware_behavior(root=root, consumer=None)
    deadline = time.monotonic() + max(10, min(timeout, 300))
    dashboard = {}
    while time.monotonic() < deadline:
        dashboard = _read_dashboard(state_path)
        runtime = dashboard.get("runtime", {}) if isinstance(dashboard, dict) else {}
        detections = runtime.get("file_activity", {}).get("last_detections", []) if isinstance(runtime, dict) else []
        result = runtime.get("lab_quarantine", {}) if isinstance(runtime, dict) else {}
        if any(isinstance(item, dict) and item.get("type") == "RANSOMWARE_BEHAVIOR" for item in detections):
            if isinstance(result, dict) and result.get("status") in {"VERIFIED_QUARANTINED", "DENIED"}:
                break
        time.sleep(2)

    runtime = dashboard.get("runtime", {}) if isinstance(dashboard, dict) else {}
    detections = runtime.get("file_activity", {}).get("last_detections", []) if isinstance(runtime, dict) else []
    quarantine = runtime.get("lab_quarantine", {}) if isinstance(runtime, dict) else {}

    # Dedicated sibling only; never probe or mutate arbitrary user paths.
    outside_root.mkdir(parents=True, exist_ok=True)
    outside_target = outside_root / "outside-control.txt"
    outside_target.write_text("harmless outside-root negative control\n", encoding="utf-8")
    outside_exists = outside_target.exists()

    report = {
        "status": quarantine.get("status", "UNVERIFIED") if isinstance(quarantine, dict) else "UNVERIFIED",
        "test_timestamp": time.time(),
        "endpoint_id": dashboard.get("endpoint_id") if isinstance(dashboard, dict) else None,
        "source_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPOSITORY_ROOT, check=False, capture_output=True, text=True, timeout=10).stdout.strip(),
        "installed_hashes": {
            "agent_main": _sha256(Path(r"C:\Program Files\CyberDefender\app\agent\main.py")),
            "collector": _sha256(Path(r"C:\Program Files\CyberDefender\app\agent\sensors\file_activity_collector.py")),
        },
        "collector_event_count": runtime.get("file_activity", {}).get("events_seen") if isinstance(runtime, dict) else None,
        "detections": detections,
        "incident_id": quarantine.get("incident_id") if isinstance(quarantine, dict) else None,
        "risk": quarantine.get("risk_result") if isinstance(quarantine, dict) else None,
        "policy": quarantine.get("policy_decision") if isinstance(quarantine, dict) else None,
        "decision_digest": quarantine.get("decision_digest") if isinstance(quarantine, dict) else None,
        "verification": quarantine.get("verification_outcome") if isinstance(quarantine, dict) else None,
        "capability_id": quarantine.get("capability_id") if isinstance(quarantine, dict) else None,
        "quarantine_id": quarantine.get("quarantine_id") if isinstance(quarantine, dict) else None,
        "containment_verification": quarantine.get("status") if isinstance(quarantine, dict) else None,
        "services_before": before_services,
        "services_after": {name: _service_state(name) for name in SERVICES},
        "negative_control": {
            "outside_root": str(outside_root),
            "target_exists_after": outside_exists,
            "containment_allowed": False,
        },
        "simulator_event_count": len(simulator_events),
        "simulator_event_injection": False,
        "network_activity": False,
        "production_authorization": quarantine.get("production_authorization", "NOT_GRANTED") if isinstance(quarantine, dict) else "NOT_GRANTED",
    }
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_root / f"phase6-live-{int(report['test_timestamp'])}.json"
    evidence_path.write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
    report["evidence_path"] = str(evidence_path)
    report["dashboard_before"] = dashboard_before
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        print(json.dumps(run_live(execute=args.execute, state_path=args.state, evidence_root=args.evidence_root, timeout=args.timeout), sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "LIVE_TEST_FAILED", "error": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
