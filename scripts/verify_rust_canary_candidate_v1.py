from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.correlation.graph import ProcessGraph
from agent.sensors.process import ProcessSensor
from agent.sensors.rust_process_canary import RustProcessCanary


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def count(section: object) -> int:
    if not isinstance(section, dict):
        return -1
    try: return int(section.get("count", -1))
    except (TypeError, ValueError): return -1


def field_mismatches(comparison: dict, name: str) -> int:
    fields = comparison.get("fields", {})
    item = fields.get(name, {}) if isinstance(fields, dict) else {}
    try: return int(item.get("mismatches", -1)) if isinstance(item, dict) else -1
    except (TypeError, ValueError): return -1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-exe", required=True)
    parser.add_argument("--attempts", type=int, default=4)
    args = parser.parse_args()

    if os.name != "nt":
        print("Windows live canary candidate gate is Windows-only")
        return 2

    exe = Path(args.rust_exe).expanduser().resolve()
    check(exe.is_file(), "Rust v0.5.1 release candidate executable exists")
    check(ProcessGraph.VERSION == "1.6", "ProcessGraph coverage-aware version is 1.6")
    digest = sha256(exe)
    print(f"Rust candidate SHA-256: {digest}")

    canary = RustProcessCanary(
        exe,
        digest,
        timeout=5.0,
        max_restarts=2,
        restart_window_seconds=60.0,
        min_field_coverage=0.98,
    )
    sensor = ProcessSensor()
    try:
        result = None
        attempts = max(1, min(int(args.attempts), 8))
        for attempt in range(1, attempts + 1):
            py = sensor.collect()
            result = canary.sample(py)
            comparison = result.get("comparison", {}) if isinstance(result, dict) else {}
            print(
                f"Attempt {attempt}: ready={result.get('candidate_ready')} "
                f"reason={result.get('readiness_reason')} "
                f"common={comparison.get('common_processes')}"
            )
            if result.get("candidate_ready") is True:
                break
            time.sleep(0.35)

        check(isinstance(result, dict), "Rust canary produced validated comparison telemetry")
        comparison = result.get("comparison", {})
        check(isinstance(comparison, dict), "comparison object is present")
        check(count(comparison.get("identity_disagreements")) == 0, "identity disagreements remain zero")
        check(count(comparison.get("parent_disagreements")) == 0, "parent disagreements remain zero")
        check(count(comparison.get("canonical_name_conflicts")) == 0, "canonical name conflicts remain zero")
        for field in ("exe", "username", "cmdline"):
            check(field_mismatches(comparison, field) == 0, f"{field} collected-value mismatches remain zero")
        check(result.get("candidate_ready") is True, "v0.5.1 candidate passes bounded readiness gate")

        before = canary.supervisor.health_check()
        check(before.get("status") == "HEALTHY", "persistent supervisor is HEALTHY before crash probe")
        check(before.get("launch_binding_verified") is True, "launch nonce binding is verified")
        check(before.get("direct_pid_verified") is True, "direct native child PID binding is verified")
        old_epoch = before.get("sensor_epoch")
        old_generation = int(before.get("generation", 0))
        child = canary.supervisor.child
        check(child is not None and child.poll() is None, "native child is alive before controlled crash")
        child.kill()
        child.wait(timeout=3)

        recovered = canary.sample(sensor.collect())
        after = canary.supervisor.health_check()
        check(after.get("status") == "HEALTHY", "supervisor recovers after controlled native crash")
        check(int(after.get("restart_count", 0)) >= 1, "controlled crash increments restart counter")
        check(int(after.get("generation", 0)) > old_generation, "controlled crash advances supervisor generation")
        check(after.get("sensor_epoch") and after.get("sensor_epoch") != old_epoch, "controlled crash negotiates a new sensor epoch")
        check(recovered.get("authoritative") is False, "recovered Rust evidence remains non-authoritative")
        check(recovered.get("authoritative_sensor") == "ProcessSensor", "Python remains authoritative after native recovery")

        health = canary.health_check()
        check(health.get("binary_trusted") is True, "deployment candidate binary pin remains verified")
        check(health.get("promotion_bound") is False, "candidate evidence cannot self-promote")
        print("RUST CANARY CANDIDATE LIVE v1: PASS")
        return 0
    finally:
        canary.close()


if __name__ == "__main__":
    raise SystemExit(main())
