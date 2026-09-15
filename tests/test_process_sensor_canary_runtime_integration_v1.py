from __future__ import annotations

import base64
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.sensors.process_authority import ProcessSensorAuthorityController, ProcessSensorMode


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def snapshot() -> dict[str, Any]:
    return {
        "sensor": "ProcessSensor", "version": "1.0", "timestamp": time.time(),
        "process_count": 1,
        "processes": [{"pid": 700, "ppid": 4, "name": "tracked.exe", "exe": r"C:\\tracked.exe",
                       "username": "test", "cmdline": ["tracked.exe"], "create_time": 7000.0,
                       "cpu_percent": 0.0, "memory_percent": 0.0}],
    }


class FixedSensor:
    def __init__(self) -> None: self.calls = 0
    def collect(self) -> dict[str, Any]: self.calls += 1; return snapshot()
    def health_check(self) -> dict[str, Any]: return {"sensor":"ProcessSensor","status":"HEALTHY","version":"test"}
    def get_stats(self) -> dict[str, Any]: return {"collect_count":self.calls,"failed_count":0}


class FakeCanary:
    def __init__(self) -> None:
        self.calls = 0
        self.fail = False
        self.seen_sources: list[str] = []
    def sample(self, authoritative: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        self.seen_sources.append(str(authoritative.get("sensor")))
        if self.fail: raise RuntimeError("synthetic canary crash")
        return {"schema":"cd.process-canary-result.v1","authoritative":False,
                "authoritative_sensor":"ProcessSensor","candidate_sensor":"RustProcessSensor",
                "candidate_ready":True,"readiness_reason":"CANARY_PARITY_GATE_PASS"}
    def health_check(self) -> dict[str, Any]:
        return {"component":"RustProcessCanary","status":"DEGRADED" if self.fail else "HEALTHY",
                "mode":"RUST_CANARY","authoritative":False,"authoritative_sensor":"ProcessSensor",
                "promotion_bound":False,"sample_count":self.calls,"failure_count":0,
                "binary_trusted":True,"supervisor":{"status":"HEALTHY"}}
    def close(self) -> None: pass


def clear_env() -> None:
    for k in list(os.environ):
        if k.startswith("CYBERDEFENDER_PROCESS_SENSOR_") or k.startswith("CYBERDEFENDER_RUST_PROCESS_"):
            os.environ.pop(k, None)


def main() -> int:
    clear_env()
    temp = tempfile.TemporaryDirectory(prefix="cd_canary_runtime_")
    runtime = None
    try:
        os.environ["CYBERDEFENDER_STATE_DIR"] = str(Path(temp.name) / "state")
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(os.urandom(32)).decode()
        state_root = Path(os.environ["CYBERDEFENDER_STATE_DIR"])
        state_root.mkdir(parents=True)
        km = KeyManager(state_root / "keys", base64.b64decode(os.environ["CYBERDEFENDER_STORAGE_KEY_B64"]))
        if not km.generate_key(): raise AssertionError("signing key provisioning failed")
        runtime = CyberDefenderRuntime(SafetyCore(), load_config())

        runtime.process_sensor = FixedSensor()
        runtime.process_authority_controller = ProcessSensorAuthorityController(
            mode=ProcessSensorMode.RUST_CANARY, compiled_primary_enabled=False
        )
        runtime.process_sensor_mode = ProcessSensorMode.RUST_CANARY
        runtime.rust_process_shadow_enabled = False
        runtime.rust_process_canary_enabled = True
        runtime.rust_process_canary_sample_every_cycles = 1
        fake = FakeCanary()
        runtime.rust_process_canary = fake

        graph_sources: list[str] = []
        original_ingest = runtime.process_graph.ingest_snapshot
        def guarded(s: dict[str, Any]) -> dict[str, Any]:
            graph_sources.append(str(s.get("sensor")))
            return original_ingest(s)
        runtime.process_graph.ingest_snapshot = guarded  # type: ignore[method-assign]

        before_component = runtime.component_failures
        before_graph = runtime.process_graph_failures
        r1 = runtime.update_process_graph()
        check(isinstance(r1, dict) and r1.get("accepted") is True, "Python ProcessGraph cycle succeeds with Rust canary active")
        check(graph_sources == ["ProcessSensor"], "Rust canary never enters ProcessGraph")
        check(fake.seen_sources == ["ProcessSensor"], "canary compares only after authoritative Python snapshot")
        check(runtime.last_rust_process_canary_result is not None, "canary telemetry is retained for observability")
        check(runtime.component_failures == before_component, "successful canary adds no core component failure")

        fake.fail = True
        r2 = runtime.update_process_graph()
        check(isinstance(r2, dict) and r2.get("accepted") is True, "Python graph remains available when Rust canary crashes")
        check(graph_sources == ["ProcessSensor", "ProcessSensor"], "canary crash cannot create a second graph authority")
        check(runtime.component_failures == before_component, "canary crash is isolated from core component health")
        check(runtime.process_graph_failures == before_graph, "canary crash is not misclassified as ProcessGraph failure")
        check(runtime.rust_process_canary_failures == 1, "canary failure is separately observable")
        check(runtime.degraded is False, "non-authoritative canary failure does not degrade security runtime")

        health = runtime.health_snapshot()
        check(health["process_sensor_authority"]["authoritative_sensor"] == "ProcessSensor", "health preserves Python authority")
        check(health["rust_process_canary"]["authoritative"] is False, "health labels Rust canary non-authoritative")
        check(health["rust_process_canary"]["promotion_bound"] is False, "runtime canary cannot promote itself")
        check(runtime.process_authority_controller.compiled_primary_enabled is False, "Rust primary compiled lock remains closed")

    finally:
        if runtime is not None: runtime.close()
        temp.cleanup()
        clear_env()
        os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
        os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
