from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def main() -> int:
    executable = str(os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or "").strip()
    if not executable:
        raise AssertionError("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE is required")

    exe_path = Path(executable).expanduser().resolve()
    check(exe_path.is_file(), "RustProcessSensor executable exists")

    with tempfile.TemporaryDirectory(prefix="cyberdefender_rust_shadow_live_") as state_dir:
        os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode()
        os.environ["CYBERDEFENDER_RUST_PROCESS_SHADOW"] = "1"
        os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE"] = str(exe_path)

        km = KeyManager(Path(state_dir) / "keys", storage_key)
        check(km.generate_key() and km.is_ready(), "Temporary signing key is provisioned")

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        try:
            check(runtime.rust_process_shadow_enabled, "Runtime Rust shadow flag is enabled")
            check(runtime.rust_process_shadow is not None, "Runtime initialized Rust shadow probe")

            graph_result = runtime.update_process_graph()
            check(
                isinstance(graph_result, dict) and graph_result.get("accepted") is True,
                "Authoritative Python ProcessSensor still drives accepted ProcessGraph ingestion",
            )
            check(
                int(graph_result.get("processes_valid", 0)) > 0,
                "Authoritative ProcessGraph contains live processes",
            )

            comparison = runtime.last_rust_process_shadow_result
            check(isinstance(comparison, dict), "Live Rust shadow comparison is recorded")
            check(comparison.get("mode") == "SHADOW_ONLY", "Live Rust path remains SHADOW_ONLY")
            check(
                comparison.get("verdict") in {
                    "ALIGNED_COMMON_SET",
                    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
                },
                "Live Rust common-set identity/parent evidence is aligned",
            )
            check(
                comparison.get("identity_disagreements", {}).get("count") == 0,
                "No live graph identity disagreement",
            )
            check(
                comparison.get("parent_disagreements", {}).get("count") == 0,
                "No live parent disagreement",
            )

            shadow_health = runtime.health_snapshot().get("rust_process_shadow", {})
            check(
                shadow_health.get("mode") == "SHADOW_ONLY",
                "Rust shadow health surface is explicitly non-authoritative",
            )
            check(
                runtime.health_snapshot().get("runtime", {}).get("status") == "HEALTHY",
                "Live Rust shadow does not degrade healthy authoritative runtime",
            )

            print("\nLIVE SHADOW COMPARISON")
            print(json.dumps(comparison, indent=2, sort_keys=True))
            print("\nRUST PROCESS SHADOW LIVE v1: PASS")
            return 0
        finally:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
