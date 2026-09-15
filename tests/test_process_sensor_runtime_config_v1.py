from __future__ import annotations

import json
from pathlib import Path
import tempfile

from agent.sensors.process_authority import ProcessSensorAuthorityController, ProcessSensorMode
from agent.sensors.process_runtime_config import (
    FILENAME,
    ProcessSensorRuntimeConfigError,
    load_process_sensor_runtime_config,
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def valid_config() -> dict:
    return {
        "schema": "cd.process-sensor-runtime-config.v1",
        "mode": "RUST_CANARY",
        "rust_v05": {
            "executable": r"C:\\Program Files\\CyberDefender\\app\\native\\process_sensor\\cyberdefender-process-sensor-v0.5.1.exe",
            "sha256": "a" * 64,
        },
        "canary": {
            "sample_every_cycles": 2,
            "timeout_seconds": 5.0,
            "max_restarts": 2,
            "restart_window_seconds": 60.0,
            "min_field_coverage": 0.98,
        },
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_process_cfg_") as td:
        base = Path(td)
        state_root = base / "state"
        state_root.mkdir()
        config_dir = base / "config"
        config_dir.mkdir()
        path = config_dir / FILENAME

        check(load_process_sensor_runtime_config(state_root) is None, "missing machine config preserves safe default")

        path.write_text(json.dumps(valid_config()), encoding="utf-8")
        loaded = load_process_sensor_runtime_config(state_root)
        check(isinstance(loaded, dict), "valid machine config is accepted")
        check(loaded["mode"] == ProcessSensorMode.RUST_CANARY, "RUST_CANARY mode is normalized")
        check(Path(loaded["path"]) == path.resolve(), "config resolves from machine sibling config directory")
        check(loaded["canary"]["max_restarts"] == 2, "restart budget is preserved")
        check(loaded["canary"]["min_field_coverage"] == 0.98, "coverage threshold is preserved")

        controller = ProcessSensorAuthorityController(
            mode=loaded["mode"],
            compiled_primary_enabled=False,
        )
        check(controller.mode == ProcessSensorMode.RUST_CANARY, "machine config selects canary mode only")
        check(controller.primary_runtime_unlocked() is False, "machine config cannot unlock Rust primary")
        check(controller.health_check()["authoritative_sensor"] == "ProcessSensor", "Python remains authoritative under canary config")

        zero = valid_config()
        zero["canary"]["max_restarts"] = 0
        path.write_text(json.dumps(zero), encoding="utf-8")
        check(load_process_sensor_runtime_config(state_root)["canary"]["max_restarts"] == 0, "zero restart budget remains representable")

        bad = valid_config()
        bad["rust_v05"]["sha256"] = "not-a-hash"
        path.write_text(json.dumps(bad), encoding="utf-8")
        try:
            load_process_sensor_runtime_config(state_root)
        except ProcessSensorRuntimeConfigError as exc:
            check(str(exc) == "PROCESS_CONFIG_RUST_HASH_INVALID", "invalid binary pin fails closed")
        else:
            raise AssertionError("invalid binary pin was accepted")

        # Exact duplicate JSON keys must be rejected before semantic parsing.
        path.write_text('{"schema":"cd.process-sensor-runtime-config.v1","schema":"cd.process-sensor-runtime-config.v1","mode":"RUST_CANARY","rust_v05":{"executable":"x","sha256":"' + ('a'*64) + '"},"canary":{"sample_every_cycles":2,"timeout_seconds":5,"max_restarts":2,"restart_window_seconds":60,"min_field_coverage":0.98}}', encoding="utf-8")
        try:
            load_process_sensor_runtime_config(state_root)
        except ProcessSensorRuntimeConfigError as exc:
            check(str(exc) == "PROCESS_CONFIG_DUPLICATE_KEY", "duplicate config keys are rejected")
        else:
            raise AssertionError("duplicate config key was accepted")

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
