from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


class ProcessSensorRuntimeConfigError(RuntimeError):
    pass


SCHEMA = "cd.process-sensor-runtime-config.v1"
FILENAME = "process_sensor_runtime.json"
TOP_KEYS = {"schema", "mode", "rust_v05", "canary"}
RUST_KEYS = {"executable", "sha256"}
CANARY_KEYS = {
    "sample_every_cycles",
    "timeout_seconds",
    "max_restarts",
    "restart_window_seconds",
    "min_field_coverage",
}


def _finite_number(value: Any) -> bool:
    return type(value) in {int, float} and math.isfinite(float(value))


def load_process_sensor_runtime_config(state_root: Path) -> dict[str, Any] | None:
    """Load the optional machine-local process sensor runtime config.

    The file is configuration only.  It never grants Rust primary authority;
    the ProcessSensorAuthorityController keeps its compiled primary lock.
    """
    if not isinstance(state_root, Path):
        raise TypeError("state_root must be Path")

    # Machine runtime state lives under <base>/state while operator-owned
    # configuration lives under the sibling <base>/config directory.  For a
    # repository-local runtime this naturally resolves to <repo>/config.
    path = state_root.parent / "config" / FILENAME
    if not path.is_file():
        return None

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_READ_FAILED") from exc

    if not raw or len(raw) > 64 * 1024:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_SIZE_INVALID")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_DUPLICATE_KEY")
            out[key] = value
        return out

    try:
        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    except ProcessSensorRuntimeConfigError:
        raise
    except Exception as exc:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_JSON_INVALID") from exc

    if type(data) is not dict or set(data) != TOP_KEYS:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_SCHEMA_INVALID")
    if data.get("schema") != SCHEMA:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_SCHEMA_MISMATCH")

    mode = data.get("mode")
    if not isinstance(mode, str) or not mode.strip() or len(mode) > 64:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_MODE_INVALID")

    rust = data.get("rust_v05")
    if type(rust) is not dict or set(rust) != RUST_KEYS:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_RUST_INVALID")
    executable = rust.get("executable")
    digest = rust.get("sha256")
    if not isinstance(executable, str) or not executable.strip() or len(executable) > 4096:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_RUST_PATH_INVALID")
    if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_RUST_HASH_INVALID")

    canary = data.get("canary")
    if type(canary) is not dict or set(canary) != CANARY_KEYS:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_CANARY_INVALID")

    sample_every = canary.get("sample_every_cycles")
    max_restarts = canary.get("max_restarts")
    timeout = canary.get("timeout_seconds")
    restart_window = canary.get("restart_window_seconds")
    min_coverage = canary.get("min_field_coverage")

    if type(sample_every) is not int or not 1 <= sample_every <= 60:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_SAMPLE_CADENCE_INVALID")
    if type(max_restarts) is not int or not 0 <= max_restarts <= 10:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_RESTART_BOUND_INVALID")
    if not _finite_number(timeout) or not 0.25 <= float(timeout) <= 30.0:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_TIMEOUT_INVALID")
    if not _finite_number(restart_window) or not 1.0 <= float(restart_window) <= 600.0:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_RESTART_WINDOW_INVALID")
    if not _finite_number(min_coverage) or not 0.5 <= float(min_coverage) <= 1.0:
        raise ProcessSensorRuntimeConfigError("PROCESS_CONFIG_COVERAGE_INVALID")

    return {
        "schema": SCHEMA,
        "path": str(path.resolve()),
        "mode": mode.strip().upper(),
        "rust_v05": {
            "executable": executable.strip(),
            "sha256": digest.lower(),
        },
        "canary": {
            "sample_every_cycles": sample_every,
            "timeout_seconds": float(timeout),
            "max_restarts": max_restarts,
            "restart_window_seconds": float(restart_window),
            "min_field_coverage": float(min_coverage),
        },
    }
