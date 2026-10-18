from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import traceback


_STAGES = frozenset({"runtime_imported", "gate_result"})


def _append_stage(path: Path, stage: str) -> None:
    if stage not in _STAGES:
        raise ValueError("CAPTURE_STAGE_CODE_REJECTED")
    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw = f"{stamp}|{stage}\n".encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json(path: Path, payload: dict) -> None:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > 2048:
        raise RuntimeError("CAPTURE_RESULT_BOUND_EXCEEDED")
    path.write_bytes(raw + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--stage-file", required=True)
    args = parser.parse_args()
    source_root = Path(args.source_root).resolve(strict=True)
    result_path = Path(args.result).resolve()
    trace_path = Path(args.trace).resolve()
    stage_path = Path(args.stage_file).resolve(strict=True)
    if result_path.parent != trace_path.parent or not result_path.parent.is_dir():
        raise RuntimeError("CAPTURE_OUTPUT_ROOT_REJECTED")
    if stage_path.parent != result_path.parent.parent:
        raise RuntimeError("CAPTURE_STAGE_ROOT_REJECTED")
    runtime_root = Path(sys.executable).resolve().parent
    if runtime_root != (source_root / "runtime").resolve(strict=True):
        raise RuntimeError("CAPTURE_RUNTIME_NOT_PINNED")
    dependency_root = runtime_root / "Lib" / "site-packages"
    sys.path[:0] = [
        str(source_root),
        str(dependency_root),
        str(dependency_root / "win32"),
        str(dependency_root / "win32" / "lib"),
        str(dependency_root / "Pythonwin"),
    ]
    runtime = None
    failure_fields = None
    try:
        import pywin32_bootstrap  # noqa: F401
        from agent.main import build_managed_runtime
        from agent.service_diagnostics import failure_fields

        _append_stage(stage_path, "runtime_imported")
        runtime = build_managed_runtime(allow_optional_sensors=False)
        health = runtime.health_snapshot()
        runtime_health = health.get("runtime", {}) if isinstance(health, dict) else {}
        _append_stage(stage_path, "gate_result")
        _write_json(result_path, {
            "status": "STARTUP_CAPTURE_PASS",
            "exception_class": None,
            "stage": "RUNTIME_FACTORY",
            "gate_code": None,
            "failing_component": None,
            "runtime_status": runtime_health.get("status"),
            "component_failures": runtime_health.get("component_failures"),
        })
        trace_path.write_text("NO_EXCEPTION\n", encoding="ascii")
        return 0
    except BaseException as exc:
        with trace_path.open("w", encoding="utf-8", errors="backslashreplace") as handle:
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=handle)
        fields = failure_fields(exc, "STARTUP") if failure_fields is not None else {
            "exception_class": type(exc).__name__,
            "stage": "RUNTIME_IMPORT",
            "gate_code": "BOOTSTRAP_IMPORT_FAILED",
            "failing_component": "runtime_import",
        }
        _append_stage(stage_path, "gate_result")
        _write_json(result_path, {
            "status": "STARTUP_CAPTURE_FAILED",
            "exception_class": fields.get("exception_class", "UNCLASSIFIED"),
            "stage": fields.get("stage", "UNKNOWN"),
            "gate_code": fields.get("gate_code", "BOOTSTRAP_UNCLASSIFIED"),
            "failing_component": fields.get("failing_component"),
            "source": fields.get("source"),
        })
        return 2
    finally:
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
