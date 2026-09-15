"""CyberDefender Rust Process Sensor shadow boundary.

Security contract:
- shadow/diagnostic only;
- never publishes to EventBus;
- never feeds ProcessGraph;
- never grants authorization or performs OS actions;
- validates the exact Rust v0.4 wire schema before exposing data;
- failures are isolated from the authoritative Python ProcessSensor path.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import queue
import subprocess
import threading
import time
from typing import Any

MAX_BYTES = 8 * 1024 * 1024
MAX_PROCESSES = 5000
EPOCH_TICKS = 116444736000000000


class RustProcessShadowError(RuntimeError):
    pass


def _object_no_duplicates(pairs):
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RustProcessShadowError("duplicate JSON key")
        result[key] = value
    return result


def _finite_number(value: Any) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def validate_rust_v04_snapshot(raw: bytes, *, now: float | None = None) -> dict[str, Any]:
    """Validate exact cd.process.v4 / RustProcessSensor 0.4.0 output."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise RustProcessShadowError("output size/type rejected")

    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(
                RustProcessShadowError("nonfinite JSON")
            ),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RustProcessShadowError("invalid JSON") from exc

    keys = {
        "schema",
        "sensor",
        "version",
        "timestamp",
        "partial",
        "skipped",
        "process_count",
        "processes",
        "skipped_processes",
    }
    if type(data) is not dict or set(data) != keys:
        raise RustProcessShadowError("snapshot schema rejected")

    if (
        data["schema"],
        data["sensor"],
        data["version"],
    ) != (
        "cd.process.v4",
        "RustProcessSensor",
        "0.4.0",
    ):
        raise RustProcessShadowError("unsupported schema/version")

    current_time = time.time() if now is None else now
    stamp = data["timestamp"]
    if not _finite_number(stamp) or abs(current_time - stamp) > 30:
        raise RustProcessShadowError("stale/future timestamp")

    rows = data["processes"]
    count = data["process_count"]
    skipped = data["skipped"]

    if type(rows) is not list or type(count) is not int or type(skipped) is not int:
        raise RustProcessShadowError("invalid count types")
    if count != len(rows) or count < 0 or skipped < 0 or count + skipped > MAX_PROCESSES:
        raise RustProcessShadowError("count/limit rejected")
    if type(data["partial"]) is not bool or data["partial"] != (skipped > 0):
        raise RustProcessShadowError("inconsistent completeness")
    if count + skipped == 0:
        raise RustProcessShadowError("empty enumeration rejected")

    row_keys = {
        "pid",
        "ppid",
        "name",
        "create_time",
        "creation_filetime",
        "exe",
        "username",
        "cmdline",
        "cpu_percent",
        "memory_percent",
    }
    seen: set[int] = set()

    for row in rows:
        if type(row) is not dict or set(row) != row_keys:
            raise RustProcessShadowError("invalid process schema")

        for key in ("pid", "ppid"):
            if type(row[key]) is not int or not 0 <= row[key] <= 0xFFFFFFFF:
                raise RustProcessShadowError("invalid PID")

        pid = row["pid"]
        if pid in seen:
            raise RustProcessShadowError("duplicate PID")
        seen.add(pid)

        name = row["name"]
        try:
            valid_name = type(name) is str and 0 < len(name.encode("utf-16-le")) <= 520
        except UnicodeError:
            valid_name = False
        if not valid_name:
            raise RustProcessShadowError("invalid process name")

        ticks_text = row["creation_filetime"]
        if (
            type(ticks_text) is not str
            or not ticks_text.isascii()
            or not ticks_text.isdecimal()
            or not 1 <= len(ticks_text) <= 20
        ):
            raise RustProcessShadowError("invalid creation ticks")

        ticks = int(ticks_text)
        if not EPOCH_TICKS <= ticks <= 0xFFFFFFFFFFFFFFFF:
            raise RustProcessShadowError("invalid creation epoch")

        expected = (ticks - EPOCH_TICKS) / 10_000_000.0
        created = row["create_time"]
        if (
            not _finite_number(created)
            or abs(created - expected) > 0.000001
            or created > stamp + 0.000001
        ):
            raise RustProcessShadowError("creation time mismatch")

        # v0.4 intentionally does not claim enrichment it does not collect.
        if any(
            row[key] is not None
            for key in ("exe", "username", "cmdline", "cpu_percent", "memory_percent")
        ):
            raise RustProcessShadowError("unsupported enrichment")

        # Canonical graph-compatible float is reconstructed from exact ticks.
        row["create_time"] = expected

    diagnostics = data["skipped_processes"]
    if type(diagnostics) is not list or len(diagnostics) != skipped:
        raise RustProcessShadowError("skipped diagnostic count mismatch")

    api_reasons = {
        "OPEN_ACCESS_DENIED",
        "OPEN_FAILED",
        "TIMES_FAILED",
        "SYSTEM_IDLE_UNQUERYABLE",
    }
    local_reasons = {
        "INVALID_CREATION_TIME",
        "CREATED_AFTER_SNAPSHOT_START",
        "INVALID_NAME",
    }

    for item in diagnostics:
        if type(item) is not dict or set(item) != {"pid", "reason", "win32_error"}:
            raise RustProcessShadowError("invalid skipped diagnostic")

        pid = item["pid"]
        reason = item["reason"]
        code = item["win32_error"]

        if type(pid) is not int or not 0 <= pid <= 0xFFFFFFFF or pid in seen:
            raise RustProcessShadowError("duplicate/invalid skipped PID")
        seen.add(pid)

        if type(reason) is not str or reason not in api_reasons | local_reasons:
            raise RustProcessShadowError("unknown skip reason")

        if reason in api_reasons:
            if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
                raise RustProcessShadowError("invalid Windows error code")
            if reason == "OPEN_ACCESS_DENIED" and code != 5:
                raise RustProcessShadowError("access denied code mismatch")
            if reason == "SYSTEM_IDLE_UNQUERYABLE" and (pid != 0 or code != 87):
                raise RustProcessShadowError("system idle coverage code mismatch")
            if reason == "OPEN_FAILED" and code == 5:
                raise RustProcessShadowError("access denied misclassified")
            if reason == "OPEN_FAILED" and pid == 0 and code == 87:
                raise RustProcessShadowError("known system idle limitation misclassified")
        elif code is not None:
            raise RustProcessShadowError("non-API failure has stale error")

    return data


def _run_bounded(command: list[str], *, timeout: float = 5.0, max_bytes: int = MAX_BYTES) -> bytes:
    """Run one cooperative local probe with bounded time and stdout."""
    if not 0 < timeout <= 30 or not 0 < max_bytes <= MAX_BYTES:
        raise ValueError("invalid transport limits")

    messages: queue.Queue[bytes] = queue.Queue(maxsize=8)
    stop = threading.Event()

    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            bufsize=0,
        )
    except OSError as exc:
        raise RustProcessShadowError("sensor could not start") from exc

    if child.stdout is None:
        child.kill()
        raise RustProcessShadowError("sensor stdout unavailable")

    def reader() -> None:
        try:
            while not stop.is_set():
                chunk = child.stdout.read(8192)
                while not stop.is_set():
                    try:
                        messages.put(chunk, timeout=0.05)
                        break
                    except queue.Full:
                        pass
                if not chunk:
                    return
        except (OSError, ValueError):
            return

    worker = threading.Thread(target=reader, daemon=True)
    worker.start()
    deadline = time.monotonic() + timeout
    raw = bytearray()

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RustProcessShadowError("sensor timeout")
            try:
                chunk = messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise RustProcessShadowError("sensor timeout") from exc

            if not chunk:
                break
            if len(raw) + len(chunk) > max_bytes:
                raise RustProcessShadowError("sensor output limit exceeded")
            raw.extend(chunk)

        try:
            code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise RustProcessShadowError("sensor exit timeout") from exc

        if code != 0:
            raise RustProcessShadowError("sensor nonzero exit")

        return bytes(raw)
    finally:
        stop.set()
        if child.poll() is None:
            child.kill()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        worker.join(timeout=1)
        if not worker.is_alive():
            try:
                child.stdout.close()
            except Exception:
                pass


def compare_shadow_to_authoritative(
    authoritative_snapshot: dict[str, Any],
    rust_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Compare only fields both sensors authoritatively claim.

    This is sequential shadow evidence, not an atomic proof of completeness.
    It never mutates either snapshot and never decides process lifecycle.
    """
    python_rows = authoritative_snapshot.get("processes", [])
    rust_rows = rust_snapshot.get("processes", [])

    if not isinstance(python_rows, list) or not isinstance(rust_rows, list):
        raise RustProcessShadowError("comparison snapshot rejected")

    py_by_pid: dict[int, dict[str, Any]] = {}
    for row in python_rows:
        if not isinstance(row, dict):
            continue
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            continue
        if pid < 0 or pid in py_by_pid:
            continue
        py_by_pid[pid] = row

    rust_by_pid = {row["pid"]: row for row in rust_rows if isinstance(row, dict)}
    skip_by_pid = {
        item["pid"]: item
        for item in rust_snapshot.get("skipped_processes", [])
        if isinstance(item, dict) and isinstance(item.get("pid"), int)
    }

    common = sorted(set(py_by_pid) & set(rust_by_pid))
    identity_disagreements: list[int] = []
    parent_disagreements: list[int] = []

    for pid in common:
        py_row = py_by_pid[pid]
        rust_row = rust_by_pid[pid]

        try:
            py_created = float(py_row.get("create_time"))
            rust_created = float(rust_row.get("create_time"))
        except (TypeError, ValueError, OverflowError):
            identity_disagreements.append(pid)
            continue

        if not math.isfinite(py_created) or not math.isfinite(rust_created):
            identity_disagreements.append(pid)
            continue

        # Exact ProcessGraph identity contract is six decimal places.
        if f"{py_created:.6f}" != f"{rust_created:.6f}":
            identity_disagreements.append(pid)

        try:
            py_ppid = int(py_row.get("ppid"))
        except (TypeError, ValueError):
            py_ppid = None
        rust_ppid = rust_row.get("ppid")
        if py_ppid is not None and py_ppid != rust_ppid:
            parent_disagreements.append(pid)

    python_only = sorted(set(py_by_pid) - set(rust_by_pid))
    python_only_with_skip = [pid for pid in python_only if pid in skip_by_pid]
    python_only_without_skip = [pid for pid in python_only if pid not in skip_by_pid]
    rust_only = sorted(set(rust_by_pid) - set(py_by_pid))

    review_required = bool(identity_disagreements or parent_disagreements)
    if review_required:
        verdict = "REVIEW_REQUIRED"
    elif rust_snapshot.get("partial"):
        verdict = "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS"
    else:
        verdict = "ALIGNED_COMMON_SET"

    return {
        "mode": "SHADOW_ONLY",
        "authoritative_sensor": "ProcessSensor",
        "shadow_sensor": "RustProcessSensor",
        "verdict": verdict,
        "python_process_count": len(py_by_pid),
        "rust_process_count": len(rust_by_pid),
        "common_processes": len(common),
        "exact_graph_identity_matches": len(common) - len(identity_disagreements),
        "identity_disagreements": {
            "count": len(identity_disagreements),
            "examples": identity_disagreements[:20],
        },
        "parent_disagreements": {
            "count": len(parent_disagreements),
            "examples": parent_disagreements[:20],
        },
        "python_only": {
            "count": len(python_only),
            "with_rust_skip_reason": len(python_only_with_skip),
            "without_rust_skip_reason": len(python_only_without_skip),
            "examples": python_only[:20],
        },
        "rust_only": {
            "count": len(rust_only),
            "examples": rust_only[:20],
        },
        "rust_partial": bool(rust_snapshot.get("partial")),
        "rust_skipped": int(rust_snapshot.get("skipped", 0)),
        "limits": (
            "Sequential shadow samples are not atomic. Churn may explain "
            "python-only/rust-only PIDs. Shadow results never drive ProcessGraph, "
            "EventBus, authorization, or response actions."
        ),
    }


class RustProcessShadowProbe:
    """Shadow-only executable boundary for RustProcessSensor v0.4."""

    VERSION = "0.4.0-shadow-integration.1"

    def __init__(self, executable: str | Path, *, timeout: float = 5.0):
        path = Path(executable)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("explicit existing absolute executable path required")
        if not 0 < timeout <= 30:
            raise ValueError("invalid timeout")

        self.executable = path.resolve()
        self.timeout = float(timeout)
        self.probe_count = 0
        self.failed_count = 0
        self.status = "NOT_STARTED"
        self.last_error: str | None = None
        self.last_snapshot: dict[str, Any] | None = None

    def probe(self) -> dict[str, Any]:
        try:
            data = validate_rust_v04_snapshot(
                _run_bounded([str(self.executable)], timeout=self.timeout)
            )
        except Exception as exc:
            self.failed_count += 1
            self.status = "DEGRADED"
            self.last_error = type(exc).__name__
            raise

        self.probe_count += 1
        self.last_snapshot = data
        self.last_error = None

        # A known PID 0 limitation is evidence-limited, not a transport failure.
        diagnostics = data.get("skipped_processes", [])
        known_only = bool(diagnostics) and all(
            item.get("reason") == "SYSTEM_IDLE_UNQUERYABLE"
            for item in diagnostics
            if isinstance(item, dict)
        )
        self.status = "HEALTHY" if (not data.get("partial") or known_only) else "LIMITED"
        return data

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "RustProcessShadowProbe",
            "status": self.status,
            "version": self.VERSION,
            "mode": "SHADOW_ONLY",
            "probe_count": self.probe_count,
            "failed_count": self.failed_count,
            "last_error": self.last_error,
        }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()
