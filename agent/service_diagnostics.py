from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from agent.service_crash_guard import SERVICES
from agent.service_crash_store import default_root, protected_path
from agent.runtime_gate_codes import failing_component, normalize_gate_code

_LOCK = Lock()
_MAX_BYTES = 2 * 1024 * 1024
_BACKUPS = 2
_EVENTS = frozenset({"READY", "STARTING", "RUNNING", "STOPPED", "EXIT", "FATAL", "LATCHED", "PROBE",
                     "UNAVAILABLE", "HEALTHY", "DEGRADED", "STALLED", "TELEMETRY_UNAVAILABLE",
                     "EVENTLOG_UNAVAILABLE", "OBSERVER_FAILED"})
_EXIT_REASONS = frozenset({
    "STOP_REQUESTED", "SHUTDOWN_REQUESTED", "RUNTIME_RETURNED", "UNHANDLED_EXCEPTION",
    "RESOURCE_GUARD_TERMINATION", "SERVICE_STOP_EVENT_SET", "COLLECTOR_FAILURE",
    "TEST_CYCLE_LIMIT", "UNKNOWN_EXIT",
})
_EXCEPTIONS = frozenset({"RuntimeError", "ValueError", "TypeError", "OSError", "PermissionError",
                         "TimeoutError", "ConnectionError", "ImportError", "ModuleNotFoundError"})


def _log_dir() -> Path:
    root = default_root()
    protected_path(root)
    path = root / "diagnostics"
    path.mkdir(exist_ok=True)
    protected_path(path)
    return path


def _rotate(path: Path) -> None:
    try:
        if path.exists(): protected_path(path)
        if not path.exists() or path.stat().st_size < _MAX_BYTES:
            return
        oldest = path.with_name(path.name + f".{_BACKUPS}")
        if oldest.exists():
            protected_path(oldest)
            oldest.unlink()
        for idx in range(_BACKUPS - 1, 0, -1):
            src = path.with_name(path.name + f".{idx}")
            if src.exists():
                protected_path(src)
                src.replace(path.with_name(path.name + f".{idx + 1}"))
        path.replace(path.with_name(path.name + ".1"))
    except OSError:
        raise  # Do not append beyond the retention bound if rotation fails.


def failure_fields(exc: BaseException, stage: str) -> dict:
    # Never inspect exception args, messages, locals, or chained exceptions.
    name = type(exc).__name__
    known = _EXCEPTIONS | {"RuntimeBootstrapError", "SpoolError"}
    result = {"exception_category": name if name in _EXCEPTIONS else "OTHER_EXCEPTION",
              "exception_class": name if name in known else "UNCLASSIFIED",
              "stage": stage if stage in {"STARTUP", "RUNTIME_RUN"} else "UNKNOWN"}
    if name not in known:
        result["class_fingerprint"] = hashlib.sha256(name[:256].encode("utf-8", "replace")).hexdigest()[:16]
    if name == "RuntimeBootstrapError":
        gate_code = normalize_gate_code(getattr(exc, "gate_code", None))
        result["gate_code"] = gate_code
        component = failing_component(gate_code)
        if component is not None:
            result["failing_component"] = component
    trusted = {"windows_service.py": {"_run_attempt"},
               "service_runner.py": {"run"},
               "main.py": {"build_managed_runtime", "__init__", "_initialize"}}
    root = Path(__file__).resolve().parent
    frame = exc.__traceback__
    for _ in range(32):
        if frame is None:
            break
        code = frame.tb_frame.f_code
        file = Path(code.co_filename)
        if file.is_absolute() and file.parent == root and code.co_name in trusted.get(file.name, set()):
            result["source"] = {"file": file.name, "function": code.co_name,
                                "line": min(max(frame.tb_lineno, 0), 999999)}
        frame = frame.tb_next
    return result


def write_service_log(service: str, message: str, *, exc: BaseException | None = None,
                      exit_reason: str | None = None, stage: str = "UNKNOWN") -> None:
    """Allowlisted, bounded per-service evidence; no arbitrary exception text.

    Separate files and an OS exclusive lock serialize rotation across processes.
    """
    if service not in SERVICES: return
    try:
        record = dict(schema="cd.service-diagnostic.v1", service=service,
                      time=datetime.now(timezone.utc).isoformat(),
                      event=message if message in _EVENTS else "UNCLASSIFIED")
        if exc is not None:
            record.update(failure_fields(exc, stage))
        if exit_reason is not None:
            record["exit_reason"] = exit_reason if exit_reason in _EXIT_REASONS else "UNKNOWN_EXIT"
        raw=json.dumps(record,separators=(",",":"),ensure_ascii=True).encode("ascii")+b"\n"
        if len(raw)>512: return
        with _LOCK:
            directory=_log_dir(); lock_path=directory/(service+".lock")
            if lock_path.exists(): protected_path(lock_path)
            import win32file, win32con
            lock=win32file.CreateFile(str(lock_path),win32con.GENERIC_READ|win32con.GENERIC_WRITE,
                                     0,None,win32con.OPEN_ALWAYS,0,None)
            try:
                path=directory/(service+".jsonl")
                _rotate(path)
                if path.exists(): protected_path(path)
                with path.open("ab") as handle: handle.write(raw)
            finally: lock.Close()
    except Exception:
        pass
