from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from agent.service_crash_guard import SERVICES
from agent.service_crash_store import default_root, protected_path

_LOCK = Lock()
_MAX_BYTES = 2 * 1024 * 1024
_BACKUPS = 2
_EVENTS = frozenset({"READY", "STARTING", "RUNNING", "STOPPED", "FATAL", "LATCHED", "PROBE",
                     "UNAVAILABLE", "HEALTHY", "DEGRADED", "STALLED", "TELEMETRY_UNAVAILABLE"})
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


def write_service_log(service: str, message: str, *, exc: BaseException | None = None) -> None:
    """Allowlisted, bounded per-service evidence; no arbitrary exception text.

    Separate files and an OS exclusive lock serialize rotation across processes.
    """
    if service not in SERVICES: return
    try:
        record = dict(schema="cd.service-diagnostic.v1", service=service,
                      time=datetime.now(timezone.utc).isoformat(),
                      event=message if message in _EVENTS else "UNCLASSIFIED")
        if exc is not None:
            name=type(exc).__name__
            record["exception_category"]=name if name in _EXCEPTIONS else "OTHER_EXCEPTION"
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
