"""Entrypoint for a versioned Agent release.

The shared installed virtualenv remains in the original application directory,
while this bootstrap forces every CyberDefender import to resolve from the
immutable Agent release directory.
"""
from __future__ import annotations

import importlib.util
import importlib
import os
import runpy
import secrets
import stat
import sys
import threading
from pathlib import Path


_STAGE_CODES = (
    "CD_BOOTSTRAP_B00_ENTER",
    "CD_BOOTSTRAP_B10_ROOT_OK",
    "CD_BOOTSTRAP_B20_PATH_PINNED",
    "CD_BOOTSTRAP_B30_ORIGIN_OK",
    "CD_BOOTSTRAP_B40_DISPATCH_ENTER",
    "CD_BOOTSTRAP_B90_DISPATCH_ERROR",
    "CD_BOOTSTRAP_B99_DISPATCH_RETURN",
)
_STAGE_CODE_SET = frozenset(_STAGE_CODES)
_MAX_STAGE_BYTES = 4096
_STAGE_DIRECTORY = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Temp"
_STAGE_PATH: Path | None = None
_STAGE_HANDLE = None
_STAGE_BYTES = 0
_STAGE_LOCK = threading.RLock()


def _directory_is_safe(path: Path) -> bool:
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
        return True
    except OSError:
        return False


def _open_stage() -> None:
    global _STAGE_PATH, _STAGE_HANDLE, _STAGE_BYTES
    with _STAGE_LOCK:
        if _STAGE_HANDLE is not None or not _directory_is_safe(_STAGE_DIRECTORY):
            return
        path = _STAGE_DIRECTORY / ("CyberDefenderAgent-bootstrap-" + secrets.token_hex(16) + ".log")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
            _STAGE_PATH = path
            _STAGE_HANDLE = os.fdopen(descriptor, "wb", buffering=0)
            _STAGE_BYTES = 0
        except OSError:
            _STAGE_PATH = None
            _STAGE_HANDLE = None
            _STAGE_BYTES = 0


def _close_stage() -> None:
    global _STAGE_HANDLE
    with _STAGE_LOCK:
        if _STAGE_HANDLE is not None:
            try:
                _STAGE_HANDLE.close()
            except OSError:
                pass
            _STAGE_HANDLE = None


def _stage(code: str) -> None:
    """Best-effort, bounded fixed-code evidence before SCM lifecycle starts."""
    global _STAGE_BYTES
    if code not in _STAGE_CODE_SET:
        return
    with _STAGE_LOCK:
        descriptor = None
        before = None
        try:
            raw = code.encode("ascii") + b"\n"
            if _STAGE_HANDLE is None:
                return
            descriptor = _STAGE_HANDLE.fileno()
            before = os.fstat(descriptor).st_size
            _STAGE_BYTES = before
            if before + len(raw) > _MAX_STAGE_BYTES:
                return
            written = os.write(descriptor, raw)
            after = os.fstat(descriptor).st_size
            if written != len(raw) or after != before + len(raw):
                os.ftruncate(descriptor, before)
                os.lseek(descriptor, before, os.SEEK_SET)
                _STAGE_BYTES = before
                return
            os.fsync(descriptor)
            _STAGE_BYTES = after
        except (OSError, ValueError):
            if descriptor is not None and before is not None:
                try:
                    os.ftruncate(descriptor, before)
                    os.lseek(descriptor, before, os.SEEK_SET)
                except OSError:
                    pass
                _STAGE_BYTES = before


def _verify_pinned_dependencies(root: Path, *, required: bool) -> None:
    runtime_root = (root / "runtime").resolve()
    if Path(sys.executable).resolve().parent != runtime_root:
        if required:
            raise RuntimeError("dependency probe is not using the pinned runtime")
        return
    dependency_root = (runtime_root / "Lib" / "site-packages").resolve(strict=True)
    if not dependency_root.is_relative_to(runtime_root) or not _directory_is_safe(dependency_root):
        raise RuntimeError("dependency path escaped pinned runtime")
    for relative in ("win32", "win32/lib", "Pythonwin"):
        extension_root = (dependency_root / relative).resolve(strict=True)
        if not extension_root.is_relative_to(dependency_root) or not _directory_is_safe(extension_root):
            raise RuntimeError("pywin32 path escaped pinned runtime")
        sys.path.insert(0, str(extension_root))
    bootstrap_spec = importlib.util.find_spec("pywin32_bootstrap")
    if bootstrap_spec is None or bootstrap_spec.origin is None or not Path(bootstrap_spec.origin).resolve(strict=True).is_relative_to(dependency_root):
        raise RuntimeError("pywin32 bootstrap escaped pinned runtime")
    importlib.import_module("pywin32_bootstrap")
    for name in ("cryptography", "psutil", "win32service"):
        module = importlib.import_module(name)
        origin = getattr(module, "__file__", None)
        if origin is None or not Path(origin).resolve(strict=True).is_relative_to(dependency_root):
            raise RuntimeError("dependency import escaped pinned runtime: " + name)


def main() -> int:
    dependency_probe = sys.argv[1:] == ["--dependency-probe"]
    authorize_probe = sys.argv[1:] == ["--authorize-probe"]
    if not dependency_probe and not authorize_probe:
        _open_stage()
    _stage("CD_BOOTSTRAP_B00_ENTER")
    root = Path(__file__).resolve().parent
    if not (root / "agent" / "windows_service.py").is_file():
        raise RuntimeError("pinned Agent package is missing")
    _stage("CD_BOOTSTRAP_B10_ROOT_OK")
    sys.path.insert(0, str(root))
    _stage("CD_BOOTSTRAP_B20_PATH_PINNED")
    spec = importlib.util.find_spec("agent.windows_service")
    if spec is None or spec.origin is None or Path(spec.origin).resolve().parent.parent != root:
        raise RuntimeError("Agent import escaped protected release root")
    _stage("CD_BOOTSTRAP_B30_ORIGIN_OK")
    _verify_pinned_dependencies(root, required=dependency_probe or authorize_probe)
    if dependency_probe:
        print("PROTECTED_RUNTIME_DEPENDENCY_PROBE_PASS")
        return 0
    if authorize_probe:
        from agent import service_crash_store

        sys.argv = ["service_crash_store", "authorize-probe", "--service", "CyberDefenderAgent"]
        service_crash_store.main()
        return 0
    # Preserve the known-good `python -m agent.windows_service` dispatch
    # contract: pywin32 observes the service module as __main__, including
    # its module argv[0], while all imports remain pinned to this release.
    _stage("CD_BOOTSTRAP_B40_DISPATCH_ENTER")
    try:
        runpy.run_module("agent.windows_service", run_name="__main__", alter_sys=True)
    except SystemExit as exc:
        _stage("CD_BOOTSTRAP_B99_DISPATCH_RETURN" if exc.code in (None, 0) else "CD_BOOTSTRAP_B90_DISPATCH_ERROR")
        raise
    except BaseException:
        _stage("CD_BOOTSTRAP_B90_DISPATCH_ERROR")
        raise
    else:
        _stage("CD_BOOTSTRAP_B99_DISPATCH_RETURN")
        return 0
    finally:
        _close_stage()


if __name__ == "__main__":
    raise SystemExit(main())
