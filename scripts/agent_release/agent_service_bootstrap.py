"""Entrypoint for a versioned Agent release.

The shared installed virtualenv remains in the original application directory,
while this bootstrap forces every CyberDefender import to resolve from the
immutable Agent release directory.
"""
from __future__ import annotations

import importlib.util
import importlib
import copy
import hashlib
import json
import os
import runpy
import secrets
import shutil
import stat
import sys
sys.dont_write_bytecode = True
import tempfile
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


def _verify_pinned_dependencies(
    root: Path,
    *,
    required: bool,
    allow_detached_runtime: bool = False,
) -> None:
    expected_runtime_root = (root / "runtime").resolve()
    runtime_root = Path(sys.executable).resolve().parent
    if runtime_root != expected_runtime_root and not allow_detached_runtime:
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
    for name in (
        "cryptography",
        "psutil",
        "pywintypes",
        "servicemanager",
        "win32file",
        "win32security",
        "win32service",
        "win32serviceutil",
    ):
        module = importlib.import_module(name)
        origin = getattr(module, "__file__", None)
        if origin is None or not Path(origin).resolve(strict=True).is_relative_to(dependency_root):
            raise RuntimeError("dependency import escaped pinned runtime: " + name)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_spool_snapshot(spool_dir: Path) -> tuple[int, int, set[str]]:
    from agent.storage.durable_spool import DurableSpoolPolicy

    policy = DurableSpoolPolicy()
    snapshot = spool_dir / "acked_state.json"
    pending = spool_dir / "pending.jsonl"
    if not snapshot.is_file() or not pending.is_file():
        raise RuntimeError("RECOVERY_SPOOL_REQUIRED_FILE_MISSING")
    raw = snapshot.read_bytes()
    if not 0 < len(raw) <= policy.max_terminal_state_bytes:
        raise RuntimeError("RECOVERY_ACK_SNAPSHOT_SIZE_REJECTED")
    try:
        state = json.loads(raw.decode("utf-8"))
    except Exception:
        raise RuntimeError("RECOVERY_ACK_SNAPSHOT_JSON_REJECTED") from None
    if (
        type(state) is not dict
        or set(state) != {"schema_version", "status", "acked_ids"}
        or state["schema_version"] != "1"
        or state["status"] != "ACKED"
        or type(state["acked_ids"]) is not list
        or any(type(item) is not str or not item.strip() for item in state["acked_ids"])
        or len({item.strip() for item in state["acked_ids"]}) != len(state["acked_ids"])
    ):
        raise RuntimeError("RECOVERY_ACK_SNAPSHOT_SCHEMA_REJECTED")
    acked_ids = {item.strip() for item in state["acked_ids"]}
    if pending.stat().st_size > policy.max_recovery_scan_bytes:
        raise RuntimeError("RECOVERY_PENDING_SIZE_REJECTED")
    pending_ids: set[str] = set()
    with pending.open("rb") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line.decode("utf-8"))
            except Exception:
                raise RuntimeError("RECOVERY_PENDING_JSON_REJECTED") from None
            event_id = record.get("event_id") if type(record) is dict else None
            if type(event_id) is not str or not event_id.strip():
                raise RuntimeError("RECOVERY_PENDING_SCHEMA_REJECTED")
            event_id = event_id.strip()
            # pending.jsonl is an append journal.  Rows made terminal by the
            # authoritative ACK snapshot can remain until bounded compaction;
            # they are no longer part of the logical pending set exposed by
            # DurableEventSpool on the evidence copy.
            if event_id not in acked_ids:
                pending_ids.add(event_id)
            if len(pending_ids) > policy.max_pending_events:
                raise RuntimeError("RECOVERY_PENDING_COUNT_REJECTED")
    return len(state["acked_ids"]), len(raw), pending_ids


def _copy_spool_for_check(live: Path, destination: Path) -> dict[str, str]:
    if not _directory_is_safe(live):
        raise RuntimeError("RECOVERY_SPOOL_PATH_REJECTED")
    names = ("pending.jsonl", "acked.jsonl", "quarantined.jsonl", "acked_state.json")
    hashes: dict[str, str] = {}
    destination.mkdir(parents=True)
    for name in names:
        source = live / name
        if source.exists():
            if not source.is_file() or source.is_symlink() or getattr(source.lstat(), "st_file_attributes", 0) & 0x400:
                raise RuntimeError("RECOVERY_SPOOL_FILE_REJECTED")
            hashes[name] = _file_sha256(source)
            shutil.copyfile(source, destination / name)
    for name, expected in hashes.items():
        if _file_sha256(live / name) != expected:
            raise RuntimeError("RECOVERY_SPOOL_CHANGED_DURING_COPY")
    return hashes


class _MemoryCrashStore:
    def __init__(self, record: dict):
        self.record = copy.deepcopy(record)

    def load(self):
        return copy.deepcopy(self.record)

    def write(self, record):
        from agent.service_crash_store import CrashStoreError, validate_record

        if record["revision"] != self.record["revision"]:
            raise CrashStoreError("STORE_STALE_WRITER")
        updated = copy.deepcopy(record)
        updated["revision"] += 1
        validate_record(updated, updated["service"])
        self.record = updated
        return self.load()


def _guard_admission_preview(record: dict, *, authorize: bool) -> dict:
    from agent.service_crash_guard import CrashGuard, CrashPolicy
    from agent.service_crash_store import authorize_probe_transition

    candidate = authorize_probe_transition(record) if authorize else copy.deepcopy(record)
    ticks = [0.0]
    clock = lambda: ticks[0]
    policy = CrashPolicy()
    memory = _MemoryCrashStore(candidate)
    guard = CrashGuard(memory, boot="feedface", policy=policy, clock=clock)
    ticks[0] = policy.cooldown_seconds + 1.0
    if not guard.admit():
        raise RuntimeError("RECOVERY_CRASHGUARD_ADMISSION_REJECTED")
    admitted = memory.load()
    return {
        "state": admitted["state"],
        "generation": admitted["generation"],
        "attempts_since_stable": admitted["attempts_since_stable"],
        "probes_used": admitted["probes_used"],
        "active_attempt": admitted["active_attempt"],
    }


def _recovery_gate(*, authorize_preview: bool, require_live_safe: bool) -> dict:
    from agent.service_crash_store import FileCrashStore, default_root
    from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy

    store = FileCrashStore(default_root(), "CyberDefenderAgent")
    try:
        record = store.load()
    finally:
        store.close()
    admission = _guard_admission_preview(record, authorize=authorize_preview)
    live = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "CyberDefender" / "state" / "spool"
    raw_count, raw_bytes, pending_before = _strict_spool_snapshot(live)
    policy = DurableSpoolPolicy()
    allowed = policy.max_terminal_records if require_live_safe else policy.max_terminal_records + 1
    if raw_count > allowed:
        raise RuntimeError("RECOVERY_ACK_COUNT_REJECTED")
    if require_live_safe and raw_count > policy.max_terminal_records:
        raise RuntimeError("RECOVERY_LIVE_SPOOL_UNSAFE")
    with tempfile.TemporaryDirectory(prefix="cd-recovery-gate-") as raw:
        copied = Path(raw) / "spool"
        hashes = _copy_spool_for_check(live, copied)
        checked = DurableEventSpool(copied)
        health = checked.health_check()
        pending_after = {item["event_id"] for item in checked.pending_records()}
        if health["status"] != "HEALTHY" or not health["terminal_state_safe"]:
            raise RuntimeError("RECOVERY_SPOOL_COPY_UNHEALTHY")
        if pending_before != pending_after:
            raise RuntimeError("RECOVERY_PENDING_SET_CHANGED")
        for name, expected in hashes.items():
            if _file_sha256(live / name) != expected:
                raise RuntimeError("RECOVERY_LIVE_SPOOL_CHANGED")
    return {
        "status": "RECOVERY_PRESTART_PASS" if require_live_safe else "RECOVERY_PLAN_COPY_PASS",
        "guard": admission,
        "spool": {
            "raw_terminal_records": raw_count,
            "max_terminal_records": policy.max_terminal_records,
            "raw_snapshot_bytes": raw_bytes,
            "max_terminal_state_bytes": policy.max_terminal_state_bytes,
            "pending_before": len(pending_before),
            "pending_after": len(pending_after),
            "pending_preserved": True,
            "copy_health": "HEALTHY",
            "live_hashes_unchanged": True,
        },
    }


def main() -> int:
    dependency_probe = sys.argv[1:] == ["--dependency-probe"]
    authorize_probe = sys.argv[1:] == ["--authorize-probe"]
    recovery_plan = sys.argv[1:] == ["--recovery-plan-copy"]
    pre_start_check = sys.argv[1:] == ["--pre-start-check"]
    if not dependency_probe and not authorize_probe and not recovery_plan and not pre_start_check:
        _open_stage()
    _stage("CD_BOOTSTRAP_B00_ENTER")
    script_dir = Path(__file__).resolve().parent
    root = script_dir
    if recovery_plan and not (root / "agent" / "windows_service.py").is_file():
        source_root = script_dir.parents[1]
        expected = source_root / "scripts" / "agent_release" / "agent_service_bootstrap.py"
        if expected.resolve() != Path(__file__).resolve():
            raise RuntimeError("RECOVERY_SOURCE_ROOT_REJECTED")
        root = source_root
    if not (root / "agent" / "windows_service.py").is_file():
        raise RuntimeError("pinned Agent package is missing")
    _stage("CD_BOOTSTRAP_B10_ROOT_OK")
    sys.path.insert(0, str(root))
    _stage("CD_BOOTSTRAP_B20_PATH_PINNED")
    spec = importlib.util.find_spec("agent.windows_service")
    if spec is None or spec.origin is None or Path(spec.origin).resolve().parent.parent != root:
        raise RuntimeError("Agent import escaped protected release root")
    _stage("CD_BOOTSTRAP_B30_ORIGIN_OK")
    _verify_pinned_dependencies(
        root,
        required=dependency_probe or authorize_probe or recovery_plan or pre_start_check,
        allow_detached_runtime=recovery_plan,
    )
    if dependency_probe:
        print("PROTECTED_RUNTIME_DEPENDENCY_PROBE_PASS")
        return 0
    if authorize_probe:
        from agent import service_crash_store

        sys.argv = ["service_crash_store", "authorize-probe", "--service", "CyberDefenderAgent"]
        service_crash_store.main()
        return 0
    if recovery_plan:
        print(json.dumps(_recovery_gate(authorize_preview=True, require_live_safe=False), sort_keys=True, separators=(",", ":")))
        return 0
    if pre_start_check:
        print(json.dumps(_recovery_gate(authorize_preview=False, require_live_safe=True), sort_keys=True, separators=(",", ":")))
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
