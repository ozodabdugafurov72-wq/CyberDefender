"""CrashGuard v2 authenticated dual-slot store for a single service writer."""
from __future__ import annotations

import copy
import errno
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import stat
import tempfile
import time
from typing import Callable

from agent.crashguard_v2.failure_codes import FAILURE_CODES, STORE_FAILURE_CODES
from agent.crashguard_v2.state_machine import Health, Lifecycle


RECORD_SCHEMA = "cd.crashguard-state.v2"
ANCHOR_SCHEMA = "cd.crashguard-anchor.v2"
STATUS_SCHEMA = "cd.crashguard-status.v2"
MAX_RECORD_BYTES = 32 * 1024
MAX_STATUS_BYTES = 4 * 1024
MAX_HISTORY = 32
MAX_NONCES = 64
WALL_ROLLBACK_TOLERANCE_NS = 5 * 60 * 1_000_000_000


class StoreV2Error(RuntimeError):
    pass


def _fail(code: str) -> None:
    if code not in STORE_FAILURE_CODES:
        code = "CRASH_STORE_COMMIT_FAILED"
    raise StoreV2Error(code)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("SCHEMA_INVALID")


def _strict_json(raw: bytes, maximum: int) -> dict:
    if not 0 < len(raw) <= maximum:
        _fail("CRASH_STORE_OVERSIZE")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("SCHEMA_INVALID")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=pairs,
            parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()),
        )
    except StoreV2Error:
        raise
    except Exception:
        _fail("SCHEMA_INVALID")
    if type(value) is not dict:
        _fail("SCHEMA_INVALID")
    return value


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _reject_reparse(path: Path) -> None:
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                _fail("REPARSE_REJECTED")
    except FileNotFoundError:
        _fail("REPARSE_REJECTED")


def windows_acl_validator(path: Path) -> None:
    if os.name != "nt":
        _fail("ACL_REJECTED")
    try:
        import win32security as security

        descriptor = security.GetNamedSecurityInfo(
            str(path),
            security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
        )
        privileged = {
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        }
        if security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in privileged:
            _fail("ACL_REJECTED")
        dacl = descriptor.GetSecurityDescriptorDacl()
        if dacl is None:
            _fail("ACL_REJECTED")
        write_mask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            if ace[0][0] not in (0, 1):
                _fail("ACL_REJECTED")
            sid = security.ConvertSidToStringSid(ace[2])
            if ace[0][0] == 0 and sid not in privileged and int(ace[1]) & write_mask:
                _fail("ACL_REJECTED")
    except StoreV2Error:
        raise
    except Exception:
        _fail("ACL_REJECTED")


def _envelope(payload: dict, key: bytes) -> bytes:
    body = _canonical(payload)
    return _canonical({"payload": payload, "mac": hmac.new(key, body, hashlib.sha256).hexdigest()})


def _decode(raw: bytes, key: bytes, maximum: int) -> dict:
    envelope = _strict_json(raw, maximum)
    if set(envelope) != {"payload", "mac"} or type(envelope["payload"]) is not dict or type(envelope["mac"]) is not str:
        _fail("SCHEMA_INVALID")
    expected = hmac.new(key, _canonical(envelope["payload"]), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["mac"]):
        _fail("CRASH_STORE_AUTH_FAILED")
    return envelope["payload"]


def _move_replace(source: Path, target: Path) -> None:
    if os.name == "nt":
        import ctypes

        if not ctypes.windll.kernel32.MoveFileExW(str(source), str(target), 0x1 | 0x8):
            raise ctypes.WinError()
        descriptor = os.open(target, os.O_RDWR | getattr(os, "O_BINARY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        os.replace(source, target)


def _atomic_write(path: Path, payload: bytes, *, maximum: int) -> None:
    if not 0 < len(payload) <= maximum:
        _fail("CRASH_STORE_OVERSIZE")
    last_error: OSError | None = None
    for delay in (0.0, 0.01, 0.02, 0.04):
        temporary: Path | None = None
        try:
            descriptor, raw = tempfile.mkstemp(prefix=".cg2-", dir=path.parent)
            temporary = Path(raw)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _move_replace(temporary, path)
            return
        except OSError as exc:
            last_error = exc
            if exc.errno == errno.ENOSPC:
                _fail("CRASH_STORE_DISK_FULL")
            if delay:
                time.sleep(delay)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    _fail("LOCKED_BY_OWNER" if isinstance(last_error, PermissionError) else "CRASH_STORE_COMMIT_FAILED")


def fresh_record(service: str, *, boot_id: str, monotonic_ns: int, wall_time_ns: int) -> dict:
    return {
        "schema": RECORD_SCHEMA,
        "service": service,
        "revision": 0,
        "generation": 0,
        "lifecycle": Lifecycle.INIT.value,
        "health": Health.UNKNOWN.value,
        "boot_id": boot_id,
        "monotonic_ns": monotonic_ns,
        "wall_time_ns": wall_time_ns,
        "cumulative_failures": 0,
        "attempts_since_stable": 0,
        "recovery_budget_remaining": 0,
        "consumed_nonces": [],
        "failure_history": [],
        "last_failure_code": None,
        "runtime_identity": None,
        "migration": None,
    }


def validate_record(record: dict, service: str) -> None:
    expected = set(fresh_record(service, boot_id="boot", monotonic_ns=0, wall_time_ns=0))
    if type(record) is not dict or set(record) != expected:
        _fail("SCHEMA_INVALID")
    if record["schema"] != RECORD_SCHEMA or record["service"] != service:
        _fail("SCHEMA_INVALID")
    for name in (
        "revision",
        "generation",
        "monotonic_ns",
        "wall_time_ns",
        "cumulative_failures",
        "attempts_since_stable",
        "recovery_budget_remaining",
    ):
        if type(record[name]) is not int or not 0 <= record[name] < 2**63:
            _fail("SCHEMA_INVALID")
    if record["lifecycle"] not in {item.value for item in Lifecycle} or record["health"] not in {item.value for item in Health}:
        _fail("SCHEMA_INVALID")
    if type(record["boot_id"]) is not str or not 1 <= len(record["boot_id"]) <= 128 or not record["boot_id"].isascii():
        _fail("SCHEMA_INVALID")
    if type(record["consumed_nonces"]) is not list or len(record["consumed_nonces"]) > MAX_NONCES:
        _fail("SCHEMA_INVALID")
    if len(set(record["consumed_nonces"])) != len(record["consumed_nonces"]) or any(
        type(item) is not str or not 1 <= len(item) <= 128 or not item.isascii() for item in record["consumed_nonces"]
    ):
        _fail("SCHEMA_INVALID")
    if type(record["failure_history"]) is not list or len(record["failure_history"]) > MAX_HISTORY:
        _fail("SCHEMA_INVALID")
    for item in record["failure_history"]:
        if type(item) is not dict or set(item) != {"generation", "code"}:
            _fail("SCHEMA_INVALID")
        if type(item["generation"]) is not int or not 0 <= item["generation"] <= record["generation"]:
            _fail("SCHEMA_INVALID")
        if item["code"] not in FAILURE_CODES:
            _fail("SCHEMA_INVALID")
    if record["last_failure_code"] is not None and record["last_failure_code"] not in FAILURE_CODES:
        _fail("SCHEMA_INVALID")
    identity = record["runtime_identity"]
    if identity is not None:
        if type(identity) is not dict or set(identity) != {"pid", "executable_sha256", "start_time_ns"}:
            _fail("SCHEMA_INVALID")
        if type(identity["pid"]) is not int or not 1 <= identity["pid"] < 2**32:
            _fail("SCHEMA_INVALID")
        if type(identity["start_time_ns"]) is not int or not 0 <= identity["start_time_ns"] < 2**63:
            _fail("SCHEMA_INVALID")
        digest = identity["executable_sha256"]
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            _fail("SCHEMA_INVALID")
    migration = record["migration"]
    if migration is not None:
        migration_fields = {
            "source_schema",
            "source_state",
            "source_revision",
            "probes_used",
            "repair_count",
            "clean_stop",
            "active_attempt",
            "recent_failures",
        }
        if type(migration) is not dict or set(migration) != migration_fields:
            _fail("SCHEMA_INVALID")
        if migration["source_schema"] != "cd.service-crash.v1" or migration["source_state"] not in {
            "READY", "STARTING", "RUNNING", "LATCHED", "PROBE", "UNAVAILABLE"
        }:
            _fail("SCHEMA_INVALID")
        for name in ("source_revision", "probes_used", "repair_count"):
            if type(migration[name]) is not int or not 0 <= migration[name] < 2**63:
                _fail("SCHEMA_INVALID")
        if migration["source_revision"] > record["revision"] or migration["probes_used"] > 1:
            _fail("SCHEMA_INVALID")
        if type(migration["clean_stop"]) is not bool or type(migration["active_attempt"]) is not bool:
            _fail("SCHEMA_INVALID")
        if type(migration["recent_failures"]) is not list or len(migration["recent_failures"]) > MAX_HISTORY:
            _fail("SCHEMA_INVALID")
        for item in migration["recent_failures"]:
            if type(item) is not dict or set(item) != {"generation", "boot", "code", "tick"}:
                _fail("SCHEMA_INVALID")
            if type(item["generation"]) is not int or not 0 <= item["generation"] <= record["generation"]:
                _fail("SCHEMA_INVALID")
            if type(item["boot"]) is not str or len(item["boot"]) > 128 or any(
                character not in "0123456789abcdef-" for character in item["boot"]
            ):
                _fail("SCHEMA_INVALID")
            if type(item["code"]) is not str or not 1 <= len(item["code"]) <= 64 or not item["code"].isascii():
                _fail("SCHEMA_INVALID")
            if type(item["tick"]) not in (int, float) or not math.isfinite(item["tick"]) or not 0 <= item["tick"] <= 10**12:
                _fail("SCHEMA_INVALID")
        if record["cumulative_failures"] < len(migration["recent_failures"]):
            _fail("SCHEMA_INVALID")
    if len(_canonical(record)) > MAX_RECORD_BYTES // 2:
        _fail("CRASH_STORE_OVERSIZE")


def _status(record: dict) -> dict:
    return {
        "schema": STATUS_SCHEMA,
        "service": record["service"],
        "revision": record["revision"],
        "generation": record["generation"],
        "lifecycle": record["lifecycle"],
        "health": record["health"],
        "failure_code": record["last_failure_code"],
        "updated_wall_time_ns": record["wall_time_ns"],
    }


def read_status_snapshot(path: Path, key: bytes) -> dict:
    try:
        payload = _decode(Path(path).read_bytes(), key, MAX_STATUS_BYTES)
    except OSError:
        _fail("CRASH_STORE_STATUS_PUBLISH_FAILED")
    expected = {
        "schema", "service", "revision", "generation", "lifecycle", "health", "failure_code", "updated_wall_time_ns"
    }
    if set(payload) != expected or payload["schema"] != STATUS_SCHEMA:
        _fail("SCHEMA_INVALID")
    return payload


class StoreV2:
    def __init__(
        self,
        state_root: Path,
        anchor_root: Path,
        service: str,
        key: bytes,
        *,
        path_validator: Callable[[Path], None] = windows_acl_validator,
    ):
        if type(key) is not bytes or len(key) != 32 or not service or len(service) > 96:
            _fail("SCHEMA_INVALID")
        self.state_root = Path(state_root).absolute()
        self.anchor_root = Path(anchor_root).absolute()
        if self.state_root == self.anchor_root or _inside(self.anchor_root, self.state_root):
            _fail("SCHEMA_INVALID")
        self.service = service
        self.key = key
        self.path_validator = path_validator
        for root in (self.state_root, self.anchor_root):
            _reject_reparse(root)
            path_validator(root)
        self.slot_paths = tuple(self.state_root / f"{service}.{index}.json" for index in range(2))
        self.anchor_path = self.anchor_root / f"{service}.anchor"
        self.status_path = self.anchor_root / f"{service}.status.json"
        self.lock_path = self.anchor_root / f"{service}.writer.lock"
        self._lock_handle = None
        self._highwater = -1
        self._acquire_writer()

    def _acquire_writer(self) -> None:
        handle = None
        try:
            handle = self.lock_path.open("a+b")
            handle.seek(0, 2)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_handle = handle
        except Exception:
            try:
                if handle is not None:
                    handle.close()
            except Exception:
                pass
            _fail("LOCKED_BY_OWNER")

    def close(self) -> None:
        if self._lock_handle is None:
            return
        try:
            self._lock_handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._lock_handle.close()
            self._lock_handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def provision(self, record: dict) -> dict:
        if self.anchor_path.exists() or any(path.exists() for path in self.slot_paths):
            _fail("SCHEMA_INVALID")
        validate_record(record, self.service)
        slot = self.slot_paths[record["revision"] % 2]
        _atomic_write(slot, _envelope(record, self.key), maximum=MAX_RECORD_BYTES)
        anchor = self._anchor(record)
        _atomic_write(self.anchor_path, _envelope(anchor, self.key), maximum=MAX_RECORD_BYTES)
        self._highwater = record["revision"]
        self._publish_status(record)
        return self.load()

    def _anchor(self, record: dict) -> dict:
        return {
            "schema": ANCHOR_SCHEMA,
            "service": self.service,
            "revision": record["revision"],
            "slot": record["revision"] % 2,
            "digest": hashlib.sha256(_canonical(record)).hexdigest(),
            "boot_id": record["boot_id"],
            "monotonic_ns": record["monotonic_ns"],
            "wall_time_ns": record["wall_time_ns"],
        }

    def _read(self, path: Path, maximum: int = MAX_RECORD_BYTES) -> dict:
        try:
            _reject_reparse(path)
            self.path_validator(path)
            return _decode(path.read_bytes(), self.key, maximum)
        except StoreV2Error:
            raise
        except OSError:
            _fail("CRASH_STORE_COMMIT_FAILED")

    def load(self) -> dict:
        anchor = self._read(self.anchor_path)
        expected_anchor = {"schema", "service", "revision", "slot", "digest", "boot_id", "monotonic_ns", "wall_time_ns"}
        if set(anchor) != expected_anchor or anchor["schema"] != ANCHOR_SCHEMA or anchor["service"] != self.service:
            _fail("SCHEMA_INVALID")
        if type(anchor["revision"]) is not int or not 0 <= anchor["revision"] < 2**63 or anchor["slot"] != anchor["revision"] % 2:
            _fail("SCHEMA_INVALID")
        if anchor["revision"] < self._highwater:
            _fail("ROLLBACK_SUSPECTED")
        record = self._read(self.slot_paths[anchor["slot"]])
        validate_record(record, self.service)
        if record["revision"] != anchor["revision"] or not hmac.compare_digest(
            hashlib.sha256(_canonical(record)).hexdigest(), anchor["digest"]
        ):
            _fail("ROLLBACK_SUSPECTED")
        for name in ("boot_id", "monotonic_ns", "wall_time_ns"):
            if record[name] != anchor[name]:
                _fail("ROLLBACK_SUSPECTED")
        self._highwater = anchor["revision"]
        return copy.deepcopy(record)

    def write(self, record: dict) -> dict:
        old = self.load()
        candidate = copy.deepcopy(record)
        if candidate.get("revision") != old["revision"]:
            _fail("ROLLBACK_SUSPECTED")
        candidate["revision"] += 1
        validate_record(candidate, self.service)
        if candidate["generation"] < old["generation"]:
            _fail("ROLLBACK_SUSPECTED")
        if candidate["boot_id"] == old["boot_id"] and candidate["monotonic_ns"] < old["monotonic_ns"]:
            _fail("ROLLBACK_SUSPECTED")
        if candidate["wall_time_ns"] + WALL_ROLLBACK_TOLERANCE_NS < old["wall_time_ns"]:
            _fail("ROLLBACK_SUSPECTED")
        slot = self.slot_paths[candidate["revision"] % 2]
        _atomic_write(slot, _envelope(candidate, self.key), maximum=MAX_RECORD_BYTES)
        _atomic_write(self.anchor_path, _envelope(self._anchor(candidate), self.key), maximum=MAX_RECORD_BYTES)
        self._highwater = candidate["revision"]
        self._publish_status(candidate)
        return self.load()

    def _publish_status(self, record: dict) -> None:
        try:
            _atomic_write(self.status_path, _envelope(_status(record), self.key), maximum=MAX_STATUS_BYTES)
        except StoreV2Error:
            _fail("CRASH_STORE_STATUS_PUBLISH_FAILED")

