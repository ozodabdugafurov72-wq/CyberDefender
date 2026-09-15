from __future__ import annotations

import json
import math
import ntpath
import os
import time
from typing import Any

MAX_BYTES = 12 * 1024 * 1024
MAX_PROCESSES = 5000
EPOCH_TICKS = 116_444_736_000_000_000

TOP_KEYS = {
    "schema",
    "sensor",
    "version",
    "timestamp",
    "partial",
    "skipped",
    "process_count",
    "ipc",
    "enrichment_provenance",
    "processes",
    "skipped_processes",
}

ROW_KEYS = {
    "pid",
    "ppid",
    "name",
    "create_time",
    "creation_filetime",
    "exe",
    "username",
    "cmdline",
    "sid",
    "session_id",
    "integrity_level",
    "cpu_percent",
    "memory_percent",
    "enrichment_status",
}

STATUS_FIELDS = {
    "exe",
    "username",
    "sid",
    "cmdline",
    "session_id",
    "integrity_level",
    "cpu_percent",
    "memory_percent",
}

ALLOWED_STATUSES = {
    "COLLECTED",
    "ACCESS_DENIED",
    "QUERY_FAILED",
    "UNAVAILABLE",
    "NOT_COLLECTED_V05_CORE",
}

INTEGRITY_LEVELS = {
    "UNTRUSTED",
    "LOW",
    "MEDIUM",
    "MEDIUM_PLUS",
    "HIGH",
    "SYSTEM",
    "PROTECTED",
    "UNKNOWN",
}

PROVENANCE = {
    "exe": {"source": "QueryFullProcessImageNameW", "confidence": "HIGH"},
    "cmdline": {
        "source": "NtQueryInformationProcess+CommandLineToArgvW",
        "confidence": "HIGH_WHEN_COLLECTED",
    },
    "username": {
        "source": "OpenProcessToken+LookupAccountSidW",
        "confidence": "HIGH_WHEN_COLLECTED",
    },
    "sid": {
        "source": "OpenProcessToken+ConvertSidToStringSidW",
        "confidence": "HIGH_WHEN_COLLECTED",
    },
    "session_id": {
        "source": "ProcessIdToSessionId",
        "confidence": "HIGH_WHEN_COLLECTED",
    },
    "integrity_level": {
        "source": "TokenIntegrityLevel",
        "confidence": "HIGH_WHEN_COLLECTED",
    },
    "cpu_percent": {
        "source": "DEFERRED_TO_PERSISTENT_METRICS_TIER",
        "confidence": "NOT_AVAILABLE_V05_CORE",
    },
    "memory_percent": {
        "source": "DEFERRED_TO_PERSISTENT_METRICS_TIER",
        "confidence": "NOT_AVAILABLE_V05_CORE",
    },
}


class RustProcessV05Error(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RustProcessV05Error("duplicate JSON key")
        result[key] = value
    return result


def _number(value: Any) -> bool:
    return type(value) in {int, float} and not isinstance(value, bool) and math.isfinite(float(value))


def _valid_text(value: Any, *, max_chars: int, allow_empty: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    if not allow_empty and not value:
        return False
    return len(value) <= max_chars and "\x00" not in value


def _validate_status_map(row: dict[str, Any]) -> None:
    status_map = row.get("enrichment_status")
    if type(status_map) is not dict or set(status_map) != STATUS_FIELDS:
        raise RustProcessV05Error("invalid enrichment status map")

    for field in STATUS_FIELDS:
        item = status_map[field]
        if type(item) is not dict or set(item) != {"status"}:
            raise RustProcessV05Error("invalid enrichment status entry")
        status = item.get("status")
        if status not in ALLOWED_STATUSES:
            raise RustProcessV05Error("unknown enrichment status")

        value = row.get(field)
        if field in {"cpu_percent", "memory_percent"}:
            if value is not None or status != "NOT_COLLECTED_V05_CORE":
                raise RustProcessV05Error("v0.5 core metric contract mismatch")
            continue

        if status == "COLLECTED" and value is None:
            raise RustProcessV05Error("collected enrichment is null")
        if status != "COLLECTED" and value is not None:
            raise RustProcessV05Error("uncollected enrichment carries value")


def validate_v05_snapshot(
    raw: bytes | bytearray | str | dict[str, Any],
    *,
    now: float | None = None,
    require_ipc: bool | None = None,
    expected_sequence: int | None = None,
    expected_epoch: str | None = None,
    expected_supervisor_pid: int | None = None,
    expected_sensor_pid: int | None = None,
) -> dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    else:
        if isinstance(raw, str):
            encoded = raw.encode("utf-8")
        elif isinstance(raw, (bytes, bytearray)):
            encoded = bytes(raw)
        else:
            raise RustProcessV05Error("invalid snapshot type")

        if not encoded or len(encoded) > MAX_BYTES:
            raise RustProcessV05Error("snapshot size rejected")
        try:
            data = json.loads(
                encoded.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    RustProcessV05Error(f"non-finite JSON constant: {value}")
                ),
            )
        except RustProcessV05Error:
            raise
        except Exception as exc:
            raise RustProcessV05Error("invalid JSON") from exc

    if type(data) is not dict or set(data) != TOP_KEYS:
        raise RustProcessV05Error("invalid top-level schema")
    if data.get("schema") != "cd.process.v5":
        raise RustProcessV05Error("schema mismatch")
    if data.get("sensor") != "RustProcessSensor":
        raise RustProcessV05Error("sensor mismatch")
    if data.get("version") != "0.5.1":
        raise RustProcessV05Error("version mismatch")

    stamp = data.get("timestamp")
    if not _number(stamp):
        raise RustProcessV05Error("invalid timestamp")
    stamp = float(stamp)
    reference_now = time.time() if now is None else float(now)
    if abs(stamp - reference_now) > 30.0:
        raise RustProcessV05Error("stale/future snapshot")

    partial = data.get("partial")
    skipped = data.get("skipped")
    count = data.get("process_count")
    if type(partial) is not bool:
        raise RustProcessV05Error("invalid partial flag")
    if type(skipped) is not int or skipped < 0:
        raise RustProcessV05Error("invalid skipped count")
    if type(count) is not int or not 0 <= count <= MAX_PROCESSES:
        raise RustProcessV05Error("invalid process count")
    if partial != (skipped > 0):
        raise RustProcessV05Error("partial/skipped mismatch")

    provenance = data.get("enrichment_provenance")
    if provenance != PROVENANCE:
        raise RustProcessV05Error("enrichment provenance mismatch")

    ipc = data.get("ipc")
    if require_ipc is True and not isinstance(ipc, dict):
        raise RustProcessV05Error("IPC metadata required")
    if require_ipc is False and ipc is not None:
        raise RustProcessV05Error("unexpected IPC metadata")
    if ipc is not None:
        if type(ipc) is not dict or set(ipc) != {
            "protocol",
            "version",
            "sequence",
            "sensor_epoch",
            "supervisor_pid",
            "sensor_pid",
        }:
            raise RustProcessV05Error("invalid IPC metadata")
        if ipc.get("protocol") != "cd.sensor.ipc.v1" or ipc.get("version") != 1:
            raise RustProcessV05Error("IPC protocol mismatch")
        sequence = ipc.get("sequence")
        supervisor_pid = ipc.get("supervisor_pid")
        sensor_pid = ipc.get("sensor_pid")
        epoch = ipc.get("sensor_epoch")
        if type(sequence) is not int or sequence <= 0:
            raise RustProcessV05Error("invalid IPC sequence")
        if expected_sequence is not None and sequence != expected_sequence:
            raise RustProcessV05Error("IPC sequence mismatch")
        if type(supervisor_pid) is not int or supervisor_pid <= 0:
            raise RustProcessV05Error("invalid supervisor PID")
        if expected_supervisor_pid is not None and supervisor_pid != expected_supervisor_pid:
            raise RustProcessV05Error("supervisor PID mismatch")
        if type(sensor_pid) is not int or sensor_pid <= 0:
            raise RustProcessV05Error("invalid sensor PID")
        if expected_sensor_pid is not None and sensor_pid != expected_sensor_pid:
            raise RustProcessV05Error("sensor PID mismatch")
        if not _valid_text(epoch, max_chars=128):
            raise RustProcessV05Error("invalid sensor epoch")
        if expected_epoch is not None and epoch != expected_epoch:
            raise RustProcessV05Error("sensor epoch mismatch")

    rows = data.get("processes")
    diagnostics = data.get("skipped_processes")
    if type(rows) is not list or len(rows) != count:
        raise RustProcessV05Error("process count mismatch")
    if type(diagnostics) is not list or len(diagnostics) != skipped:
        raise RustProcessV05Error("skipped diagnostic count mismatch")
    if count + skipped > MAX_PROCESSES:
        raise RustProcessV05Error("combined process limit exceeded")

    seen: set[int] = set()
    for row in rows:
        if type(row) is not dict or set(row) != ROW_KEYS:
            raise RustProcessV05Error("invalid process schema")
        pid = row.get("pid")
        ppid = row.get("ppid")
        if type(pid) is not int or not 0 <= pid <= 0xFFFFFFFF:
            raise RustProcessV05Error("invalid PID")
        if type(ppid) is not int or not 0 <= ppid <= 0xFFFFFFFF:
            raise RustProcessV05Error("invalid PPID")
        if pid in seen:
            raise RustProcessV05Error("duplicate PID")
        seen.add(pid)

        name = row.get("name")
        try:
            valid_name = type(name) is str and 0 < len(name.encode("utf-16-le")) <= 520
        except UnicodeError:
            valid_name = False
        if not valid_name:
            raise RustProcessV05Error("invalid process name")

        ticks_text = row.get("creation_filetime")
        if (
            type(ticks_text) is not str
            or not ticks_text.isascii()
            or not ticks_text.isdecimal()
            or not 1 <= len(ticks_text) <= 20
        ):
            raise RustProcessV05Error("invalid creation ticks")
        ticks = int(ticks_text)
        if not EPOCH_TICKS <= ticks <= 0xFFFFFFFFFFFFFFFF:
            raise RustProcessV05Error("invalid creation epoch")

        created = row.get("create_time")
        expected_created = (ticks - EPOCH_TICKS) / 10_000_000.0
        if (
            not _number(created)
            or abs(float(created) - expected_created) > 0.000001
            or float(created) > stamp + 0.000001
        ):
            raise RustProcessV05Error("creation time mismatch")
        row["create_time"] = expected_created

        exe = row.get("exe")
        if exe is not None and not _valid_text(exe, max_chars=32768):
            raise RustProcessV05Error("invalid executable path")
        username = row.get("username")
        if username is not None and not _valid_text(username, max_chars=2048):
            raise RustProcessV05Error("invalid username")
        sid = row.get("sid")
        if sid is not None and (
            not _valid_text(sid, max_chars=512)
            or not sid.startswith("S-")
        ):
            raise RustProcessV05Error("invalid SID")
        session_id = row.get("session_id")
        if session_id is not None and (
            type(session_id) is not int or not 0 <= session_id <= 0xFFFFFFFF
        ):
            raise RustProcessV05Error("invalid session id")
        integrity = row.get("integrity_level")
        if integrity is not None and integrity not in INTEGRITY_LEVELS:
            raise RustProcessV05Error("invalid integrity level")

        cmdline = row.get("cmdline")
        if cmdline is not None:
            if type(cmdline) is not list or len(cmdline) > 4096:
                raise RustProcessV05Error("invalid command line")
            total = 0
            for arg in cmdline:
                if not isinstance(arg, str) or "\x00" in arg or len(arg) > 32768:
                    raise RustProcessV05Error("invalid command line argument")
                total += len(arg)
                if total > 131072:
                    raise RustProcessV05Error("command line too large")

        _validate_status_map(row)

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
            raise RustProcessV05Error("invalid skipped diagnostic")
        pid = item.get("pid")
        reason = item.get("reason")
        code = item.get("win32_error")
        if type(pid) is not int or not 0 <= pid <= 0xFFFFFFFF or pid in seen:
            raise RustProcessV05Error("duplicate/invalid skipped PID")
        seen.add(pid)
        if reason not in api_reasons | local_reasons:
            raise RustProcessV05Error("unknown skip reason")
        if reason in api_reasons:
            if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
                raise RustProcessV05Error("invalid Windows error code")
            if reason == "OPEN_ACCESS_DENIED" and code != 5:
                raise RustProcessV05Error("access denied code mismatch")
            if reason == "SYSTEM_IDLE_UNQUERYABLE" and (pid != 0 or code != 87):
                raise RustProcessV05Error("system idle coverage code mismatch")
            if reason == "OPEN_FAILED" and code == 5:
                raise RustProcessV05Error("access denied misclassified")
            if reason == "OPEN_FAILED" and pid == 0 and code == 87:
                raise RustProcessV05Error("system idle limitation misclassified")
        elif code is not None:
            raise RustProcessV05Error("non-API failure has stale error")

    return data


def _path_norm(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return ntpath.normcase(ntpath.normpath(value))


def _windows_image_kind(value: Any) -> str:
    """Classify a Windows image value without trusting non-empty text as a path.

    psutil can expose kernel pseudo-process tokens such as ``MemCompression``
    through its ``exe`` field. Those tokens are useful telemetry but are not
    filesystem/device image paths and must not participate in executable-path
    parity or block the narrow Windows pseudo-process name policy.
    """
    if not isinstance(value, str):
        return "MISSING"
    text = value.strip()
    if not text:
        return "MISSING"

    normalized = text.replace("/", "\\")
    drive, _ = ntpath.splitdrive(normalized)
    path_prefixes = (
        "\\\\",          # UNC
        "\\Device\\",
        "\\SystemRoot\\",
        "\\??\\",
        "\\GLOBALROOT\\",
    )
    if drive or "\\" in normalized or normalized.startswith(path_prefixes):
        return "PATH_LIKE"
    return "PSEUDO_TOKEN"


def _image_path_norm(value: Any) -> str | None:
    if _windows_image_kind(value) != "PATH_LIKE":
        return None
    return _path_norm(value)


def _pseudo_image_token_norm(value: Any) -> str | None:
    if _windows_image_kind(value) != "PSEUDO_TOKEN":
        return None
    return _name_norm(value)


def _user_norm(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.replace("/", "\\").strip().casefold()


def _sid_norm(value: Any) -> str | None:
    """Normalize a textual Windows SID without guessing account names.

    User/account names are display labels and can vary by Windows locale or
    account-name resolution context.  A collected token SID is the stronger
    principal identity evidence.  We accept only strict S-<rev>-<authority>-...
    decimal syntax; malformed or missing SID evidence can never suppress a
    username mismatch.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    parts = text.split("-")
    if len(parts) < 4 or parts[0] != "S":
        return None
    try:
        revision = int(parts[1], 10)
        authority = int(parts[2], 10)
        subauth = [int(part, 10) for part in parts[3:]]
    except (TypeError, ValueError):
        return None
    if revision < 0 or authority < 0 or any(item < 0 for item in subauth):
        return None
    return text


def _resolve_windows_username_sid(value: Any) -> str | None:
    """Resolve a Windows account display name to its canonical SID.

    This is used only as a *secondary parity proof* when Python/psutil and
    native LookupAccountSidW return different display labels for the already
    PID/create_time-aligned process.  Failure to resolve is fail-closed: the
    username mismatch remains hard.
    """
    if os.name != "nt" or not isinstance(value, str) or not value.strip():
        return None
    try:
        import win32security  # type: ignore

        sid_obj, _domain, _account_type = win32security.LookupAccountName(
            None, value.strip()
        )
        return _sid_norm(win32security.ConvertSidToStringSid(sid_obj))
    except Exception:
        return None


def _cmd_norm(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    return tuple(str(item) for item in value)


def _name_norm(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return ntpath.basename(value).casefold()


def _canonical_process_name(row: dict[str, Any]) -> str | None:
    """Canonical display/detection name with image-path semantics.

    A real Windows image path is preferred. A non-empty pseudo token in an
    ``exe`` field (for example psutil's ``MemCompression`` observation) is not
    treated as an image path; raw process name remains the display fallback.
    """
    exe_name = None
    if _windows_image_kind(row.get("exe")) == "PATH_LIKE":
        exe_name = _name_norm(row.get("exe"))
    if exe_name:
        return exe_name
    return _name_norm(row.get("name"))


def _known_windows_exeless_name_equivalence(
    py: dict[str, Any],
    rust: dict[str, Any],
) -> str | None:
    """Return a narrow Windows pseudo-process alias classification.

    This is intentionally *not* a generic fuzzy-name matcher. It is only
    reachable when neither side has a real executable image path. A narrowly
    recognized psutil pseudo-image token may be present on the Python side.
    Normal user-mode image-backed processes therefore cannot gain equivalence
    merely by choosing a similar display name. PID/create_time and parent
    parity are checked by the caller before this classification is considered.
    """
    py_image_kind = _windows_image_kind(py.get("exe"))
    rust_image_kind = _windows_image_kind(rust.get("exe"))
    if py_image_kind == "PATH_LIKE":
        return None
    if rust_image_kind == "PATH_LIKE":
        return None

    rust_exe_status = (
        rust.get("enrichment_status", {})
        .get("exe", {})
        .get("status")
    )
    if rust_exe_status == "COLLECTED":
        return None

    py_name = _name_norm(py.get("name"))
    rust_name = _name_norm(rust.get("name"))
    py_pseudo_exe = _pseudo_image_token_norm(py.get("exe"))

    # Windows memory compression is surfaced as ``MemCompression`` by psutil
    # on some systems while Toolhelp32 reports ``Memory Compression``. psutil
    # may also place the pseudo token ``MemCompression`` in ``exe``; accept
    # only that exact token (or no exe value), never an arbitrary token/path.
    if py_name == "memcompression" and rust_name == "memory compression":
        if py_pseudo_exe in {None, "memcompression"}:
            return "WINDOWS_MEMORY_COMPRESSION_PSEUDO_IMAGE_ALIAS"

    # psutil can expose an empty display name for the VBS/VSM Secure System
    # pseudo-process while Toolhelp32 still exposes ``Secure System``.  Keep
    # the observed direction and require no Python pseudo-image token.
    if (
        py_name is None
        and rust_name == "secure system"
        and py_pseudo_exe is None
    ):
        return "WINDOWS_SECURE_SYSTEM_NAME_GAP"

    return None


def compare_enrichment(
    python_snapshot: dict[str, Any],
    rust_snapshot: dict[str, Any],
) -> dict[str, Any]:
    py_rows = python_snapshot.get("processes", [])
    rust_rows = rust_snapshot.get("processes", [])
    if not isinstance(py_rows, list) or not isinstance(rust_rows, list):
        raise RustProcessV05Error("comparison snapshot rejected")

    py_by_pid: dict[int, dict[str, Any]] = {}
    for row in py_rows:
        if not isinstance(row, dict):
            continue
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            continue
        if pid < 0 or pid in py_by_pid:
            continue
        py_by_pid[pid] = row

    rust_by_pid = {
        row["pid"]: row
        for row in rust_rows
        if isinstance(row, dict) and type(row.get("pid")) is int
    }

    common = sorted(set(py_by_pid) & set(rust_by_pid))
    identity_mismatch: list[int] = []
    parent_mismatch: list[int] = []
    raw_name_differences: list[dict[str, Any]] = []
    known_system_name_aliases: list[dict[str, Any]] = []
    python_pseudo_image_tokens: list[dict[str, Any]] = []
    canonical_name_conflicts: list[dict[str, Any]] = []
    canonical_name_matches = 0

    fields = {
        "exe": {"python_available": 0, "rust_collected": 0, "matches": 0, "mismatches": 0, "missing": 0, "examples": []},
        "username": {
            "python_available": 0,
            "rust_collected": 0,
            "matches": 0,
            "exact_matches": 0,
            "sid_backed_display_variants": 0,
            "mismatches": 0,
            "missing": 0,
            "examples": [],
            "display_variant_examples": [],
            "semantics": (
                "username is a display label; a differing label is accepted only "
                "when the same PID/create_time has a syntactically valid COLLECTED "
                "native token SID; otherwise the mismatch remains hard"
            ),
        },
        "cmdline": {"python_available": 0, "rust_collected": 0, "matches": 0, "mismatches": 0, "missing": 0, "examples": []},
    }

    for pid in common:
        py = py_by_pid[pid]
        rust = rust_by_pid[pid]
        try:
            py_created = float(py.get("create_time"))
            rust_created = float(rust.get("create_time"))
        except (TypeError, ValueError, OverflowError):
            identity_mismatch.append(pid)
            continue
        if f"{py_created:.6f}" != f"{rust_created:.6f}":
            identity_mismatch.append(pid)
            continue

        try:
            if int(py.get("ppid")) != int(rust.get("ppid")):
                parent_mismatch.append(pid)
        except (TypeError, ValueError):
            parent_mismatch.append(pid)

        py_raw_name = _name_norm(py.get("name"))
        rust_raw_name = _name_norm(rust.get("name"))
        py_canonical_name = _canonical_process_name(py)
        rust_canonical_name = _canonical_process_name(rust)

        if _windows_image_kind(py.get("exe")) == "PSEUDO_TOKEN":
            if len(python_pseudo_image_tokens) < 20:
                python_pseudo_image_tokens.append({
                    "pid": pid,
                    "python_name": py.get("name"),
                    "python_exe_token": py.get("exe"),
                })

        if py_raw_name != rust_raw_name:
            if len(raw_name_differences) < 20:
                raw_name_differences.append({
                    "pid": pid,
                    "python_name": py.get("name"),
                    "rust_name": rust.get("name"),
                    "python_exe": py.get("exe"),
                    "rust_exe": rust.get("exe"),
                    "python_canonical": py_canonical_name,
                    "rust_canonical": rust_canonical_name,
                })

        if py_raw_name != rust_raw_name:
            system_alias = _known_windows_exeless_name_equivalence(py, rust)
        else:
            system_alias = None

        if system_alias is not None:
            if len(known_system_name_aliases) < 20:
                known_system_name_aliases.append({
                    "pid": pid,
                    "classification": system_alias,
                    "python_name": py.get("name"),
                    "rust_name": rust.get("name"),
                    "python_exe": py.get("exe"),
                    "rust_exe": rust.get("exe"),
                    "rust_exe_status": (
                        rust.get("enrichment_status", {})
                        .get("exe", {})
                        .get("status")
                    ),
                    "python_canonical": py_canonical_name,
                    "rust_canonical": rust_canonical_name,
                })
        elif (
            py_canonical_name is not None
            and rust_canonical_name is not None
        ):
            if py_canonical_name == rust_canonical_name:
                canonical_name_matches += 1
            elif len(canonical_name_conflicts) < 20:
                canonical_name_conflicts.append({
                    "pid": pid,
                    "reason": "CANONICAL_NAME_CONFLICT",
                    "python_name": py.get("name"),
                    "rust_name": rust.get("name"),
                    "python_exe": py.get("exe"),
                    "rust_exe": rust.get("exe"),
                    "python_canonical": py_canonical_name,
                    "rust_canonical": rust_canonical_name,
                })
        elif py_raw_name != rust_raw_name:
            # One side has no usable canonical display name and this is not a
            # narrowly allowlisted Windows pseudo-process semantic.  Keep it a
            # hard review signal rather than silently treating missing evidence
            # as parity.
            if len(canonical_name_conflicts) < 20:
                canonical_name_conflicts.append({
                    "pid": pid,
                    "reason": "UNRESOLVED_EXELESS_NAME_SEMANTICS",
                    "python_name": py.get("name"),
                    "rust_name": rust.get("name"),
                    "python_exe": py.get("exe"),
                    "rust_exe": rust.get("exe"),
                    "python_canonical": py_canonical_name,
                    "rust_canonical": rust_canonical_name,
                })

        comparisons = {
            "exe": (_image_path_norm(py.get("exe")), _image_path_norm(rust.get("exe"))),
            "username": (_user_norm(py.get("username")), _user_norm(rust.get("username"))),
            "cmdline": (_cmd_norm(py.get("cmdline")), _cmd_norm(rust.get("cmdline"))),
        }

        for field, (py_value, rust_value) in comparisons.items():
            stat = fields[field]
            if py_value is None:
                continue
            stat["python_available"] += 1
            status_map = rust.get("enrichment_status", {})
            rust_status = status_map.get(field, {}).get("status") if isinstance(status_map, dict) else None
            if rust_status == "COLLECTED" and rust_value is not None:
                stat["rust_collected"] += 1
                if rust_value == py_value:
                    stat["matches"] += 1
                    if field == "username":
                        stat["exact_matches"] += 1
                elif field == "username":
                    # Windows account names are display labels.  The same
                    # principal can resolve to different localized/contextual
                    # strings (especially under LocalSystem).  We do *not* trust
                    # a string mismatch merely because Rust has some SID.
                    # Instead, resolve the Python/psutil username to a SID and
                    # require exact equality with the collected Rust token SID.
                    sid_status = (
                        status_map.get("sid", {}).get("status")
                        if isinstance(status_map, dict)
                        else None
                    )
                    rust_sid = _sid_norm(rust.get("sid"))
                    python_sid = _resolve_windows_username_sid(py.get("username"))
                    if (
                        sid_status == "COLLECTED"
                        and rust_sid is not None
                        and python_sid is not None
                        and python_sid == rust_sid
                    ):
                        stat["matches"] += 1
                        stat["sid_backed_display_variants"] += 1
                        if len(stat["display_variant_examples"]) < 10:
                            stat["display_variant_examples"].append({
                                "pid": pid,
                                "python_username": py.get("username"),
                                "rust_username": rust.get("username"),
                                "principal_sid": rust_sid,
                                "classification": "SID_VERIFIED_USERNAME_DISPLAY_VARIANT",
                            })
                    else:
                        stat["mismatches"] += 1
                        if len(stat["examples"]) < 10:
                            stat["examples"].append({
                                "pid": pid,
                                "python_username": py.get("username"),
                                "rust_username": rust.get("username"),
                                "python_resolved_sid": python_sid,
                                "rust_sid": rust.get("sid"),
                                "rust_sid_status": sid_status,
                            })
                else:
                    stat["mismatches"] += 1
                    if len(stat["examples"]) < 10:
                        stat["examples"].append(pid)
            else:
                stat["missing"] += 1

    any_authority_mismatch = bool(identity_mismatch or parent_mismatch)
    any_enrichment_mismatch = (
        bool(canonical_name_conflicts)
        or any(stat["mismatches"] for stat in fields.values())
    )
    coverage_gap = any(stat["missing"] for stat in fields.values())

    # Raw Windows process names are not identity. Toolhelp32 and psutil can
    # expose different display-name semantics for special/native processes.
    # Canonical-name conflicts remain observable, while executable-path
    # mismatches are already a hard REVIEW_REQUIRED condition above.
    if any_authority_mismatch or any_enrichment_mismatch:
        verdict = "REVIEW_REQUIRED"
    elif coverage_gap:
        verdict = "ENRICHMENT_ALIGNED_WITH_COVERAGE_GAPS"
    elif fields["username"].get("sid_backed_display_variants", 0):
        verdict = "ENRICHMENT_ALIGNED_WITH_SID_BACKED_USERNAME_VARIANTS"
    elif known_system_name_aliases:
        verdict = "ENRICHMENT_ALIGNED_WITH_SYSTEM_NAME_ALIASES"
    elif raw_name_differences:
        verdict = "ENRICHMENT_ALIGNED_WITH_NAME_VARIANTS"
    else:
        verdict = "ENRICHMENT_ALIGNED"

    for stat in fields.values():
        available = stat["python_available"]
        collected = stat["rust_collected"]
        comparable = stat["matches"] + stat["mismatches"]
        stat["coverage_rate"] = (collected / available) if available else None
        stat["parity_rate"] = (stat["matches"] / comparable) if comparable else None

    return {
        "schema": "cd.process.enrichment-comparison.v1.5",
        "verdict": verdict,
        "python_process_count": len(py_by_pid),
        "rust_process_count": len(rust_by_pid),
        "common_processes": len(common),
        "identity_disagreements": {"count": len(identity_mismatch), "examples": identity_mismatch[:10]},
        "parent_disagreements": {"count": len(parent_mismatch), "examples": parent_mismatch[:10]},
        "name_disagreements": {
            "count": len(canonical_name_conflicts),
            "examples": [item["pid"] for item in canonical_name_conflicts[:10]],
            "semantics": "canonical-name conflicts; raw display-name variants are separate telemetry",
        },
        "raw_name_differences": {
            "count": len(raw_name_differences),
            "examples": raw_name_differences,
        },
        "canonical_name_matches": canonical_name_matches,
        "known_system_name_aliases": {
            "count": len(known_system_name_aliases),
            "examples": known_system_name_aliases,
            "policy": (
                "exact allowlist only; no real image path; narrowly recognized "
                "pseudo-image token allowed; never used as PID/create_time identity"
            ),
        },
        "python_pseudo_image_tokens": {
            "count": len(python_pseudo_image_tokens),
            "examples": python_pseudo_image_tokens,
            "semantics": "non-path psutil exe values; excluded from executable-path parity",
        },
        "canonical_name_conflicts": {
            "count": len(canonical_name_conflicts),
            "examples": canonical_name_conflicts,
        },
        "fields": fields,
        "rust_partial": bool(rust_snapshot.get("partial")),
        "rust_skipped": int(rust_snapshot.get("skipped", 0)),
    }

