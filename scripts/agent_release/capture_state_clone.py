from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import BinaryIO, Callable, NamedTuple


MAX_TOTAL_BYTES = 64 * 1024 * 1024
COPY_RETRIES = 3
COPY_RETRY_SECONDS = 2.0
CHUNK_BYTES = 1024 * 1024
_MARKER_RE = re.compile(
    r"^(?:clone_begin|clone_item:\d+:[a-z0-9_]+:\d+|clone_done|"
    r"STAGE_TIMEOUT:[a-z0-9_]+|worker_finished:[A-Z0-9_]+)$"
)


class CopySpec(NamedTuple):
    relative_path: str
    file_class: str
    required: bool


COPY_SPECS = (
    CopySpec("keys/key_state.json", "key_state", True),
    CopySpec("keys/key_state.mac", "key_mac", True),
    CopySpec("spool/pending.jsonl", "spool_pending", True),
    CopySpec("spool/acked.jsonl", "spool_ack_journal", True),
    CopySpec("spool/acked_state.json", "spool_ack_state", True),
    CopySpec("spool/quarantined.jsonl", "spool_quarantine", True),
    # Runtime health reads the incident outbox through CorrelationAdapter.
    CopySpec("incident_outbox/incident_outbox.jsonl", "incident_outbox", False),
    CopySpec("state.json", "event_state", False),
)


class CloneFailure(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def append_marker(path: Path, code: str) -> None:
    if not _MARKER_RE.fullmatch(code):
        raise CloneFailure("CLONE_MARKER_REJECTED")
    raw = f"{_utc()}|{code}\n".encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def _open_shared_read(path: Path) -> BinaryIO:
    if os.name != "nt":
        return path.open("rb")
    import msvcrt

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002 | 0x00000004,  # READ | WRITE | DELETE sharing
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise
    return os.fdopen(fd, "rb", closefd=True)


def _has_reparse_point(path: Path) -> bool:
    info = os.lstat(path)
    attributes = getattr(info, "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _reject_reparse_chain(root: Path, target: Path) -> None:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(target))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise CloneFailure("CLONE_SOURCE_OUTSIDE_ROOT") from exc
    current = root
    if _has_reparse_point(current):
        raise CloneFailure("CLONE_REPARSE_REJECTED")
    for part in relative.parts:
        current = current / part
        if _has_reparse_point(current):
            raise CloneFailure("CLONE_REPARSE_REJECTED")


def _deadline_check(deadline: float, monotonic: Callable[[], float]) -> None:
    if monotonic() >= deadline:
        raise CloneFailure("STAGE_TIMEOUT:clone")


def _copy_and_hash(
    source: Path,
    destination: Path,
    file_class: str,
    *,
    deadline: float,
    open_reader: Callable[[Path], BinaryIO],
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    remaining_budget: int,
) -> tuple[int, str]:
    last_lock = False
    for attempt in range(COPY_RETRIES):
        _deadline_check(deadline, monotonic)
        digest = hashlib.sha256()
        copied = 0
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with open_reader(source) as src, destination.open("wb") as dst:
                while True:
                    _deadline_check(deadline, monotonic)
                    chunk = src.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    if copied + len(chunk) > remaining_budget:
                        raise CloneFailure("CLONE_TOO_LARGE")
                    dst.write(chunk)
                    digest.update(chunk)
                    copied += len(chunk)
                dst.flush()
                os.fsync(dst.fileno())
            return copied, digest.hexdigest()
        except OSError as exc:
            destination.unlink(missing_ok=True)
            last_lock = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in {32, 33}
            if not last_lock:
                raise CloneFailure(f"CLONE_COPY_FAILED:{file_class}") from exc
            if attempt + 1 < COPY_RETRIES:
                sleep(COPY_RETRY_SECONDS)
    if last_lock:
        raise CloneFailure(f"CLONE_FILE_LOCKED:{file_class}")
    raise CloneFailure(f"CLONE_COPY_FAILED:{file_class}")


def _hash_source(
    path: Path,
    *,
    deadline: float,
    open_reader: Callable[[Path], BinaryIO],
    monotonic: Callable[[], float],
) -> str:
    digest = hashlib.sha256()
    with open_reader(path) as handle:
        while True:
            _deadline_check(deadline, monotonic)
            chunk = handle.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def clone_state(
    live_state: Path,
    clone_root: Path,
    stage_file: Path,
    result_path: Path,
    *,
    live_key: Path | None = None,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    stage_timeout_seconds: int = 90,
    open_reader: Callable[[Path], BinaryIO] = _open_shared_read,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict:
    if max_total_bytes <= 0 or stage_timeout_seconds <= 0:
        raise CloneFailure("CLONE_POLICY_INVALID")
    live_state = Path(os.path.abspath(live_state))
    clone_root = Path(os.path.abspath(clone_root))
    stage_file = stage_file.resolve(strict=True)
    result_path = result_path.resolve()
    if not live_state.is_dir():
        raise CloneFailure("CLONE_STATE_ROOT_MISSING")
    _reject_reparse_chain(live_state, live_state)
    deadline = monotonic() + stage_timeout_seconds
    append_marker(stage_file, "clone_begin")
    selected: list[tuple[Path, Path, str, str]] = []
    for spec in COPY_SPECS:
        source = live_state / Path(spec.relative_path)
        if not source.exists():
            if spec.required:
                raise CloneFailure(f"CLONE_REQUIRED_MISSING:{spec.file_class}")
            continue
        _reject_reparse_chain(live_state, source)
        if not source.is_file():
            raise CloneFailure(f"CLONE_SOURCE_REJECTED:{spec.file_class}")
        selected.append((source, clone_root / "state" / Path(spec.relative_path), spec.file_class, f"state/{spec.relative_path}"))
    if live_key is not None:
        key_root = live_state.parent
        key = Path(os.path.abspath(live_key))
        _reject_reparse_chain(key_root, key)
        if not key.is_file():
            raise CloneFailure("CLONE_SOURCE_REJECTED:storage_key")
        selected.append((key, clone_root / "secrets" / "storage_key.b64", "storage_key", "secrets/storage_key.b64"))

    total = 0
    for source, _destination, file_class, _relative in selected:
        size = source.stat().st_size
        if size < 0 or total + size > max_total_bytes:
            raise CloneFailure("CLONE_TOO_LARGE")
        total += size

    rows: list[dict[str, object]] = []
    for index, (source, destination, file_class, relative) in enumerate(selected, start=1):
        copied, before_hash = _copy_and_hash(
            source,
            destination,
            file_class,
            deadline=deadline,
            open_reader=open_reader,
            sleep=sleep,
            monotonic=monotonic,
            remaining_budget=max_total_bytes - sum(int(row["bytes"]) for row in rows),
        )
        after_hash = _hash_source(source, deadline=deadline, open_reader=open_reader, monotonic=monotonic)
        if before_hash != after_hash or destination.stat().st_size != copied:
            raise CloneFailure("CLONE_SOURCE_CHANGED")
        append_marker(stage_file, f"clone_item:{index}:{file_class}:{copied}")
        rows.append({"relative_name": relative, "bytes": copied, "sha256": before_hash})
    append_marker(stage_file, "clone_done")
    payload = {
        "status": "CLONE_PASS",
        "files": len(rows),
        "bytes": sum(int(row["bytes"]) for row in rows),
        "live_hashes_match": True,
        "items": rows,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > 16384:
        raise CloneFailure("CLONE_RESULT_BOUND_EXCEEDED")
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_bytes(encoded + b"\n")
    return payload


def verify_unchanged(
    live_state: Path,
    live_key: Path,
    expected_result: Path,
    result_path: Path,
    *,
    stage_timeout_seconds: int = 90,
    open_reader: Callable[[Path], BinaryIO] = _open_shared_read,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict:
    raw = expected_result.read_bytes()
    if len(raw) > 16384:
        raise CloneFailure("CLONE_RESULT_BOUND_EXCEEDED")
    try:
        expected = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloneFailure("CLONE_RESULT_INVALID") from exc
    if expected.get("status") != "CLONE_PASS" or not isinstance(expected.get("items"), list):
        raise CloneFailure("CLONE_RESULT_INVALID")
    live_state = Path(os.path.abspath(live_state))
    live_key = Path(os.path.abspath(live_key))
    _reject_reparse_chain(live_state, live_state)
    deadline = monotonic() + stage_timeout_seconds
    for item in expected["items"]:
        if not isinstance(item, dict) or set(item) != {"relative_name", "bytes", "sha256"}:
            raise CloneFailure("CLONE_RESULT_INVALID")
        relative = item["relative_name"]
        if relative == "secrets/storage_key.b64":
            source = live_key
            _reject_reparse_chain(live_state.parent, source)
        elif isinstance(relative, str) and relative.startswith("state/"):
            source = live_state / relative[6:]
            _reject_reparse_chain(live_state, source)
        else:
            raise CloneFailure("CLONE_RESULT_INVALID")
        if source.stat().st_size != item["bytes"]:
            raise CloneFailure("CLONE_SOURCE_CHANGED")
        actual = _hash_source(source, deadline=deadline, open_reader=open_reader, monotonic=monotonic)
        if actual != item["sha256"]:
            raise CloneFailure("CLONE_SOURCE_CHANGED")
    payload = {"status": "VERIFY_PASS", "live_hashes_match": True, "files": len(expected["items"])}
    result_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live-state", required=True)
    parser.add_argument("--live-key", required=True)
    parser.add_argument("--clone-root", required=True)
    parser.add_argument("--stage-file", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--stage-timeout", type=int, default=90)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--expected-result")
    args = parser.parse_args()
    try:
        if args.verify_only:
            if not args.expected_result:
                raise CloneFailure("CLONE_RESULT_REQUIRED")
            verify_unchanged(Path(args.live_state), Path(args.live_key), Path(args.expected_result), Path(args.result), stage_timeout_seconds=args.stage_timeout)
        else:
            clone_state(Path(args.live_state), Path(args.clone_root), Path(args.stage_file), Path(args.result), live_key=Path(args.live_key), stage_timeout_seconds=args.stage_timeout)
        return 0
    except CloneFailure as exc:
        payload = json.dumps({"status": "CLONE_FAILED", "code": exc.code}, sort_keys=True, separators=(",", ":"))
        Path(args.result).write_text(payload + "\n", encoding="ascii")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
