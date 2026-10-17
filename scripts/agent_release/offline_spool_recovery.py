"""One-shot, evidence-preserving offline ACK-window recovery."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys

from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy


AUTHORIZATION = "OFFLINE_SPOOL_RECOVERY_AUTHORIZED"
FILES = ("pending.jsonl", "acked.jsonl", "quarantined.jsonl", "acked_state.json")


class RecoveryError(RuntimeError):
    pass


def fail(code: str) -> None:
    raise RecoveryError(code)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_directory(path: Path) -> bool:
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
        return True
    except OSError:
        return False


def safe_file(path: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISREG(info.st_mode) and not path.is_symlink() and not (
            getattr(info, "st_file_attributes", 0) & 0x400
        )
    except OSError:
        return False


def pending_ids(path: Path, policy: DurableSpoolPolicy) -> set[str]:
    if path.stat().st_size > policy.max_recovery_scan_bytes:
        fail("PENDING_SIZE_REJECTED")
    result: set[str] = set()
    with path.open("rb") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                fail("PENDING_JSON_REJECTED")
            event_id = record.get("event_id") if isinstance(record, dict) else None
            if not isinstance(event_id, str) or not event_id.strip():
                fail("PENDING_SCHEMA_REJECTED")
            result.add(event_id.strip())
            if len(result) > policy.max_pending_events:
                fail("PENDING_COUNT_REJECTED")
    return result


def pending_digest(ids: set[str]) -> str:
    return hashlib.sha256("\n".join(sorted(ids)).encode("utf-8")).hexdigest()[:16]


def ack_evidence(spool: Path, policy: DurableSpoolPolicy) -> tuple[set[str], list[str]]:
    try:
        snapshot = json.loads((spool / "acked_state.json").read_text(encoding="utf-8"))
        ids = snapshot["acked_ids"]
    except (OSError, KeyError, UnicodeError, json.JSONDecodeError, TypeError):
        fail("ACK_SNAPSHOT_REJECTED")
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != {"schema_version", "status", "acked_ids"}
        or snapshot.get("schema_version") != "1"
        or snapshot.get("status") != "ACKED"
        or not isinstance(ids, list)
        or any(not isinstance(item, str) or not item.strip() for item in ids)
        or len(set(ids)) != len(ids)
        or len(ids) != policy.max_terminal_records + 1
    ):
        fail("ACK_SNAPSHOT_SHAPE_REJECTED")
    order: list[str] = []
    try:
        with (spool / "acked.jsonl").open("rb") as handle:
            for line in handle:
                record = json.loads(line.decode("utf-8"))
                if not isinstance(record, dict) or set(record) != {"event_id"}:
                    fail("ACK_JOURNAL_SCHEMA_REJECTED")
                event_id = record["event_id"]
                if not isinstance(event_id, str) or not event_id.strip():
                    fail("ACK_JOURNAL_SCHEMA_REJECTED")
                order.append(event_id.strip())
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("ACK_JOURNAL_REJECTED")
    if len(order) != len(set(order)) or set(order) != set(ids):
        fail("ACK_JOURNAL_MISMATCH")
    return set(ids), order


def copy_backup(spool: Path, backup: Path) -> dict[str, str]:
    if backup.exists() or not safe_directory(backup.parent):
        fail("BACKUP_PATH_REJECTED")
    backup.mkdir(mode=0o700)
    hashes: dict[str, str] = {}
    for name in FILES:
        source = spool / name
        if not safe_file(source):
            fail("SPOOL_FILE_REJECTED")
        hashes[name] = sha256(source)
        with source.open("rb") as incoming, (backup / name).open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if sha256(backup / name) != hashes[name] or sha256(source) != hashes[name]:
            fail("BACKUP_VERIFY_FAILED")
    return hashes


def restore(spool: Path, backup: Path, expected: dict[str, str]) -> bool:
    if set(expected) != set(FILES) or any(
        not safe_file(backup / name) or sha256(backup / name) != expected[name]
        for name in FILES
    ):
        return False
    # A filesystem cannot atomically replace four independent files.  Make
    # one bounded second restoration pass if the first is interrupted.  The
    # immutable, preverified backup remains available if both passes fail.
    for _attempt in range(2):
        staged: dict[str, Path] = {}
        try:
            for name in FILES:
                source = backup / name
                temporary = spool / ("." + name + ".restore-" + secrets.token_hex(8))
                with source.open("rb") as incoming, temporary.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                if sha256(temporary) != expected[name]:
                    raise OSError("RESTORE_STAGE_VERIFY_FAILED")
                staged[name] = temporary
            for name in FILES:
                os.replace(staged[name], spool / name)
            if all(sha256(spool / name) == digest for name, digest in expected.items()):
                return True
        except OSError:
            pass
        finally:
            for path in staged.values():
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
    return False


def known_program_data() -> Path:
    if os.name != "nt":
        fail("LIVE_MODE_WINDOWS_REQUIRED")
    # FOLDERID_ProgramData via the Windows Known Folder API; do not trust a
    # caller-controlled environment variable for the protected live path.
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = (
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        )

    folder = GUID(
        0x62AB5D82,
        0xFDC1,
        0x4DC3,
        (ctypes.c_ubyte * 8)(0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97),
    )
    value = ctypes.c_wchar_p()
    result = ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(folder), 0, 0, ctypes.byref(value))
    if result != 0 or not value.value:
        fail("PROGRAMDATA_RESOLUTION_FAILED")
    try:
        return Path(value.value).resolve(strict=True)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(value)


def require_agent_stopped() -> None:
    if os.name != "nt":
        fail("LIVE_MODE_WINDOWS_REQUIRED")
    try:
        import psutil

        state = psutil.win_service_get("CyberDefenderAgent").as_dict()
    except Exception:
        fail("AGENT_STATE_UNAVAILABLE")
    if state.get("status") != "stopped" or state.get("pid") not in (None, 0):
        fail("AGENT_NOT_QUIESCENT")


def validate_mode(mode: str, spool: Path) -> tuple[Path, object | None]:
    resolved_spool = spool.resolve(strict=True)
    live = (known_program_data() / "CyberDefender" / "state" / "spool").resolve(strict=False)
    if mode == "copy":
        if resolved_spool == live:
            fail("COPY_MODE_LIVE_PATH_REJECTED")
        return resolved_spool, None
    if resolved_spool != live.resolve(strict=True):
        fail("LIVE_SPOOL_PATH_REJECTED")
    require_agent_stopped()
    return resolved_spool, require_agent_stopped


def recover(
    spool: Path,
    backup: Path,
    expected_pending: str,
    quiescent_check=None,
) -> dict[str, object]:
    policy = DurableSpoolPolicy()
    spool = spool.resolve(strict=True)
    if not safe_directory(spool):
        fail("SPOOL_PATH_REJECTED")
    before_ids, journal = ack_evidence(spool, policy)
    before_pending = pending_ids(spool / "pending.jsonl", policy)
    if pending_digest(before_pending) != expected_pending:
        fail("PENDING_DIGEST_MISMATCH")
    if quiescent_check:
        quiescent_check()
    before_hashes = copy_backup(spool, backup)
    if quiescent_check:
        quiescent_check()
    try:
        if quiescent_check:
            quiescent_check()
        repaired = DurableEventSpool(spool)
        health = repaired.health_check()
        after_ids = set(repaired._acked)
        after_pending = {item["event_id"] for item in repaired.pending_records()}
        evicted = before_ids - after_ids
        if (
            health["status"] != "HEALTHY"
            or not health["terminal_state_safe"]
            or len(after_ids) != policy.max_terminal_records
            or len(evicted) != 1
            or journal.index(next(iter(evicted))) != 0
            or after_pending != before_pending
        ):
            fail("RECOVERY_POSTCHECK_FAILED")
        first_hashes = {name: sha256(spool / name) for name in FILES}
        second = DurableEventSpool(spool)
        if (
            second.health_check()["status"] != "HEALTHY"
            or set(second._acked) != after_ids
            or {item["event_id"] for item in second.pending_records()} != before_pending
            or any(sha256(spool / name) != digest for name, digest in first_hashes.items())
        ):
            fail("RECOVERY_NOT_IDEMPOTENT")
        if quiescent_check:
            quiescent_check()
        salt = secrets.token_bytes(16)
        evidence = hashlib.sha256(salt + next(iter(evicted)).encode("utf-8")).hexdigest()
        return {
            "status": "OFFLINE_SPOOL_RECOVERY_PASS",
            "ack_before": len(before_ids),
            "ack_after": len(after_ids),
            "evicted_count": 1,
            "evicted_journal_position": 1,
            "evicted_salt": salt.hex(),
            "evicted_digest": evidence,
            "pending_count": len(before_pending),
            "pending_digest16": expected_pending,
            "idempotent_second_run": True,
            "backup_hashes_recorded": len(before_hashes),
            "rollback_required": False,
        }
    except Exception:
        if not restore(spool, backup, before_hashes):
            raise RecoveryError("ROLLBACK_VERIFY_FAILED") from None
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--expected-pending-digest16", required=True)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--mode", choices=("copy", "live"), required=True)
    args = parser.parse_args()
    try:
        if args.authorization != AUTHORIZATION:
            fail("AUTHORIZATION_REJECTED")
        _resolved_spool, quiescent_check = validate_mode(args.mode, args.spool)
        result = recover(
            args.spool,
            args.backup,
            args.expected_pending_digest16,
            quiescent_check,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except RecoveryError as exc:
        print(json.dumps({"status": "BLOCKED", "code": str(exc)}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"status": "BLOCKED", "code": "UNEXPECTED_FAILURE"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
