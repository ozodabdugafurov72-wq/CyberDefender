from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
STATE_DIR = PROJECT_ROOT / "state"
STATE_PATH = STATE_DIR / "state.json"


def result(name: str, status: str, detail: str = "") -> None:
    mark = "PASS" if status == "PASS" else "INFO" if status == "INFO" else "FAIL"
    print(f"[{mark}] {name}")
    if detail:
        print(f"      {detail}")


def get_windows_acl(path: Path) -> str:
    try:
        completed = subprocess.run(
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        output = (completed.stdout or completed.stderr).strip()
        return output
    except Exception as exc:
        return f"icacls unavailable: {type(exc).__name__}: {exc}"


def find_agent_processes() -> list[str]:
    try:
        ps = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process | "
                    "Where-Object { "
                    "$_.Name -match '^python(\\.exe)?$' -and "
                    "$_.CommandLine -match 'agent[\\\\/]main\\.py|agent\\.main' "
                    "} | "
                    "Select-Object ProcessId,Name,CommandLine | "
                    "Format-List | Out-String"
                ),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        text = (ps.stdout or "").strip()
        if not text:
            return []
        return [text]
    except Exception as exc:
        return [f"process inspection unavailable: {type(exc).__name__}: {exc}"]


def locked_replace_probe() -> tuple[bool, str]:
    """
    Controlled reproduction test in a temporary directory.

    We copy the current state.json into a temp directory, acquire an
    exclusive Windows handle on that COPY, then attempt os.replace()
    against the locked copy. The production state.json is never renamed,
    deleted, or replaced.
    """
    if os.name != "nt":
        return False, "Windows-only probe skipped."

    import shutil

    with tempfile.TemporaryDirectory(prefix="cd_state_probe_") as tmp:
        tmp_dir = Path(tmp)
        target = tmp_dir / "state.json"
        replacement = tmp_dir / "replacement.tmp"

        if STATE_PATH.exists():
            shutil.copy2(STATE_PATH, target)
        else:
            target.write_text("{}", encoding="utf-8")

        replacement.write_text(
            target.read_text(encoding="utf-8") if target.exists() else "{}",
            encoding="utf-8",
        )

        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        handle = kernel32.CreateFileW(
            str(target),
            GENERIC_READ | GENERIC_WRITE,
            0,  # no sharing: intentionally lock the COPY
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )

        if handle == INVALID_HANDLE_VALUE:
            return False, "Could not acquire exclusive lock on temporary copy."

        try:
            try:
                os.replace(replacement, target)
            except PermissionError as exc:
                return True, f"Windows returned PermissionError while target copy was locked: {exc}"
            except OSError as exc:
                return False, f"Windows returned {type(exc).__name__}: {exc}"
            else:
                return False, "os.replace succeeded despite exclusive lock; lock behavior did not reproduce."
        finally:
            kernel32.CloseHandle(handle)


def main() -> int:
    print("=" * 72)
    print("CYBERDEFENDER — EVENTSTATE PERMISSION ROOT-CAUSE DIAGNOSTIC v1")
    print("=" * 72)
    print()
    print("Safety: production state.json is NEVER renamed, replaced, deleted,")
    print("or rewritten by this diagnostic.")
    print()

    # 01 — Paths
    print("01. PATH / FILE STATE")
    print("-" * 72)

    result(
        "Project root",
        "PASS" if PROJECT_ROOT.exists() else "FAIL",
        str(PROJECT_ROOT),
    )

    result(
        "State directory",
        "PASS" if STATE_DIR.is_dir() else "FAIL",
        str(STATE_DIR),
    )

    if STATE_PATH.exists():
        try:
            stat = STATE_PATH.stat()
            result(
                "state.json exists",
                "PASS",
                f"size={stat.st_size} bytes; mode={oct(stat.st_mode)}",
            )
        except OSError as exc:
            result("state.json stat", "FAIL", f"{type(exc).__name__}: {exc}")
    else:
        result("state.json exists", "INFO", "File does not exist.")

    print()

    # 02 — EventState health
    print("02. EVENTSTATE HEALTH CONTRACT")
    print("-" * 72)

    try:
        from agent.state import EventState

        manager = EventState(STATE_PATH)
        health = manager.health_check()
        print(json.dumps(health, indent=2, ensure_ascii=False))

        status = health.get("status")
        if status == "HEALTHY":
            result(
                "EventState.health_check()",
                "PASS",
                "Persisted state is readable and structurally valid.",
            )
        else:
            result(
                "EventState.health_check()",
                "FAIL",
                f"status={status}; last_error={health.get('last_error')}",
            )
    except Exception as exc:
        result(
            "EventState.health_check()",
            "FAIL",
            f"{type(exc).__name__}: {exc}",
        )

    print()

    # 03 — ACL
    print("03. WINDOWS ACL")
    print("-" * 72)

    acl_target = STATE_PATH if STATE_PATH.exists() else STATE_DIR
    acl = get_windows_acl(acl_target)
    print(acl)
    print()

    # 04 — Directory write/rename probe
    print("04. CONTROLLED DIRECTORY ATOMIC-RENAME PROBE")
    print("-" * 72)

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=".cd_permission_probe_",
            suffix=".tmp",
            dir=STATE_DIR,
            delete=False,
        ) as file:
            probe_source = Path(file.name)
            file.write("CYBERDEFENDER_PERMISSION_PROBE\n")
            file.flush()
            os.fsync(file.fileno())

        probe_target = STATE_DIR / ".cd_permission_probe_target.tmp"
        try:
            os.replace(probe_source, probe_target)
            result(
                "Create/write/atomic-rename in state directory",
                "PASS",
                "Directory permits the same basic filesystem operations used by EventState._save().",
            )
        finally:
            probe_source.unlink(missing_ok=True)
            probe_target.unlink(missing_ok=True)

    except Exception as exc:
        result(
            "Create/write/atomic-rename in state directory",
            "FAIL",
            f"{type(exc).__name__}: {exc}",
        )

    print()

    # 05 — Controlled Windows lock reproduction
    print("05. CONTROLLED WINDOWS LOCK REPRODUCTION")
    print("-" * 72)

    reproduced, detail = locked_replace_probe()
    result(
        "Locked-target os.replace() behavior",
        "PASS" if reproduced else "INFO",
        detail,
    )

    print()

    # 06 — Concurrent agent inspection
    print("06. CONCURRENT AGENT PROCESS INSPECTION")
    print("-" * 72)

    processes = find_agent_processes()
    if processes:
        for text in processes:
            print(text)
        result(
            "agent.main process inspection",
            "INFO",
            "Review the output above. More than one agent.main process is a strong candidate for a Windows state-file race.",
        )
    else:
        result(
            "agent.main process inspection",
            "PASS",
            "No agent.main process was detected at diagnostic time.",
        )

    print()
    print("=" * 72)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 72)
    print()
    print("INTERPRETATION:")
    print("1) EventState HEALTHY + directory probe PASS => current filesystem is writable.")
    print("2) Locked-target reproduction PASS => PermissionError is consistent with")
    print("   another process/handle holding state.json during atomic replacement.")
    print("3) Multiple agent.main processes => investigate concurrent runtime instances.")
    print("4) If all probes PASS and only historical runtime shows one failure,")
    print("   do NOT modify EventState yet; the failure likely occurred transiently.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
