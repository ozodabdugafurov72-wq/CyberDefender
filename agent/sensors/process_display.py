from __future__ import annotations

from functools import lru_cache
from pathlib import PureWindowsPath
from typing import Any
import ctypes
from ctypes import wintypes
import os


# DISPLAY-ONLY CONTRACT
# ---------------------
# These labels are presentation/read-model evidence only. They never
# participate in process identity, ProcessGraph lifecycle, correlation,
# risk, policy, authorization, Safety Core, or Action Gateway decisions.
_FRIENDLY_EXECUTABLES = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "opera.exe": "Opera",
    "brave.exe": "Brave Browser",
    "python.exe": "Python",
    "pythonw.exe": "Python",
    "py.exe": "Python Launcher",
    "powershell.exe": "Windows PowerShell",
    "pwsh.exe": "PowerShell",
    "cmd.exe": "Command Prompt",
    "code.exe": "Visual Studio Code",
    "devenv.exe": "Microsoft Visual Studio",
    "explorer.exe": "Windows Explorer",
    "taskmgr.exe": "Task Manager",
    "notepad.exe": "Notepad",
    "notepad++.exe": "Notepad++",
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "outlook.exe": "Microsoft Outlook",
    "teams.exe": "Microsoft Teams",
    "ms-teams.exe": "Microsoft Teams",
    "zoom.exe": "Zoom",
    "telegram.exe": "Telegram",
    "discord.exe": "Discord",
    "chatgpt.exe": "ChatGPT",
    "onedrive.exe": "Microsoft OneDrive",
    "msedgewebview2.exe": "Microsoft Edge WebView2",
    "windowsterminal.exe": "Windows Terminal",
    "openconsole.exe": "Windows Console",
    "applicationframehost.exe": "Windows Application Frame Host",
    "systemsettings.exe": "Windows Settings",
    "lockapp.exe": "Windows Lock Screen",
    "textinputhost.exe": "Windows Text Input",
    "widgets.exe": "Windows Widgets",
    "widgetservice.exe": "Windows Widgets Service",
    "securityhealthsystray.exe": "Windows Security",
    "securityhealthservice.exe": "Windows Security Service",
    "smartscreen.exe": "Microsoft Defender SmartScreen",
    "nissrv.exe": "Microsoft Defender Network Inspection",
    "audiodg.exe": "Windows Audio Device Graph",
    "spoolsv.exe": "Windows Print Spooler",
    "wmiprvse.exe": "Windows Management Instrumentation",
    "dllhost.exe": "Windows COM Surrogate",
    "fontdrvhost.exe": "Windows Font Driver Host",
    "sihost.exe": "Windows Shell Infrastructure Host",
    "ctfmon.exe": "Windows Text Services",
    "msiexec.exe": "Windows Installer",
    "winget.exe": "Windows Package Manager",
    "cargo.exe": "Rust Cargo",
    "rustc.exe": "Rust Compiler",
    "slack.exe": "Slack",
    "spotify.exe": "Spotify",
    "java.exe": "Java",
    "javaw.exe": "Java",
    "node.exe": "Node.js",
    "docker desktop.exe": "Docker Desktop",
    "wsl.exe": "Windows Subsystem for Linux",
    "conhost.exe": "Windows Console Host",
    "svchost.exe": "Windows Service Host",
    "taskhostw.exe": "Windows Task Host",
    "searchhost.exe": "Windows Search",
    "startmenuexperiencehost.exe": "Windows Start Menu",
    "shellexperiencehost.exe": "Windows Shell Experience",
    "runtimebroker.exe": "Windows Runtime Broker",
    "dwm.exe": "Desktop Window Manager",
    "winlogon.exe": "Windows Logon",
    "services.exe": "Windows Services Manager",
    "lsass.exe": "Local Security Authority",
    "csrss.exe": "Windows Client/Server Runtime",
    "smss.exe": "Windows Session Manager",
    "system": "Windows System",
    "secure system": "Windows Secure System",
    "memcompression": "Windows Memory Compression",
    "memory compression": "Windows Memory Compression",
}

_GENERIC_PRODUCT_NAMES = {
    "microsoft windows operating system",
    "microsoft® windows® operating system",
    "windows operating system",
    "windows",
}

_DISPLAY_SOURCE_PRIORITY = {
    "UNKNOWN": 0,
    "EXECUTABLE_FALLBACK": 1,
    "FILE_DESCRIPTION": 2,
    "FILE_PRODUCT_NAME": 3,
    "KNOWN_EXECUTABLE": 4,
}

_METADATA_CACHE_MAXSIZE = 512
_MAX_VERSION_RESOURCE_BYTES = 8 * 1024 * 1024
_MAX_TRANSLATIONS = 8
_MAX_DISPLAY_TEXT = 160
_MAX_EXE_PATH = 520
_MAX_USERNAME = 160
_MAX_PID_SAMPLES = 6


# Active Applications selection policy
# -----------------------------------
# This policy is presentation-only. It prevents high-memory Windows service
# processes from starving real user applications out of the bounded dashboard
# list. Classification never participates in security identity or authority.
_USER_FACING_EXECUTABLES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "python.exe", "pythonw.exe", "py.exe", "powershell.exe", "pwsh.exe",
    "cmd.exe", "code.exe", "devenv.exe", "explorer.exe", "taskmgr.exe",
    "notepad.exe", "notepad++.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "outlook.exe", "teams.exe", "ms-teams.exe", "zoom.exe",
    "telegram.exe", "discord.exe", "chatgpt.exe", "slack.exe", "spotify.exe",
    "windowsterminal.exe", "systemsettings.exe", "onedrive.exe",
    "java.exe", "javaw.exe", "docker desktop.exe", "wsl.exe",
}

_BACKGROUND_EXECUTABLES = {
    "msedgewebview2.exe", "applicationframehost.exe", "textinputhost.exe",
    "widgets.exe", "widgetservice.exe", "securityhealthsystray.exe",
    "securityhealthservice.exe", "smartscreen.exe", "nissrv.exe",
    "audiodg.exe", "spoolsv.exe", "wmiprvse.exe", "dllhost.exe",
    "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "conhost.exe",
    "svchost.exe", "taskhostw.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "runtimebroker.exe", "dwm.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "system", "secure system",
    "memcompression", "memory compression", "searchindexer.exe",
    "widgetboard.exe", "crossdeviceservice.exe",
    "microsoftstartfeedprovider.exe", "dsaservice.exe", "dsatray.exe",
}

_SYSTEM_PRINCIPAL_PREFIXES = (
    "nt authority\\",
    "nt service\\",
    "window manager\\",
    "font driver host\\",
)

_APPLICATION_CLASS_PRIORITY = {
    "SYSTEM_COMPONENT": 0,
    "UNATTRIBUTED_COMPONENT": 1,
    "USER_COMPONENT": 2,
    "USER_APPLICATION": 3,
}



def _basename(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        base = PureWindowsPath(text).name
    except Exception:
        base = text
    return base or text


def _clean_display_text(value: Any, *, limit: int = _MAX_DISPLAY_TEXT) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if not text:
        return ""
    text = " ".join(text.split())
    return text[:limit]


def _humanize_executable(value: str) -> str:
    if not value:
        return "Unknown Process"
    stem = value[:-4] if value.casefold().endswith(".exe") else value
    stem = stem.replace("_", " ").replace("-", " ").strip()
    if not stem:
        return value
    if stem.islower() or stem.isupper():
        return " ".join(part.capitalize() for part in stem.split()) or value
    return stem


def _normalize_exe_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        # PureWindowsPath is deterministic even when unit tests run elsewhere.
        return str(PureWindowsPath(text)).casefold()
    except Exception:
        return text.replace("/", "\\").casefold()


def _display_group_key(process: dict[str, Any]) -> str:
    """Build a display aggregation key without trusting display metadata.

    ProductName/FileDescription are intentionally NOT part of this key because
    executable metadata is presentation evidence and can collide or be spoofed.
    Grouping uses technical evidence only: executable path when available,
    otherwise raw executable name. Username is included to avoid attributing
    resources from different principals to a single dashboard row.
    """
    exe_path = _normalize_exe_path(process.get("exe"))
    raw_name = _basename(process.get("name")).casefold()
    exe_name = _basename(process.get("exe")).casefold()
    username = str(process.get("username") or "").strip().casefold()

    if exe_path:
        return f"path:{exe_path}|user:{username}"
    if exe_name:
        return f"exe:{exe_name}|user:{username}"
    if raw_name:
        return f"name:{raw_name}|user:{username}"

    pid = process.get("pid")
    try:
        return f"unknown-pid:{int(pid)}|user:{username}"
    except (TypeError, ValueError):
        return f"unknown-object:{id(process)}|user:{username}"


@lru_cache(maxsize=_METADATA_CACHE_MAXSIZE)
def _read_windows_version_strings_cached(
    exe_path: str,
    file_size: int,
    mtime_ns: int,
) -> tuple[tuple[str, str], ...]:
    """Read bounded PE version-resource strings using Win32 Version APIs.

    Cache identity is path + size + mtime. Replacing an executable therefore
    produces a new cache key instead of reusing stale presentation metadata.
    Any read/parse failure returns empty metadata and never degrades runtime.
    """
    del file_size, mtime_ns  # cache identity only

    if os.name != "nt":
        return ()

    try:
        version = ctypes.WinDLL("version", use_last_error=True)

        version.GetFileVersionInfoSizeW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        version.GetFileVersionInfoSizeW.restype = wintypes.DWORD

        version.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        version.GetFileVersionInfoW.restype = wintypes.BOOL

        version.VerQueryValueW.argtypes = [
            wintypes.LPCVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        version.VerQueryValueW.restype = wintypes.BOOL

        dummy = wintypes.DWORD(0)
        size = int(version.GetFileVersionInfoSizeW(exe_path, ctypes.byref(dummy)))
        if size <= 0 or size > _MAX_VERSION_RESOURCE_BYTES:
            return ()

        block = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(exe_path, 0, size, block):
            return ()

        translations: list[tuple[int, int]] = []
        ptr = ctypes.c_void_p()
        length = wintypes.UINT(0)

        if version.VerQueryValueW(
            block,
            r"\VarFileInfo\Translation",
            ctypes.byref(ptr),
            ctypes.byref(length),
        ):
            byte_len = int(length.value)
            if ptr.value and byte_len >= 4:
                word_count = byte_len // ctypes.sizeof(wintypes.WORD)
                words_type = wintypes.WORD * word_count
                words = ctypes.cast(ptr, ctypes.POINTER(words_type)).contents
                for idx in range(0, word_count - 1, 2):
                    pair = (int(words[idx]), int(words[idx + 1]))
                    if pair not in translations:
                        translations.append(pair)

        # Common English Unicode/Windows code-page fallbacks. These are only
        # lookup candidates; missing values remain a safe empty result.
        for pair in ((0x0409, 0x04B0), (0x0409, 0x04E4)):
            if pair not in translations:
                translations.append(pair)

        fields = (
            "ProductName",
            "FileDescription",
            "CompanyName",
            "OriginalFilename",
        )
        result: dict[str, str] = {}

        for lang, codepage in translations[:_MAX_TRANSLATIONS]:
            for field in fields:
                if field in result:
                    continue

                sub_block = rf"\StringFileInfo\{lang:04X}{codepage:04X}\{field}"
                value_ptr = ctypes.c_void_p()
                value_len = wintypes.UINT(0)

                ok = version.VerQueryValueW(
                    block,
                    sub_block,
                    ctypes.byref(value_ptr),
                    ctypes.byref(value_len),
                )
                if not ok or not value_ptr.value or int(value_len.value) <= 1:
                    continue

                text = ctypes.wstring_at(
                    value_ptr.value,
                    max(0, int(value_len.value) - 1),
                )
                cleaned = _clean_display_text(text)
                if cleaned:
                    result[field] = cleaned

            if "ProductName" in result and "FileDescription" in result:
                break

        return tuple(sorted(result.items()))
    except Exception:
        return ()


def _read_windows_version_strings(exe_path: Any) -> dict[str, str]:
    path = str(exe_path or "").strip()
    if not path or os.name != "nt":
        return {}

    try:
        stat = os.stat(path)
        items = _read_windows_version_strings_cached(
            path,
            int(stat.st_size),
            int(stat.st_mtime_ns),
        )
        return dict(items)
    except Exception:
        return {}


def metadata_cache_info() -> dict[str, int]:
    """Expose bounded cache telemetry for tests/diagnostics only."""
    info = _read_windows_version_strings_cached.cache_info()
    return {
        "hits": int(info.hits),
        "misses": int(info.misses),
        "currsize": int(info.currsize),
        "maxsize": int(info.maxsize or 0),
    }


def resolve_process_display(process: Any) -> tuple[str, str]:
    """Resolve a human-friendly label and explicit evidence source.

    Resolution order:
      1) trusted executable map;
      2) Windows PE ProductName;
      3) Windows PE FileDescription;
      4) non-invented executable-name fallback.

    The result is never security identity or authorization evidence.
    """
    if not isinstance(process, dict):
        return "Unknown Process", "UNKNOWN"

    raw_name = _basename(process.get("name"))
    exe_path = str(process.get("exe") or "").strip()
    exe_name = _basename(exe_path)

    for value in (exe_name, raw_name):
        if not value:
            continue
        mapped = _FRIENDLY_EXECUTABLES.get(value.casefold())
        if mapped:
            return mapped, "KNOWN_EXECUTABLE"

    try:
        metadata = _read_windows_version_strings(exe_path)
    except Exception:
        metadata = {}

    product = _clean_display_text(metadata.get("ProductName"))
    description = _clean_display_text(metadata.get("FileDescription"))

    if product:
        if product.casefold() not in _GENERIC_PRODUCT_NAMES:
            return product, "FILE_PRODUCT_NAME"
        if description:
            return description, "FILE_DESCRIPTION"

    if description:
        return description, "FILE_DESCRIPTION"

    value = exe_name or raw_name
    if not value:
        return "Unknown Process", "UNKNOWN"

    return _humanize_executable(value), "EXECUTABLE_FALLBACK"


def friendly_process_name(process: dict[str, Any]) -> str:
    """Backward-compatible display-label helper."""
    return resolve_process_display(process)[0]


def _safe_float(value: Any) -> float:
    try:
        parsed = float(value)
        if parsed != parsed:  # NaN
            return 0.0
        return max(0.0, parsed)
    except (TypeError, ValueError):
        return 0.0


def _is_system_principal(username: Any) -> bool:
    text = str(username or "").strip().casefold()
    if not text:
        return False
    if any(text.startswith(prefix) for prefix in _SYSTEM_PRINCIPAL_PREFIXES):
        return True
    if text in {"system", "local service", "network service"}:
        return True
    return text.startswith("dwm-") or text.startswith("umfd-")


def _is_windows_system_path(exe_path: Any) -> bool:
    path = _normalize_exe_path(exe_path)
    if not path:
        return False
    # Drive-letter and device-like forms are both handled conservatively.
    return "\\windows\\" in path or path.endswith("\\windows")


def _looks_background_executable(exe_name: str) -> bool:
    name = str(exe_name or "").casefold()
    if not name:
        return False
    if name in _BACKGROUND_EXECUTABLES:
        return True

    stem = name[:-4] if name.endswith(".exe") else name
    normalized = stem.replace("-", "_").replace(" ", "_")
    parts = [part for part in normalized.split("_") if part]

    background_tokens = {
        "service", "svc", "host", "broker", "provider", "helper",
        "updater", "update", "indexer", "tray",
    }
    if any(part in background_tokens for part in parts):
        return True
    if stem.endswith("service") or stem.endswith("service64") or stem.endswith("svc"):
        return True
    if "webview" in stem:
        return True
    return False


def classify_process_for_display(
    process: Any,
    display_source: str | None = None,
) -> str:
    """Classify a row for dashboard selection only.

    This classification is deliberately non-authoritative. It exists only to
    keep bounded Active Applications focused on user applications instead of
    letting high-memory Windows service processes consume every display slot.
    """
    if not isinstance(process, dict):
        return "UNATTRIBUTED_COMPONENT"

    username = str(process.get("username") or "").strip()
    raw_name = _basename(process.get("name"))
    exe_path = str(process.get("exe") or "").strip()
    exe_name = (_basename(exe_path) or raw_name).casefold()

    if _is_system_principal(username):
        return "SYSTEM_COMPONENT"

    if exe_name in _USER_FACING_EXECUTABLES:
        return "USER_APPLICATION"

    if _looks_background_executable(exe_name):
        return "USER_COMPONENT" if username else "UNATTRIBUTED_COMPONENT"

    if username:
        if exe_path and not _is_windows_system_path(exe_path):
            return "USER_APPLICATION"
        if str(display_source or "") in {"FILE_PRODUCT_NAME", "FILE_DESCRIPTION"}:
            return "USER_APPLICATION"
        return "USER_COMPONENT"

    if (
        exe_path
        and not _is_windows_system_path(exe_path)
        and str(display_source or "") in {"FILE_PRODUCT_NAME", "FILE_DESCRIPTION"}
    ):
        return "UNATTRIBUTED_COMPONENT"

    return "UNATTRIBUTED_COMPONENT"


def _resource_sort_key(row: dict[str, Any]) -> tuple[float, float, int, float]:
    return (
        _safe_float(row.get("memory_percent")),
        _safe_float(row.get("cpu_percent")),
        int(row.get("processes") or 0),
        _safe_float(row.get("latest_create_time")),
    )


def _recent_sort_key(row: dict[str, Any]) -> tuple[float, float, float, int]:
    return (
        _safe_float(row.get("latest_create_time")),
        _safe_float(row.get("memory_percent")),
        _safe_float(row.get("cpu_percent")),
        int(row.get("processes") or 0),
    )


def _select_bounded_rows(
    rows: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Select a bounded, application-first dashboard inventory.

    Policy:
      * USER_APPLICATION rows always outrank background/system components;
      * if all user applications fit, all are retained;
      * if they exceed the bound, most slots are resource-ranked while a
        bounded recent-start reserve prevents a newly launched low-memory app
        from disappearing completely;
      * remaining capacity is filled by user components, then unattributed,
        then system components.

    This is presentation selection only and never feeds back into security
    authority, ProcessGraph, correlation, policy, or response decisions.
    """
    if limit <= 0:
        return []

    buckets: dict[str, list[dict[str, Any]]] = {
        "USER_APPLICATION": [],
        "USER_COMPONENT": [],
        "UNATTRIBUTED_COMPONENT": [],
        "SYSTEM_COMPONENT": [],
    }
    for row in rows:
        cls = str(row.get("application_class") or "UNATTRIBUTED_COMPONENT")
        buckets.setdefault(cls, []).append(row)

    selected: list[dict[str, Any]] = []
    selected_ids: set[int] = set()

    def add(row: dict[str, Any], reason: str) -> None:
        marker = id(row)
        if marker in selected_ids or len(selected) >= limit:
            return
        row["selection_reason"] = reason
        selected.append(row)
        selected_ids.add(marker)

    user_apps = sorted(
        buckets.get("USER_APPLICATION", []),
        key=_resource_sort_key,
        reverse=True,
    )

    if len(user_apps) <= limit:
        for row in user_apps:
            add(row, "USER_APPLICATION")
    else:
        # 75% resource-ranked + 25% recent-start diversity, with minimum two
        # recent slots where the bound permits it.
        recent_slots = max(2, limit // 4) if limit >= 4 else 1
        recent_slots = min(recent_slots, limit)
        resource_slots = max(0, limit - recent_slots)

        for row in user_apps[:resource_slots]:
            add(row, "USER_APPLICATION_RESOURCE")

        remaining = [row for row in user_apps if id(row) not in selected_ids]
        remaining.sort(key=_recent_sort_key, reverse=True)
        for row in remaining:
            add(row, "USER_APPLICATION_RECENT")
            if len(selected) >= limit:
                break

    for class_name, reason in (
        ("USER_COMPONENT", "USER_COMPONENT_FILL"),
        ("UNATTRIBUTED_COMPONENT", "UNATTRIBUTED_FILL"),
        ("SYSTEM_COMPONENT", "SYSTEM_COMPONENT_FILL"),
    ):
        candidates = sorted(
            buckets.get(class_name, []),
            key=_resource_sort_key,
            reverse=True,
        )
        for row in candidates:
            add(row, reason)
            if len(selected) >= limit:
                break
        if len(selected) >= limit:
            break

    return selected


def build_process_inventory(
    snapshot: dict[str, Any] | None,
    *,
    limit: int = 18,
) -> list[dict[str, Any]]:
    """Build bounded display-only application inventory.

    Security properties:
      * source remains the authoritative Python ProcessSensor snapshot;
      * no input object is mutated;
      * display metadata never becomes process/group security identity;
      * grouping uses technical path/name + user evidence, not ProductName;
      * application relevance classification is display-only;
      * metadata reads are exception-safe and globally cache-bounded;
      * raw technical name, executable path and bounded PID samples remain.
    """
    if not isinstance(snapshot, dict):
        return []

    processes = snapshot.get("processes")
    if not isinstance(processes, list):
        return []

    grouped: dict[str, dict[str, Any]] = {}
    cycle_display_cache: dict[tuple[str, str], tuple[str, str]] = {}

    for item in processes:
        if not isinstance(item, dict):
            continue

        raw_name = _basename(item.get("name"))
        exe_path = str(item.get("exe") or "").strip()
        resolver_key = (raw_name.casefold(), _normalize_exe_path(exe_path))
        resolved = cycle_display_cache.get(resolver_key)
        if resolved is None:
            resolved = resolve_process_display(item)
            cycle_display_cache[resolver_key] = resolved
        display, display_source = resolved
        application_class = classify_process_for_display(item, display_source)

        group_key = _display_group_key(item)
        row = grouped.get(group_key)

        if row is None:
            row = {
                "display_name": display,
                "display_name_source": display_source,
                "technical_name": raw_name or _basename(exe_path) or "unknown",
                "application_class": application_class,
                "processes": 0,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "username": str(item.get("username") or "").strip() or None,
                "exe": exe_path or None,
                "pids": [],
                "latest_create_time": 0.0,
            }
            grouped[group_key] = row
        else:
            if (
                _DISPLAY_SOURCE_PRIORITY.get(display_source, 0)
                > _DISPLAY_SOURCE_PRIORITY.get(
                    str(row.get("display_name_source") or "UNKNOWN"),
                    0,
                )
            ):
                row["display_name"] = display
                row["display_name_source"] = display_source

            if (
                _APPLICATION_CLASS_PRIORITY.get(application_class, 0)
                > _APPLICATION_CLASS_PRIORITY.get(
                    str(row.get("application_class") or "UNATTRIBUTED_COMPONENT"),
                    0,
                )
            ):
                row["application_class"] = application_class

        row["processes"] += 1
        row["cpu_percent"] += _safe_float(item.get("cpu_percent"))
        row["memory_percent"] += _safe_float(item.get("memory_percent"))
        row["latest_create_time"] = max(
            _safe_float(row.get("latest_create_time")),
            _safe_float(item.get("create_time")),
        )

        pid = item.get("pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = None

        if pid is not None and len(row["pids"]) < _MAX_PID_SAMPLES:
            row["pids"].append(pid)

        if row.get("username") is None and item.get("username"):
            row["username"] = str(item.get("username"))[:_MAX_USERNAME]

        if row.get("exe") is None and item.get("exe"):
            row["exe"] = str(item.get("exe"))[:_MAX_EXE_PATH]

    try:
        bounded_limit = max(1, min(int(limit), 32))
    except (TypeError, ValueError):
        bounded_limit = 18

    selected = _select_bounded_rows(list(grouped.values()), bounded_limit)

    out: list[dict[str, Any]] = []
    for row in selected:
        out.append({
            "display_name": str(row.get("display_name") or "Unknown Process")[:_MAX_DISPLAY_TEXT],
            "display_name_source": str(row.get("display_name_source") or "UNKNOWN")[:48],
            "technical_name": str(row.get("technical_name") or "unknown")[:160],
            "application_class": str(row.get("application_class") or "UNATTRIBUTED_COMPONENT")[:48],
            "selection_reason": str(row.get("selection_reason") or "UNSPECIFIED")[:64],
            "processes": int(row.get("processes") or 0),
            "cpu_percent": round(_safe_float(row.get("cpu_percent")), 2),
            "memory_percent": round(_safe_float(row.get("memory_percent")), 2),
            "username": row.get("username"),
            "exe": row.get("exe"),
            "pids": list(row.get("pids") or [])[:_MAX_PID_SAMPLES],
        })

    return out
