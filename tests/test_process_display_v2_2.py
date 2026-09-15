from __future__ import annotations

import copy
from pathlib import Path
import sys
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent.sensors.process_display import (  # noqa: E402
    build_process_inventory,
    classify_process_for_display,
    friendly_process_name,
    metadata_cache_info,
    resolve_process_display,
)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print(f"PASS | {msg}")


def main():
    check(
        friendly_process_name({
            "name": "chrome.exe",
            "exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        }) == "Google Chrome",
        "Chrome is shown as Google Chrome",
    )
    check(
        friendly_process_name({"name": "python.exe", "exe": r"C:\Python314\python.exe"}) == "Python",
        "python.exe is shown as Python",
    )
    check(
        friendly_process_name({"name": "WINWORD.EXE", "exe": r"C:\Program Files\Microsoft Office\WINWORD.EXE"}) == "Microsoft Word",
        "Word technical executable is humanized",
    )
    check(
        friendly_process_name({"name": "custom_worker.exe", "exe": None}) == "Custom Worker",
        "unknown executable uses bounded humanized fallback",
    )

    with patch(
        "agent.sensors.process_display._read_windows_version_strings",
        return_value={
            "ProductName": "Dragon's Dogma: Dark Arisen",
            "FileDescription": "Dragon's Dogma: Dark Arisen",
            "CompanyName": "Capcom U.S.A., Inc.",
            "OriginalFilename": "DDDA.exe",
        },
    ):
        process = {
            "pid": 15256,
            "name": "DDDA.exe",
            "exe": r"D:\game\Dragons Dogma Dark Arisen\DDDA.exe",
            "username": r"WIN-TEST\user",
            "cpu_percent": 0.0,
            "memory_percent": 0.22,
            "create_time": 1000.0,
        }
        label, source = resolve_process_display(process)
        check(label == "Dragon's Dogma: Dark Arisen", "DDDA.exe resolves from Windows ProductName")
        check(source == "FILE_PRODUCT_NAME", "ProductName source is explicit")
        check(classify_process_for_display(process, source) == "USER_APPLICATION", "DDDA is classified as user application")

        rows = build_process_inventory({"processes": [process]})
        check(rows[0]["display_name"] == "Dragon's Dogma: Dark Arisen", "inventory shows full Dragon's Dogma product name")
        check(rows[0]["technical_name"] == "DDDA.exe", "DDDA.exe remains preserved for forensic accuracy")
        check(rows[0]["exe"] == process["exe"], "executable path remains preserved")
        check(rows[0]["display_name_source"] == "FILE_PRODUCT_NAME", "inventory exposes display-name evidence source")
        check(rows[0]["application_class"] == "USER_APPLICATION", "inventory exposes display-only application class")

    with patch(
        "agent.sensors.process_display._read_windows_version_strings",
        return_value={"ProductName": "Specific Product", "FileDescription": "Specific Description"},
    ):
        label, source = resolve_process_display({"name": "product.exe", "exe": r"C:\Apps\product.exe"})
        check(label == "Specific Product", "ProductName has priority")
        check(source == "FILE_PRODUCT_NAME", "ProductName priority source is explicit")

    with patch(
        "agent.sensors.process_display._read_windows_version_strings",
        return_value={
            "ProductName": "Microsoft® Windows® Operating System",
            "FileDescription": "Example Windows Helper",
        },
    ):
        label, source = resolve_process_display({"name": "unknownhelper.exe", "exe": r"C:\Windows\System32\unknownhelper.exe"})
        check(label == "Example Windows Helper", "generic ProductName yields to specific FileDescription")
        check(source == "FILE_DESCRIPTION", "FileDescription source is explicit")

    with patch("agent.sensors.process_display._read_windows_version_strings", return_value={}):
        label, source = resolve_process_display({"name": "plain_worker.exe", "exe": r"C:\Apps\plain_worker.exe"})
        check(label == "Plain Worker", "missing metadata uses safe fallback")
        check(source == "EXECUTABLE_FALLBACK", "fallback source is explicit")

    with patch(
        "agent.sensors.process_display._read_windows_version_strings",
        side_effect=PermissionError("test"),
    ):
        label, source = resolve_process_display({"name": "denied_worker.exe", "exe": r"C:\Apps\denied_worker.exe"})
        check(label == "Denied Worker", "metadata exception fails safely to executable")
        check(source == "EXECUTABLE_FALLBACK", "exception fallback source is explicit")

    snap = {
        "processes": [
            {"pid": 10, "name": "chrome.exe", "exe": r"C:\Chrome\chrome.exe", "username": "U", "cpu_percent": 1.0, "memory_percent": 2.5, "create_time": 1},
            {"pid": 11, "name": "chrome.exe", "exe": r"C:\Chrome\chrome.exe", "username": "U", "cpu_percent": 2.0, "memory_percent": 1.5, "create_time": 2},
            {"pid": 20, "name": "python.exe", "exe": r"C:\Python\python.exe", "username": "U", "cpu_percent": 0.5, "memory_percent": 1.0, "create_time": 3},
        ]
    }
    before = copy.deepcopy(snap)
    rows = build_process_inventory(snap, limit=18)
    check(snap == before, "inventory builder does not mutate authoritative snapshot")
    check(len(rows) == 2, "same technical application processes are aggregated")
    check(rows[0]["display_name"] == "Google Chrome", "largest aggregate is first")
    check(rows[0]["processes"] == 2, "aggregate process count is exact")
    check(rows[0]["cpu_percent"] == 3.0, "aggregate CPU percent is exact")
    check(rows[0]["memory_percent"] == 4.0, "aggregate memory percent is exact")
    check(rows[0]["pids"] == [10, 11], "bounded PID samples remain visible")
    check(rows[0]["technical_name"] == "chrome.exe", "technical process name remains preserved")
    check(rows[0]["exe"] == r"C:\Chrome\chrome.exe", "aggregate executable path remains preserved")
    check(rows[0]["display_name_source"] == "KNOWN_EXECUTABLE", "known mapping provenance is present")

    # Display metadata collision safety.
    with patch(
        "agent.sensors.process_display._read_windows_version_strings",
        return_value={"ProductName": "Shared Display Product"},
    ):
        collision_rows = build_process_inventory({
            "processes": [
                {"pid": 101, "name": "one.exe", "exe": r"C:\VendorA\one.exe", "username": "U", "cpu_percent": 1, "memory_percent": 1},
                {"pid": 202, "name": "two.exe", "exe": r"C:\VendorB\two.exe", "username": "U", "cpu_percent": 1, "memory_percent": 1},
            ]
        })
        check(len(collision_rows) == 2, "display metadata collision does not merge different executables")
        check(all(row["display_name"] == "Shared Display Product" for row in collision_rows), "collision rows may share display label without sharing technical identity")

    # Core v2.2 regression: huge/high-memory system background inventory must
    # not starve a real user application out of the bounded 18-row dashboard.
    system_rows = []
    for idx in range(40):
        system_rows.append({
            "pid": 1000 + idx,
            "name": f"svc_{idx}.exe",
            "exe": rf"C:\Windows\System32\svc_{idx}.exe",
            "username": r"NT AUTHORITY\SYSTEM",
            "cpu_percent": 5.0,
            "memory_percent": 10.0 - (idx * 0.01),
            "create_time": 100 + idx,
        })

    ddda = {
        "pid": 15256,
        "name": "DDDA.exe",
        "exe": r"D:\game\Dragons Dogma Dark Arisen\DDDA.exe",
        "username": r"WIN-TEST\user",
        "cpu_percent": 0.0,
        "memory_percent": 0.22,
        "create_time": 5000.0,
    }
    with patch(
        "agent.sensors.process_display._read_windows_version_strings",
        side_effect=lambda path: {
            "ProductName": "Dragon's Dogma: Dark Arisen"
        } if str(path).lower().endswith("ddda.exe") else {},
    ):
        priority_rows = build_process_inventory({"processes": system_rows + [ddda]}, limit=18)
    dragon = next((r for r in priority_rows if r["technical_name"].lower() == "ddda.exe"), None)
    check(dragon is not None, "high-memory system components cannot starve DDDA user application")
    check(dragon["application_class"] == "USER_APPLICATION", "DDDA survives selection as USER_APPLICATION")
    check(len(priority_rows) == 18, "bounded inventory remains exactly limited")

    # All user applications fit -> all must survive regardless of system memory.
    user_apps = [
        {
            "pid": 2000 + idx,
            "name": f"app_{idx}.exe",
            "exe": rf"D:\Apps\app_{idx}.exe",
            "username": r"WIN-TEST\user",
            "cpu_percent": 0.0,
            "memory_percent": 0.1 + idx * 0.01,
            "create_time": 1000 + idx,
        }
        for idx in range(12)
    ]
    rows = build_process_inventory({"processes": system_rows + user_apps}, limit=18)
    kept = {r["technical_name"].lower() for r in rows}
    check(all(f"app_{idx}.exe" in kept for idx in range(12)), "all user applications survive when they fit within bound")

    # If user apps exceed the bound, recent-start reserve must retain a newly
    # launched low-memory user app rather than reverting to pure memory ranking.
    many_user_apps = []
    for idx in range(24):
        many_user_apps.append({
            "pid": 3000 + idx,
            "name": f"heavy_{idx}.exe",
            "exe": rf"D:\Apps\heavy_{idx}.exe",
            "username": r"WIN-TEST\user",
            "cpu_percent": 0.0,
            "memory_percent": 10.0 - idx * 0.1,
            "create_time": 1000 + idx,
        })
    newest_low = {
        "pid": 9999,
        "name": "new_low.exe",
        "exe": r"D:\Apps\new_low.exe",
        "username": r"WIN-TEST\user",
        "cpu_percent": 0.0,
        "memory_percent": 0.01,
        "create_time": 999999.0,
    }
    rows = build_process_inventory({"processes": many_user_apps + [newest_low]}, limit=18)
    newest = next((r for r in rows if r["technical_name"].lower() == "new_low.exe"), None)
    check(newest is not None, "recent-start reserve retains newly launched low-memory user app")
    check(newest["selection_reason"] == "USER_APPLICATION_RECENT", "recent selection provenance is explicit")

    # Background/user component classification is display-only and lower rank.
    background = {
        "pid": 500,
        "name": "CrossDeviceService.exe",
        "exe": r"C:\Program Files\WindowsApps\CrossDeviceService.exe",
        "username": r"WIN-TEST\user",
    }
    check(classify_process_for_display(background, "FILE_PRODUCT_NAME") == "USER_COMPONENT", "background user service is not promoted to user application")

    malformed = build_process_inventory({"processes": [None, "bad", 3, {}, {"pid": "x", "name": None, "exe": None}]})
    check(isinstance(malformed, list), "malformed process entries remain safe")
    check(resolve_process_display(None) == ("Unknown Process", "UNKNOWN"), "malformed resolver input remains safe")

    cache = metadata_cache_info()
    check(cache["maxsize"] == 512, "metadata cache is explicitly bounded")
    check(cache["currsize"] <= cache["maxsize"], "metadata cache current size remains bounded")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
