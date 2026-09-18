from __future__ import annotations

import json
from types import SimpleNamespace

import agent.network.dns_cache as dns_cache
from agent.network.dns_cache import WindowsDnsCacheReader

PASS = 0
FAIL = 0


def check(condition: bool, label: str) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS | {label}")
    else:
        FAIL += 1
        print(f"FAIL | {label}")


def run_fixture(rows):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        payload = json.dumps(rows, separators=(",", ":")).encode("utf-8")
        return SimpleNamespace(returncode=0, stdout=payload, stderr=b"")

    original_os = dns_cache.os
    original_run = dns_cache.subprocess.run
    dns_cache.os = SimpleNamespace(name="nt")
    dns_cache.subprocess.run = fake_run
    try:
        result = WindowsDnsCacheReader().read()
    finally:
        dns_cache.os = original_os
        dns_cache.subprocess.run = original_run
    return result, captured


def main() -> int:
    current_windows_rows = [
        {
            "Entry": "cmp2-sto2.steamserver.net",
            "Name": "cmp2-sto2.steamserver.net",
            "Data": "155.133.252.69",
            "Type": 1,
            "Status": 0,
            "Section": 1,
            "TimeToLive": 123,
        },
        {
            "Entry": "fd.api.iris.microsoft.com",
            "Name": "fd.api.iris.microsoft.com",
            "Data": "20.99.129.183",
            "Type": "A",
            "Status": 0,
            "Section": 1,
            "TimeToLive": 300,
        },
    ]
    result, captured = run_fixture(current_windows_rows)
    check(result["status"] == "HEALTHY", "current Windows schema remains healthy")
    check(result["raw_rows_observed"] == 2, "raw Windows DNS rows are observable")
    check(result["entries_observed"] == 2, "Type/Name Windows properties are accepted")
    check(result["unique_names"] == 2, "current Windows names are retained")
    check(result["unique_ips"] == 2, "current Windows IPs are retained")
    check(result["entries"][0]["name"] == "cmp2-sto2.steamserver.net", "Name property maps to normalized domain")
    check(result["entries"][0]["ip_address"] == "155.133.252.69", "Data property maps to IP")
    check(result["entries"][0]["authority"] == "NONE", "DNS evidence remains non-authoritative")
    check(result["entries"][0]["authorization"] == "NOT_GRANTED", "DNS evidence cannot authorize")

    legacy_rows = [
        {
            "Entry": "legacy.example.com",
            "RecordName": "legacy.example.com",
            "Data": "203.0.113.10",
            "RecordType": 1,
            "TimeToLive": 60,
        }
    ]
    legacy, _ = run_fixture(legacy_rows)
    check(legacy["entries_observed"] == 1, "legacy RecordName/RecordType schema remains compatible")
    check(legacy["entries"][0]["name"] == "legacy.example.com", "legacy domain is retained")

    argv_text = " ".join(captured.get("argv", []))
    check("Get-DnsClientCache" in argv_text, "reader still uses local Get-DnsClientCache")
    check("Resolve-DnsName" not in argv_text, "no active Resolve-DnsName query added")
    check("nslookup" not in argv_text.lower(), "no nslookup added")
    check(result["external_queries"] is False, "external queries remain disabled")
    check(result["reverse_lookup"] is False, "reverse lookup remains disabled")

    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
