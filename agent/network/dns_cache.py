from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from typing import Any


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def _bounded_text(value: Any, limit: int = 253) -> str:
    return str(value or "").strip()[:limit]


def _normalize_ip(value: Any) -> str | None:
    text = _bounded_text(value, 96)
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


def _normalize_domain(value: Any) -> str | None:
    text = _bounded_text(value, 253).rstrip(".").lower()
    if not text or not _DOMAIN_RE.fullmatch(text):
        return None
    return text


class WindowsDnsCacheReader:
    """Read-only observation of the local Windows DNS client cache.

    Security contract:
      * reads only the existing local DNS cache;
      * performs no DNS query, reverse lookup, socket connect, packet injection,
        firewall mutation, or remote enrichment;
      * failures are optional telemetry degradation and never grant authority;
      * output and record counts are bounded before publication.
    """

    VERSION = "0.1.6"
    MODE = "PASSIVE_LOCAL_CACHE"
    AUTHORITY = "NONE"
    POWERSHELL_TIMEOUT_SECONDS = 2.0
    MAX_WINDOWS_JSON_BYTES = 1024 * 1024
    MAX_ENTRIES = 2048

    def read(self) -> dict[str, Any]:
        if os.name != "nt":
            return self._unavailable("NON_WINDOWS")

        # Get-DnsClientCache reads the local resolver cache. It does not issue a
        # network lookup. We intentionally do not use Resolve-DnsName/nslookup.
        script = (
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
            "$ErrorActionPreference='Stop';"
            "$rows=@(Get-DnsClientCache | Select-Object "
            "Entry,RecordName,RecordType,Status,Section,TimeToLive,Data);"
            "$rows | ConvertTo-Json -Compress -Depth 3"
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=False,
                timeout=self.POWERSHELL_TIMEOUT_SECONDS,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return self._unavailable(type(exc).__name__)

        if completed.returncode != 0:
            return self._unavailable("DNS_CACHE_READ_FAILED")

        raw = bytes(completed.stdout or b"")
        if len(raw) > self.MAX_WINDOWS_JSON_BYTES:
            return self._unavailable("DNS_CACHE_OUTPUT_TOO_LARGE")

        try:
            text = raw.decode("utf-8-sig", errors="strict").strip()
            payload: Any = json.loads(text) if text else []
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._unavailable("DNS_CACHE_PARSE_FAILED")

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return self._unavailable("DNS_CACHE_SCHEMA_INVALID")

        entries: list[dict[str, Any]] = []
        for item in payload[: self.MAX_ENTRIES * 2]:
            if not isinstance(item, dict):
                continue
            record_type = _bounded_text(item.get("RecordType"), 24).upper()
            # PowerShell may serialize record type numerically on some builds.
            if record_type not in {"A", "AAAA", "1", "28"}:
                continue
            ip = _normalize_ip(item.get("Data"))
            name = _normalize_domain(item.get("RecordName") or item.get("Entry"))
            if not ip or not name:
                continue
            try:
                ttl = max(0, min(int(item.get("TimeToLive", 0) or 0), 7 * 24 * 3600))
            except (TypeError, ValueError):
                ttl = 0
            entries.append({
                "name": name,
                "ip_address": ip,
                "record_type": "AAAA" if ":" in ip else "A",
                "ttl_seconds": ttl,
                "source": "WINDOWS_DNS_CACHE",
                "passive": True,
                "authoritative": False,
                "authority": "NONE",
                "authorization": "NOT_GRANTED",
            })
            if len(entries) >= self.MAX_ENTRIES:
                break

        unique_names = len({row["name"] for row in entries})
        unique_ips = len({row["ip_address"] for row in entries})
        return {
            "schema": "cyberdefender.dns-cache-observation.v0.1.6",
            "version": self.VERSION,
            "mode": self.MODE,
            "status": "HEALTHY",
            "available": True,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "external_queries": False,
            "reverse_lookup": False,
            "entries": entries,
            "entries_observed": len(entries),
            "unique_names": unique_names,
            "unique_ips": unique_ips,
            "last_error": None,
        }

    def _unavailable(self, reason: str) -> dict[str, Any]:
        return {
            "schema": "cyberdefender.dns-cache-observation.v0.1.6",
            "version": self.VERSION,
            "mode": self.MODE,
            "status": "UNAVAILABLE",
            "available": False,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "external_queries": False,
            "reverse_lookup": False,
            "entries": [],
            "entries_observed": 0,
            "unique_names": 0,
            "unique_ips": 0,
            "last_error": _bounded_text(reason, 96) or "DNS_CACHE_UNAVAILABLE",
        }
