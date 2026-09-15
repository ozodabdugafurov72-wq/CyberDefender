from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

try:
    import psutil
except Exception:  # pragma: no cover - runtime health reports dependency absence
    psutil = None


_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
_ALLOWED_TRUST = {"AUTHORIZED", "UNKNOWN", "DENIED", "REVOKED", "LOCAL"}
_ALLOWED_DEVICE_STATES = {
    "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "UNKNOWN", "LOCAL",
}


def _bounded_text(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def _normalize_mac(value: Any) -> str | None:
    text = _bounded_text(value, 64).upper().replace("-", ":")
    if not text or text in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
        return None
    return text if _MAC_RE.fullmatch(text) else None


def _normalize_ip(value: Any) -> str | None:
    text = _bounded_text(value, 96)
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if ip.is_multicast or ip.is_unspecified:
        return None
    return str(ip)


def _device_key(ip: str, mac: str | None, interface: str) -> str:
    # MAC is preferred for L2 identity; IP+interface is the bounded fallback.
    if mac:
        return f"mac:{mac.lower()}"
    return f"ip:{interface.lower()}:{ip.lower()}"


def load_trust_registry(path: str | os.PathLike[str]) -> dict[str, dict[str, Any] | str]:
    """Load a bounded, non-executable device trust registry.

    The registry is configuration evidence only; it does not grant OS/network
    authority and UNKNOWN entries are never promoted to DENIED implicitly.
    """
    target = os.fspath(path)
    try:
        size = os.path.getsize(target)
    except OSError:
        return {}
    if size < 0 or size > 256 * 1024:
        raise ValueError("NETWORK_TRUST_REGISTRY_TOO_LARGE")
    with open(target, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("NETWORK_TRUST_REGISTRY_INVALID")
    devices = payload.get("devices", payload)
    if not isinstance(devices, dict):
        raise ValueError("NETWORK_TRUST_REGISTRY_DEVICES_INVALID")
    return dict(list(devices.items())[:4096])


@dataclass(frozen=True)
class DeviceTrustRule:
    status: str
    label: str | None = None
    user_id: str | None = None
    user_verified: bool = False


class WindowsPassiveNetworkProvider:
    """Read-only local Windows telemetry provider.

    No probes, pings, socket connect attempts, packet injection, firewall changes,
    DNS resolution, or port scanning are performed.  Get-NetNeighbor only reads
    the host neighbor cache; psutil reads local adapter/connection state.
    """

    POWERSHELL_TIMEOUT_SECONDS = 3.0
    MAX_NEIGHBOR_JSON_BYTES = 1024 * 1024
    MAX_RAW_CONNECTIONS = 2048

    def _interfaces(self) -> list[dict[str, Any]]:
        if psutil is None:
            return []
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        rows: list[dict[str, Any]] = []
        for name in sorted(addresses)[:128]:
            addr_rows: list[dict[str, Any]] = []
            for addr in addresses.get(name, [])[:32]:
                family = str(getattr(addr.family, "name", addr.family))
                value = _bounded_text(addr.address, 160)
                if value:
                    addr_rows.append({"family": family, "address": value})
            stat = stats.get(name)
            rows.append({
                "name": _bounded_text(name, 128),
                "is_up": bool(getattr(stat, "isup", False)) if stat else None,
                "speed_mbps": int(getattr(stat, "speed", 0) or 0) if stat else None,
                "addresses": addr_rows,
            })
        return rows

    def _neighbors(self) -> list[dict[str, Any]]:
        if os.name != "nt":
            return []
        script = (
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
            "$ErrorActionPreference='Stop';"
            "$rows=Get-NetNeighbor | Where-Object {"
            "$_.State -notin @('Unreachable','Incomplete')"
            "} | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,State,AddressFamily;"
            "$rows | ConvertTo-Json -Compress -Depth 3"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=False,
            timeout=self.POWERSHELL_TIMEOUT_SECONDS,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            raise RuntimeError("NETWORK_NEIGHBOR_QUERY_FAILED")
        raw = bytes(completed.stdout or b"")
        if len(raw) > self.MAX_NEIGHBOR_JSON_BYTES:
            raise RuntimeError("NETWORK_NEIGHBOR_OUTPUT_TOO_LARGE")
        text = raw.decode("utf-8-sig", errors="strict").strip()
        if not text:
            return []
        payload = json.loads(text)
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []
        return [item for item in payload[:1024] if isinstance(item, dict)]

    def _connections(self) -> list[dict[str, Any]]:
        if psutil is None:
            return []
        try:
            raw = psutil.net_connections(kind="inet")
        except (OSError, RuntimeError, PermissionError):
            return []
        rows: list[dict[str, Any]] = []
        for conn in raw[: self.MAX_RAW_CONNECTIONS]:
            raddr = getattr(conn, "raddr", None)
            laddr = getattr(conn, "laddr", None)
            remote_ip = _normalize_ip(getattr(raddr, "ip", None) if raddr else None)
            local_ip = _normalize_ip(getattr(laddr, "ip", None) if laddr else None)
            if not remote_ip:
                continue
            rows.append({
                "local_ip": local_ip,
                "local_port": int(getattr(laddr, "port", 0) or 0) if laddr else 0,
                "remote_ip": remote_ip,
                "remote_port": int(getattr(raddr, "port", 0) or 0) if raddr else 0,
                "status": _bounded_text(getattr(conn, "status", ""), 32).upper() or "UNKNOWN",
                "pid": int(getattr(conn, "pid", 0) or 0),
            })
        return rows

    def collect(self) -> dict[str, Any]:
        return {
            "interfaces": self._interfaces(),
            "neighbors": self._neighbors(),
            "connections": self._connections(),
        }


class PassiveNetworkInventory:
    VERSION = "0.1"
    MODE = "PASSIVE_ONLY"
    AUTHORITY = "NONE"

    def __init__(
        self,
        provider: WindowsPassiveNetworkProvider | Callable[[], dict[str, Any]] | None = None,
        *,
        trust_registry: dict[str, dict[str, Any] | str] | None = None,
        max_devices: int = 256,
        max_connections: int = 256,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.provider = provider or WindowsPassiveNetworkProvider()
        self.clock = clock
        self.max_devices = max(16, min(int(max_devices), 2048))
        self.max_connections = max(16, min(int(max_connections), 4096))
        self._devices: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._trust = self._compile_registry(trust_registry or {})
        self.samples = 0
        self.failures = 0
        self.evictions = 0
        self.last_error: str | None = None
        self.last_sample_at: float | None = None
        self.last_duration_ms: float | None = None

    @staticmethod
    def _compile_registry(source: dict[str, dict[str, Any] | str]) -> dict[str, DeviceTrustRule]:
        compiled: dict[str, DeviceTrustRule] = {}
        for raw_key, raw_value in list(source.items())[:4096]:
            key = _bounded_text(raw_key, 160).lower()
            if not key:
                continue
            if isinstance(raw_value, str):
                status = raw_value.upper().strip()
                payload: dict[str, Any] = {}
            elif isinstance(raw_value, dict):
                payload = raw_value
                status = _bounded_text(payload.get("status"), 32).upper()
            else:
                continue
            if status not in _ALLOWED_TRUST:
                continue
            user_verified = bool(payload.get("user_verified", False))
            user_id = _bounded_text(payload.get("user_id"), 128) or None
            # A user identifier is never treated as verified unless explicitly bound.
            if not user_verified:
                user_id = None
            compiled[key] = DeviceTrustRule(
                status=status,
                label=_bounded_text(payload.get("label"), 128) or None,
                user_id=user_id,
                user_verified=user_verified,
            )
        return compiled

    @staticmethod
    def _local_ips(interfaces: list[dict[str, Any]]) -> set[str]:
        values: set[str] = set()
        for interface in interfaces[:128]:
            if not isinstance(interface, dict):
                continue
            for addr in interface.get("addresses", [])[:32] if isinstance(interface.get("addresses"), list) else []:
                if not isinstance(addr, dict):
                    continue
                ip = _normalize_ip(addr.get("address"))
                if ip:
                    values.add(ip)
        return values

    def _trust_for(self, ip: str, mac: str | None, *, local: bool) -> DeviceTrustRule:
        if local:
            return DeviceTrustRule("LOCAL", label="This endpoint")
        keys = []
        if mac:
            keys.extend([f"mac:{mac.lower()}", mac.lower()])
        keys.extend([f"ip:{ip.lower()}", ip.lower()])
        for key in keys:
            rule = self._trust.get(key)
            if rule is not None:
                return rule
        return DeviceTrustRule("UNKNOWN")

    def collect(self) -> dict[str, Any]:
        started = time.perf_counter()
        now = float(self.clock())
        try:
            raw = self.provider.collect() if hasattr(self.provider, "collect") else self.provider()
            if not isinstance(raw, dict):
                raise TypeError("NETWORK_PROVIDER_INVALID")
            interfaces = raw.get("interfaces", []) if isinstance(raw.get("interfaces"), list) else []
            neighbors = raw.get("neighbors", []) if isinstance(raw.get("neighbors"), list) else []
            connections = raw.get("connections", []) if isinstance(raw.get("connections"), list) else []
            local_ips = self._local_ips(interfaces)

            seen_keys: set[str] = set()
            for item in neighbors[:4096]:
                if not isinstance(item, dict):
                    continue
                ip = _normalize_ip(item.get("IPAddress", item.get("ip")))
                if not ip:
                    continue
                mac = _normalize_mac(item.get("LinkLayerAddress", item.get("mac")))
                interface = _bounded_text(item.get("InterfaceAlias", item.get("interface")), 128) or "UNKNOWN"
                state = _bounded_text(item.get("State", item.get("state")), 32).upper() or "UNKNOWN"
                if state not in _ALLOWED_DEVICE_STATES:
                    state = "UNKNOWN"
                local = ip in local_ips
                identity = _device_key(ip, mac, interface)
                seen_keys.add(identity)
                trust = self._trust_for(ip, mac, local=local)
                previous = self._devices.get(identity, {})
                row = {
                    "device_id": identity,
                    "ip_address": ip,
                    "mac_address": mac,
                    "interface": interface,
                    "neighbor_state": "LOCAL" if local else state,
                    "online": True,
                    "first_seen": float(previous.get("first_seen", now)),
                    "last_seen": now,
                    "trust": trust.status,
                    "label": trust.label,
                    "user_identity": {
                        "status": "VERIFIED" if trust.user_verified and trust.user_id else "UNKNOWN",
                        "user_id": trust.user_id if trust.user_verified else None,
                    },
                    "source": "LOCAL" if local else "NEIGHBOR_CACHE",
                    "passive": True,
                }
                self._devices[identity] = row
                self._devices.move_to_end(identity)

            # Keep previously observed identities as stale evidence rather than silently deleting them.
            for identity, row in list(self._devices.items()):
                if identity not in seen_keys and row.get("source") != "LOCAL":
                    row = dict(row)
                    row["online"] = False
                    row["neighbor_state"] = "STALE"
                    self._devices[identity] = row

            while len(self._devices) > self.max_devices:
                self._devices.popitem(last=False)
                self.evictions += 1

            bounded_connections: list[dict[str, Any]] = []
            for item in connections[: self.max_connections]:
                if not isinstance(item, dict):
                    continue
                remote_ip = _normalize_ip(item.get("remote_ip"))
                if not remote_ip:
                    continue
                bounded_connections.append({
                    "local_ip": _normalize_ip(item.get("local_ip")),
                    "local_port": int(item.get("local_port", 0) or 0),
                    "remote_ip": remote_ip,
                    "remote_port": int(item.get("remote_port", 0) or 0),
                    "status": _bounded_text(item.get("status"), 32).upper() or "UNKNOWN",
                    "pid": int(item.get("pid", 0) or 0),
                    "passive": True,
                })

            devices = list(self._devices.values())
            counts = {name: 0 for name in ("LOCAL", "AUTHORIZED", "UNKNOWN", "DENIED", "REVOKED")}
            for row in devices:
                status = str(row.get("trust", "UNKNOWN")).upper()
                counts[status if status in counts else "UNKNOWN"] += 1

            self.samples += 1
            self.last_error = None
            self.last_sample_at = now
            self.last_duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return {
                "schema": "cyberdefender.network-inventory.v0.1",
                "version": self.VERSION,
                "mode": self.MODE,
                "authority": self.AUTHORITY,
                "authoritative": False,
                "active_scan_enabled": False,
                "packet_injection": False,
                "firewall_mutation": False,
                "dns_resolution": False,
                "user_identity_inference": False,
                "unknown_is_unauthorized": False,
                "sampled_at": now,
                "duration_ms": self.last_duration_ms,
                "summary": {
                    "devices_total": len(devices),
                    "online": sum(1 for row in devices if row.get("online")),
                    "connections_total": len(bounded_connections),
                    "local": counts["LOCAL"],
                    "authorized": counts["AUTHORIZED"],
                    "unknown": counts["UNKNOWN"],
                    "denied": counts["DENIED"],
                    "revoked": counts["REVOKED"],
                },
                "interfaces": interfaces[:32],
                "devices": devices[-self.max_devices :],
                "connections": bounded_connections,
                "bounds": {
                    "max_devices": self.max_devices,
                    "max_connections": self.max_connections,
                    "evictions": self.evictions,
                },
            }
        except Exception as exc:
            self.failures += 1
            self.last_error = type(exc).__name__
            self.last_duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
            raise

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "PassiveNetworkInventory",
            "version": self.VERSION,
            "status": "HEALTHY" if self.last_error is None else "DEGRADED",
            "mode": self.MODE,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "active_scan_enabled": False,
            "dashboard_direct_os_access": False,
            "packet_injection": False,
            "firewall_mutation": False,
            "samples": self.samples,
            "failures": self.failures,
            "evictions": self.evictions,
            "last_sample_at": self.last_sample_at,
            "last_duration_ms": self.last_duration_ms,
            "last_error": self.last_error,
        }
