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

from .dns_cache import WindowsDnsCacheReader
from .flow_telemetry import InterfaceFlowTracker
from .process_attribution import ProcessAttributionResolver

try:
    import psutil
except Exception:  # pragma: no cover - runtime health reports dependency absence
    psutil = None


_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
_ALLOWED_TRUST = {"AUTHORIZED", "UNKNOWN", "DENIED", "REVOKED"}
_ALLOWED_DEVICE_STATES = {
    "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "UNKNOWN",
}


def _bounded_text(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def _canonical_mac_text(value: Any) -> str:
    return _bounded_text(value, 64).upper().replace("-", ":")


def _normalize_mac(value: Any) -> str | None:
    text = _canonical_mac_text(value)
    if not text or not _MAC_RE.fullmatch(text):
        return None
    # Neighbor identities are unicast L2 identities only. Broadcast/multicast
    # MACs (including 01:00:5E IPv4 and 33:33 IPv6 multicast mappings) are
    # protocol control addresses, not peer devices.
    first_octet = int(text.split(":", 1)[0], 16)
    if first_octet & 0x01:
        return None
    if text == "00:00:00:00:00:00":
        return None
    return text


def _raw_mac_is_non_unicast(value: Any) -> bool:
    text = _canonical_mac_text(value)
    if not text or not _MAC_RE.fullmatch(text):
        return False
    first_octet = int(text.split(":", 1)[0], 16)
    return bool(first_octet & 0x01)


def _normalize_ip(value: Any) -> str | None:
    text = _bounded_text(value, 96)
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        return None
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return None
    return str(ip)


def _device_key(ip: str, mac: str | None, interface: str) -> str:
    # MAC is preferred for L2 identity; IP+interface is the bounded fallback.
    if mac:
        return f"mac:{mac.lower()}"
    return f"ip:{interface.lower()}:{ip.lower()}"


def load_trust_registry(path: str | os.PathLike[str]) -> dict[str, dict[str, Any] | str]:
    """Load a bounded, non-executable peer trust registry.

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
    evidence_type: str = "NONE"
    evidence_ref: str | None = None


class WindowsPassiveNetworkProvider:
    """Read-only local Windows telemetry provider.

    No probes, pings, socket connect attempts, packet injection, firewall changes,
    DNS resolution, or port scanning are performed. A single PowerShell snapshot
    identifies active default-route interfaces and reads only their neighbor cache.
    psutil reads local adapter/connection state.
    """

    POWERSHELL_TIMEOUT_SECONDS = 3.0
    MAX_WINDOWS_JSON_BYTES = 1024 * 1024
    MAX_RAW_CONNECTIONS = 2048

    def __init__(
        self,
        process_resolver: ProcessAttributionResolver | None = None,
        dns_reader: WindowsDnsCacheReader | None = None,
    ) -> None:
        self.process_resolver = process_resolver or ProcessAttributionResolver()
        self.dns_reader = dns_reader or WindowsDnsCacheReader()

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

    def _windows_network_snapshot(self) -> dict[str, Any]:
        if os.name != "nt":
            return {"active_networks": [], "neighbors": []}
        script = (
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
            "$ErrorActionPreference='Stop';"
            "$cfgs=@(Get-NetIPConfiguration | Where-Object {"
            "$_.NetAdapter.Status -eq 'Up' -and $null -ne $_.IPv4DefaultGateway"
            "});"
            "$active=@();$neighbors=@();"
            "foreach($cfg in $cfgs){"
            "$ip=$null;$prefix=$null;"
            "if($cfg.IPv4Address){$ip=$cfg.IPv4Address[0].IPAddress;$prefix=$cfg.IPv4Address[0].PrefixLength};"
            "$gw=$cfg.IPv4DefaultGateway.NextHop;"
            "$active += [pscustomobject]@{InterfaceAlias=$cfg.InterfaceAlias;InterfaceIndex=$cfg.InterfaceIndex;IPv4Address=$ip;PrefixLength=$prefix;Gateway=$gw};"
            "$neighbors += @(Get-NetNeighbor -InterfaceIndex $cfg.InterfaceIndex | Where-Object {"
            "$_.State -notin @('Unreachable','Incomplete')"
            "} | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,LinkLayerAddress,State,AddressFamily)"
            "};"
            "[pscustomobject]@{ActiveNetworks=$active;Neighbors=$neighbors} | ConvertTo-Json -Compress -Depth 4"
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
            raise RuntimeError("NETWORK_WINDOWS_SNAPSHOT_FAILED")
        raw = bytes(completed.stdout or b"")
        if len(raw) > self.MAX_WINDOWS_JSON_BYTES:
            raise RuntimeError("NETWORK_WINDOWS_OUTPUT_TOO_LARGE")
        text = raw.decode("utf-8-sig", errors="strict").strip()
        if not text:
            return {"active_networks": [], "neighbors": []}
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return {"active_networks": [], "neighbors": []}
        active = payload.get("ActiveNetworks", [])
        neighbors = payload.get("Neighbors", [])
        if isinstance(active, dict):
            active = [active]
        if isinstance(neighbors, dict):
            neighbors = [neighbors]
        return {
            "active_networks": [x for x in active[:32] if isinstance(x, dict)] if isinstance(active, list) else [],
            "neighbors": [x for x in neighbors[:1024] if isinstance(x, dict)] if isinstance(neighbors, list) else [],
        }

    def _flow_counters(self) -> list[dict[str, Any]]:
        """Read local interface cumulative counters only.

        These are interface-level OS counters, not per-connection byte counts.
        No packet capture, socket hook, ETW session, probe, or remote lookup is
        performed here.
        """
        if psutil is None:
            return []
        try:
            counters = psutil.net_io_counters(pernic=True, nowrap=True)
        except (OSError, RuntimeError, PermissionError, TypeError):
            return []
        rows: list[dict[str, Any]] = []
        for name in sorted(counters)[:128]:
            item = counters.get(name)
            if item is None:
                continue
            rows.append({
                "interface": _bounded_text(name, 128),
                "bytes_sent": int(getattr(item, "bytes_sent", 0) or 0),
                "bytes_recv": int(getattr(item, "bytes_recv", 0) or 0),
                "packets_sent": int(getattr(item, "packets_sent", 0) or 0),
                "packets_recv": int(getattr(item, "packets_recv", 0) or 0),
                "errin": int(getattr(item, "errin", 0) or 0),
                "errout": int(getattr(item, "errout", 0) or 0),
                "dropin": int(getattr(item, "dropin", 0) or 0),
                "dropout": int(getattr(item, "dropout", 0) or 0),
            })
        return rows

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

        attribution = self.process_resolver.resolve_many([int(row.get("pid", 0) or 0) for row in rows])
        for row in rows:
            pid = int(row.get("pid", 0) or 0)
            row["process"] = attribution.get(pid, {
                "attribution_status": "UNAVAILABLE",
                "pid": pid,
                "authority": "NONE",
                "authorization": "NOT_GRANTED",
            })
        return rows

    def collect(self) -> dict[str, Any]:
        windows = self._windows_network_snapshot()
        dns_cache = self.dns_reader.read()
        return {
            "interfaces": self._interfaces(),
            "active_networks": windows["active_networks"],
            "neighbors": windows["neighbors"],
            "connections": self._connections(),
            "flow_counters": self._flow_counters(),
            "process_attribution": self.process_resolver.health_check(),
            "dns_cache": dns_cache,
        }

    def close(self) -> None:
        self.process_resolver.close()


class PassiveNetworkInventory:
    VERSION = "0.1.7"
    MODE = "PASSIVE_ONLY"
    AUTHORITY = "NONE"

    def __init__(
        self,
        provider: WindowsPassiveNetworkProvider | Callable[[], dict[str, Any]] | None = None,
        *,
        trust_registry: dict[str, dict[str, Any] | str] | None = None,
        trust_registry_path: str | os.PathLike[str] | None = None,
        max_devices: int = 256,
        max_connections: int = 256,
        clock: Callable[[], float] = time.time,
        flow_tracker: InterfaceFlowTracker | None = None,
    ) -> None:
        self.provider = provider or WindowsPassiveNetworkProvider()
        self.clock = clock
        self.flow_tracker = flow_tracker or InterfaceFlowTracker()
        self.max_devices = max(16, min(int(max_devices), 2048))
        self.max_connections = max(16, min(int(max_connections), 4096))
        self._devices: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._trust = self._compile_registry(trust_registry or {})
        self._trust_registry_path = os.fspath(trust_registry_path) if trust_registry_path is not None else None
        self._trust_registry_fingerprint: tuple[int, int] | None = None
        self.trust_registry_reloads = 0
        self.trust_registry_failures = 0
        self.trust_registry_last_error: str | None = None
        self.trust_registry_last_loaded_at: float | None = None
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
            if not user_verified:
                user_id = None
            compiled[key] = DeviceTrustRule(
                status=status,
                label=_bounded_text(payload.get("label"), 128) or None,
                user_id=user_id,
                user_verified=user_verified,
                evidence_type=_bounded_text(payload.get("evidence_type"), 48).upper() or "EXPLICIT_LOCAL_RULE",
                evidence_ref=_bounded_text(payload.get("evidence_ref"), 160) or None,
            )
        return compiled

    def _refresh_trust_registry(self) -> None:
        """Reload optional local trust evidence without granting authority.

        Missing or invalid registry evidence fails safe to UNKNOWN. A malformed
        update can never preserve an AUTHORIZED label merely because an older
        file was valid. The registry remains display/correlation evidence only.
        """
        path = self._trust_registry_path
        if not path:
            return
        now = float(self.clock())
        try:
            stat = os.stat(path)
            fingerprint = (int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))), int(stat.st_size))
        except FileNotFoundError:
            if self._trust or self._trust_registry_fingerprint is not None:
                self._trust = {}
                self._trust_registry_fingerprint = None
                self.trust_registry_reloads += 1
            self.trust_registry_last_error = None
            self.trust_registry_last_loaded_at = now
            return
        except OSError as exc:
            self._trust = {}
            self._trust_registry_fingerprint = None
            self.trust_registry_failures += 1
            self.trust_registry_last_error = type(exc).__name__
            return

        if fingerprint == self._trust_registry_fingerprint:
            return
        try:
            source = load_trust_registry(path)
            compiled = self._compile_registry(source)
        except Exception as exc:
            self._trust = {}
            self._trust_registry_fingerprint = fingerprint
            self.trust_registry_failures += 1
            self.trust_registry_last_error = type(exc).__name__
            self.trust_registry_last_loaded_at = now
            return
        self._trust = compiled
        self._trust_registry_fingerprint = fingerprint
        self.trust_registry_reloads += 1
        self.trust_registry_last_error = None
        self.trust_registry_last_loaded_at = now

    @staticmethod
    def _normalized_active_networks(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for raw in rows[:32]:
            if not isinstance(raw, dict):
                continue
            interface = _bounded_text(raw.get("InterfaceAlias", raw.get("interface")), 128) or "UNKNOWN"
            index = int(raw.get("InterfaceIndex", raw.get("interface_index", 0)) or 0)
            local_ip = _normalize_ip(raw.get("IPv4Address", raw.get("local_ipv4")))
            gateway = _normalize_ip(raw.get("Gateway", raw.get("gateway")))
            try:
                prefix = int(raw.get("PrefixLength", raw.get("prefix_length", 0)) or 0)
            except (TypeError, ValueError):
                prefix = 0
            if prefix < 0 or prefix > 32:
                prefix = 0
            result.append({
                "interface": interface,
                "interface_index": index,
                "local_ipv4": local_ip,
                "prefix_length": prefix,
                "gateway": gateway,
                "role": "DEFAULT_ROUTE",
            })
        return result

    @staticmethod
    def _active_interface_names(active_networks: list[dict[str, Any]]) -> set[str]:
        return {
            str(row.get("interface", "")).lower()
            for row in active_networks
            if row.get("interface")
        }

    @staticmethod
    def _gateway_ips(active_networks: list[dict[str, Any]]) -> set[str]:
        return {str(row["gateway"]) for row in active_networks if row.get("gateway")}

    @staticmethod
    def _broadcast_ips(active_networks: list[dict[str, Any]]) -> set[str]:
        result: set[str] = {"255.255.255.255"}
        for row in active_networks:
            ip = row.get("local_ipv4")
            prefix = row.get("prefix_length")
            if not ip or not isinstance(prefix, int) or prefix <= 0:
                continue
            try:
                network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            except ValueError:
                continue
            if isinstance(network, ipaddress.IPv4Network):
                result.add(str(network.broadcast_address))
        return result

    def _trust_for(self, ip: str, mac: str | None) -> DeviceTrustRule:
        keys = []
        if mac:
            keys.extend([f"mac:{mac.lower()}", mac.lower()])
        keys.extend([f"ip:{ip.lower()}", ip.lower()])
        for key in keys:
            rule = self._trust.get(key)
            if rule is not None:
                return rule
        return DeviceTrustRule("UNKNOWN")

    @staticmethod
    def _dns_index(raw_dns: dict[str, Any]) -> dict[str, list[str]]:
        """Build a bounded IP -> DNS-name index from passive cache evidence."""
        result: dict[str, list[str]] = {}
        entries = raw_dns.get("entries", []) if isinstance(raw_dns, dict) else []
        if not isinstance(entries, list):
            return result
        for item in entries[:4096]:
            if not isinstance(item, dict):
                continue
            ip = _normalize_ip(item.get("ip_address"))
            name = _bounded_text(item.get("name"), 253).rstrip(".").lower()
            if not ip or not name:
                continue
            names = result.setdefault(ip, [])
            if name not in names and len(names) < 4:
                names.append(name)
        return result

    def collect(self) -> dict[str, Any]:
        started = time.perf_counter()
        now = float(self.clock())
        try:
            self._refresh_trust_registry()
            raw = self.provider.collect() if hasattr(self.provider, "collect") else self.provider()
            if not isinstance(raw, dict):
                raise TypeError("NETWORK_PROVIDER_INVALID")
            interfaces = raw.get("interfaces", []) if isinstance(raw.get("interfaces"), list) else []
            active_networks = self._normalized_active_networks(
                raw.get("active_networks", []) if isinstance(raw.get("active_networks"), list) else []
            )
            neighbors = raw.get("neighbors", []) if isinstance(raw.get("neighbors"), list) else []
            connections = raw.get("connections", []) if isinstance(raw.get("connections"), list) else []
            dns_cache = raw.get("dns_cache", {}) if isinstance(raw.get("dns_cache"), dict) else {}
            dns_index = self._dns_index(dns_cache)

            active_names = self._active_interface_names(active_networks)
            flow_telemetry = self.flow_tracker.observe(
                raw.get("flow_counters", []) if isinstance(raw.get("flow_counters"), list) else [],
                active_interfaces=active_names,
            )
            gateway_ips = self._gateway_ips(active_networks)
            broadcast_ips = self._broadcast_ips(active_networks)

            seen_keys: set[str] = set()
            for item in neighbors[:4096]:
                if not isinstance(item, dict):
                    continue
                interface = _bounded_text(item.get("InterfaceAlias", item.get("interface")), 128) or "UNKNOWN"
                # If active-route context exists, only that scope can contribute current peers.
                if active_names and interface.lower() not in active_names:
                    continue

                raw_ip = item.get("IPAddress", item.get("ip"))
                ip = _normalize_ip(raw_ip)
                if not ip or ip in broadcast_ips:
                    continue

                raw_mac = item.get("LinkLayerAddress", item.get("mac"))
                if _raw_mac_is_non_unicast(raw_mac):
                    continue
                mac = _normalize_mac(raw_mac)

                state = _bounded_text(item.get("State", item.get("state")), 32).upper() or "UNKNOWN"
                if state not in _ALLOWED_DEVICE_STATES:
                    state = "UNKNOWN"

                identity = _device_key(ip, mac, interface)
                seen_keys.add(identity)
                trust = self._trust_for(ip, mac)
                previous = self._devices.get(identity, {})
                role = "GATEWAY" if ip in gateway_ips else "PEER"
                row = {
                    "device_id": identity,
                    "ip_address": ip,
                    "mac_address": mac,
                    "interface": interface,
                    "neighbor_state": state,
                    "online": True,
                    "first_seen": float(previous.get("first_seen", now)),
                    "last_seen": now,
                    "trust": trust.status,
                    "label": trust.label,
                    "trust_evidence": {
                        "source": "LOCAL_REGISTRY" if trust.status != "UNKNOWN" else "NO_MATCH",
                        "evidence_type": trust.evidence_type if trust.status != "UNKNOWN" else "NONE",
                        "evidence_ref": trust.evidence_ref if trust.status != "UNKNOWN" else None,
                        "authoritative": False,
                        "authorization": "NOT_GRANTED",
                    },
                    "user_identity": {
                        "status": "VERIFIED" if trust.user_verified and trust.user_id else "UNKNOWN",
                        "user_id": trust.user_id if trust.user_verified else None,
                    },
                    "role": role,
                    "source": "NEIGHBOR_CACHE",
                    "passive": True,
                }
                self._devices[identity] = row
                self._devices.move_to_end(identity)

            # Historical evidence is retained as stale, but current/online counts are
            # always derived from this sample only.
            for identity, row in list(self._devices.items()):
                if identity not in seen_keys:
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
                    "process": item.get("process") if isinstance(item.get("process"), dict) else {
                        "attribution_status": "UNAVAILABLE",
                        "pid": int(item.get("pid", 0) or 0),
                        "authority": "NONE",
                        "authorization": "NOT_GRANTED",
                    },
                    "dns": {
                        "names": list(dns_index.get(remote_ip, [])),
                        "source": "WINDOWS_DNS_CACHE" if dns_index.get(remote_ip) else "NO_MATCH",
                        "passive": True,
                        "authoritative": False,
                        "authority": "NONE",
                        "authorization": "NOT_GRANTED",
                    },
                    "passive": True,
                })

            devices = list(self._devices.values())
            online_devices = [row for row in devices if row.get("online")]
            counts = {name: 0 for name in ("AUTHORIZED", "UNKNOWN", "DENIED", "REVOKED")}
            for row in online_devices:
                status = str(row.get("trust", "UNKNOWN")).upper()
                counts[status if status in counts else "UNKNOWN"] += 1

            gateways_observed = sum(1 for row in online_devices if row.get("role") == "GATEWAY")
            other_peers_observed = sum(1 for row in online_devices if row.get("role") == "PEER")
            local_endpoint_count = 1 if active_networks else 0
            dns_correlated_connections = sum(
                1 for row in bounded_connections if (row.get("dns") or {}).get("names")
            )

            self.samples += 1
            self.last_error = None
            self.last_sample_at = now
            self.last_duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return {
                "schema": "cyberdefender.network-inventory.v0.1.7",
                "version": self.VERSION,
                "mode": self.MODE,
                "authority": self.AUTHORITY,
                "authoritative": False,
                "active_scan_enabled": False,
                "packet_injection": False,
                "firewall_mutation": False,
                "dns_resolution": False,
                "dns_cache_observation": True,
                "flow_telemetry_observation": True,
                "packet_capture": False,
                "per_connection_byte_attribution": False,
                "external_dns_queries": False,
                "reverse_dns_lookup": False,
                "user_identity_inference": False,
                "unknown_is_unauthorized": False,
                "hotspot_client_count": None,
                "hotspot_client_count_authoritative": False,
                "hotspot_client_count_reason": "AP_CONTROLLER_EVIDENCE_UNAVAILABLE",
                "sampled_at": now,
                "duration_ms": self.last_duration_ms,
                "summary": {
                    "local_endpoint_count": local_endpoint_count,
                    "observed_peers_total": len(devices),
                    "observed_peers_online": len(online_devices),
                    "gateways_observed": gateways_observed,
                    "other_peers_observed": other_peers_observed,
                    "connections_total": len(bounded_connections),
                    "dns_cache_entries": int(dns_cache.get("entries_observed", 0) or 0),
                    "dns_unique_names": int(dns_cache.get("unique_names", 0) or 0),
                    "dns_correlated_connections": dns_correlated_connections,
                    "flow_active_interfaces": int((flow_telemetry.get("aggregate") or {}).get("active_interfaces", 0) or 0),
                    "flow_baseline_ready": bool((flow_telemetry.get("aggregate") or {}).get("baseline_ready", False)),
                    "flow_rx_bytes_per_second": float((flow_telemetry.get("aggregate") or {}).get("rx_bytes_per_second", 0.0) or 0.0),
                    "flow_tx_bytes_per_second": float((flow_telemetry.get("aggregate") or {}).get("tx_bytes_per_second", 0.0) or 0.0),
                    "authorized": counts["AUTHORIZED"],
                    "unknown": counts["UNKNOWN"],
                    "denied": counts["DENIED"],
                    "revoked": counts["REVOKED"],
                    # Compatibility aliases. These are explicitly NOT AP/client counts.
                    "devices_total": len(devices),
                    "online": len(online_devices),
                },
                "count_semantics": {
                    "devices_total": "OBSERVED_NEIGHBOR_IDENTITIES_NOT_CONNECTED_CLIENTS",
                    "online": "CURRENTLY_OBSERVED_NEIGHBOR_IDENTITIES",
                    "connections_total": "LOCAL_SOCKET_FLOW_OBSERVATIONS",
                    "flow_rates": "ACTIVE_INTERFACE_COUNTER_DELTAS_NOT_PER_CONNECTION_BYTES",
                    "hotspot_client_count": "UNAVAILABLE_WITHOUT_AP_CONTROLLER_EVIDENCE",
                },
                "active_networks": active_networks,
                "interfaces": interfaces[:32],
                "devices": devices[-self.max_devices :],
                "connections": bounded_connections,
                "dns_cache": {
                    "schema": "cyberdefender.dns-cache-runtime.v0.1.6.1",
                    "reader_version": _bounded_text(dns_cache.get("version"), 24) or None,
                    "mode": "PASSIVE_LOCAL_CACHE",
                    "status": _bounded_text(dns_cache.get("status"), 32).upper() or "UNAVAILABLE",
                    "available": bool(dns_cache.get("available", False)),
                    "authority": "NONE",
                    "authoritative": False,
                    "external_queries": False,
                    "reverse_lookup": False,
                    "raw_rows_observed": int(dns_cache.get("raw_rows_observed", 0) or 0),
                    "entries_observed": int(dns_cache.get("entries_observed", 0) or 0),
                    "unique_names": int(dns_cache.get("unique_names", 0) or 0),
                    "unique_ips": int(dns_cache.get("unique_ips", 0) or 0),
                    "correlated_connections": dns_correlated_connections,
                    "last_error": _bounded_text(dns_cache.get("last_error"), 96) or None,
                },
                "flow_telemetry": flow_telemetry,
                "process_attribution": raw.get("process_attribution", {}) if isinstance(raw.get("process_attribution"), dict) else {},
                "trust_registry": {
                    "schema": "cyberdefender.network-trust-runtime.v0.1.5",
                    "mode": "EXPLICIT_LOCAL_EVIDENCE",
                    "authority": "NONE",
                    "authoritative": False,
                    "rules_loaded": len(self._trust),
                    "reloads": self.trust_registry_reloads,
                    "failures": self.trust_registry_failures,
                    "last_error": self.trust_registry_last_error,
                    "last_loaded_at": self.trust_registry_last_loaded_at,
                    "auto_whitelist": False,
                },
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

    def close(self) -> None:
        method = getattr(self.provider, "close", None)
        if callable(method):
            try:
                method()
            except Exception:
                pass

    def health_check(self) -> dict[str, Any]:
        process_health: dict[str, Any] = {}
        resolver = getattr(self.provider, "process_resolver", None)
        method = getattr(resolver, "health_check", None)
        if callable(method):
            try:
                candidate = method()
                if isinstance(candidate, dict):
                    process_health = candidate
            except Exception as exc:
                process_health = {"status": "DEGRADED", "error": type(exc).__name__, "authority": "NONE"}
        return {
            "component": "PassiveNetworkInventory",
            "version": self.VERSION,
            "status": "HEALTHY" if self.last_error is None else "DEGRADED",
            "mode": self.MODE,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "active_scan_enabled": False,
            "dns_cache_observation": True,
            "flow_telemetry_observation": True,
            "packet_capture": False,
            "per_connection_byte_attribution": False,
            "external_dns_queries": False,
            "reverse_dns_lookup": False,
            "dashboard_direct_os_access": False,
            "packet_injection": False,
            "firewall_mutation": False,
            "hotspot_client_count_authoritative": False,
            "samples": self.samples,
            "failures": self.failures,
            "evictions": self.evictions,
            "last_sample_at": self.last_sample_at,
            "last_duration_ms": self.last_duration_ms,
            "last_error": self.last_error,
            "process_attribution": process_health,
            "trust_registry": {
                "authority": "NONE",
                "rules_loaded": len(self._trust),
                "reloads": self.trust_registry_reloads,
                "failures": self.trust_registry_failures,
                "last_error": self.trust_registry_last_error,
                "auto_whitelist": False,
            },
        }
