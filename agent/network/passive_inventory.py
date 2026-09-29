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

from .active_verification import BoundedNetworkVerifier
from .dns_cache import WindowsDnsCacheReader
from .flow_continuity import PassiveInterfaceFlowSampler
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


def _device_key(ip: str, mac: str | None, interface: str, endpoint_id: str | None = None) -> str:
    # MAC is preferred for L2 identity; IP+interface is the bounded fallback.
    endpoint = _bounded_text(endpoint_id, 160).lower()
    prefix = f"endpoint:{endpoint}:" if endpoint else ""
    if mac:
        return f"{prefix}mac:{mac.lower()}"
    return f"{prefix}ip:{interface.lower()}:{ip.lower()}"


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

    # Host profiling showed the read-only NetTCP/IP snapshot can take about
    # 3.2 seconds on Windows 11.  Keep a finite 5-second budget so a slow CIM
    # provider cannot stall the Agent indefinitely; AsyncPassiveNetworkInventory
    # isolates this optional collector from the core protection loop.
    POWERSHELL_TIMEOUT_SECONDS = 5.0
    MAX_WINDOWS_JSON_BYTES = 1024 * 1024
    MAX_RAW_CONNECTIONS = 2048

    def __init__(
        self,
        process_resolver: ProcessAttributionResolver | None = None,
        dns_reader: WindowsDnsCacheReader | None = None,
    ) -> None:
        self.process_resolver = process_resolver or ProcessAttributionResolver()
        self.dns_reader = dns_reader or WindowsDnsCacheReader()
        self.samples = 0
        self.failures = 0
        self.last_error: str | None = None
        self.last_duration_ms: float | None = None

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
        started = time.perf_counter()
        try:
            windows = self._windows_network_snapshot()
            dns_cache = self.dns_reader.read()
            result = {
                "interfaces": self._interfaces(),
                "active_networks": windows["active_networks"],
                "neighbors": windows["neighbors"],
                "connections": self._connections(),
                "flow_counters": self._flow_counters(),
                "process_attribution": self.process_resolver.health_check(),
                "dns_cache": dns_cache,
                "network_provider": self.health_check(),
            }
            self.samples += 1
            self.last_error = None
            self.last_duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return result
        except Exception as exc:
            self.failures += 1
            self.last_error = type(exc).__name__
            self.last_duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
            raise

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "WindowsPassiveNetworkProvider",
            "status": "DEGRADED" if self.last_error else "HEALTHY",
            "mode": "PASSIVE_WINDOWS_NEIGHBOR_CACHE",
            "authority": "NONE",
            "authoritative": False,
            "active_scan_enabled": False,
            "dns_resolution": False,
            "packet_capture": False,
            "firewall_mutation": False,
            "samples": self.samples,
            "failures": self.failures,
            "timeout_seconds": self.POWERSHELL_TIMEOUT_SECONDS,
            "last_duration_ms": self.last_duration_ms,
            "last_error": self.last_error,
        }

    def close(self) -> None:
        self.process_resolver.close()


class PassiveNetworkInventory:
    VERSION = "0.1.9"
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
        flow_continuity_sampler: PassiveInterfaceFlowSampler | None = None,
        verifier: BoundedNetworkVerifier | None = None,
    ) -> None:
        self.provider = provider or WindowsPassiveNetworkProvider()
        self.clock = clock
        self.flow_tracker = flow_tracker or InterfaceFlowTracker()
        self.flow_continuity_sampler = flow_continuity_sampler
        # Optional verification is an explicitly supplied policy-gated
        # enrichment plane.  The default remains passive-only.
        self.verifier = verifier
        if self.flow_continuity_sampler is None and isinstance(self.provider, WindowsPassiveNetworkProvider):
            self.flow_continuity_sampler = PassiveInterfaceFlowSampler()
        self._last_active_interface_names: set[str] = set()
        self.max_devices = max(16, min(int(max_devices), 2048))
        self.max_connections = max(16, min(int(max_connections), 4096))
        self._devices: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._gateway_baselines: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._endpoint_observations: dict[str, dict[str, Any]] = {}
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
    def _segment_for(interface: str, ip: str, active_networks: list[dict[str, Any]]) -> str | None:
        for network in active_networks:
            if str(network.get("interface", "")).lower() != interface.lower():
                continue
            local = network.get("local_ipv4")
            prefix = network.get("prefix_length")
            if not local or not isinstance(prefix, int) or prefix <= 0:
                continue
            try:
                candidate = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
                if ipaddress.ip_address(ip) in candidate:
                    return str(candidate)
            except ValueError:
                continue
        return None

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
            self._last_active_interface_names = set(active_names)
            if self.flow_continuity_sampler is not None:
                flow_telemetry = self.flow_continuity_sampler.snapshot(active_names)
            else:
                # Deterministic fixture/backward-compatible path. Production
                # Windows runtime uses the dedicated 1 Hz continuity sampler.
                flow_telemetry = self.flow_tracker.observe(
                    raw.get("flow_counters", []) if isinstance(raw.get("flow_counters"), list) else [],
                    active_interfaces=active_names,
                )
            gateway_ips = self._gateway_ips(active_networks)
            broadcast_ips = self._broadcast_ips(active_networks)
            anomaly_evidence: list[dict[str, Any]] = []
            ip_mac_seen: dict[tuple[str, str], str | None] = {}
            endpoint_seen: dict[str, dict[str, Any]] = {}

            def add_anomaly(kind: str, *, classification: str = "REVIEW_REQUIRED", **evidence: Any) -> None:
                row = {
                    "type": _bounded_text(kind, 64).upper(),
                    "classification": classification,
                    "evidence": {
                        key: value for key, value in evidence.items()
                        if value is not None
                    },
                    "authority": "NONE",
                    "authoritative": False,
                    "authorization": "NOT_GRANTED",
                    "provenance": "NEIGHBOR_CACHE",
                }
                anomaly_evidence.append(row)

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

                endpoint_id = _bounded_text(
                    item.get("endpoint_id", item.get("enrollment_id")), 160
                ) or None
                hostname = _bounded_text(
                    item.get("hostname", item.get("host_name")), 253
                ).rstrip(".").lower() or None
                segment = self._segment_for(interface, ip, active_networks)
                identity = _device_key(ip, mac, interface, endpoint_id)
                seen_keys.add(identity)
                trust = self._trust_for(ip, mac)
                previous = self._devices.get(identity, {})
                role = "GATEWAY" if ip in gateway_ips else "PEER"
                if previous == {} and mac:
                    add_anomaly(
                        "NEW_MAC_FIRST_SEEN",
                        classification=(
                            "SUSPICIOUS_UNAUTHORIZED"
                            if trust.status in {"DENIED", "REVOKED"}
                            else "OBSERVED_UNVERIFIED"
                        ),
                        ip_address=ip,
                        mac_address=mac,
                        interface=interface,
                    )
                for prior_row in self._devices.values():
                    if (
                        prior_row.get("interface", "").lower() == interface.lower()
                        and prior_row.get("ip_address") == ip
                        and prior_row.get("mac_address")
                        and mac
                        and prior_row.get("mac_address") != mac
                    ):
                        add_anomaly(
                            "IP_MAC_CONFLICT",
                            ip_address=ip,
                            interface=interface,
                            previous_mac=prior_row.get("mac_address"),
                            current_mac=mac,
                        )
                        break
                if trust.status == "UNKNOWN" and role == "PEER":
                    add_anomaly(
                        "UNENROLLED_ACTIVE_DEVICE",
                        ip_address=ip,
                        mac_address=mac,
                        interface=interface,
                    )
                ip_mac_key = (interface.lower(), ip)
                prior_mac = ip_mac_seen.get(ip_mac_key)
                if prior_mac is not None and mac is not None and prior_mac != mac:
                    add_anomaly(
                        "IP_MAC_CONFLICT",
                        ip_address=ip,
                        interface=interface,
                        previous_mac=prior_mac,
                        current_mac=mac,
                    )
                elif ip_mac_key not in ip_mac_seen:
                    ip_mac_seen[ip_mac_key] = mac
                if endpoint_id:
                    prior_endpoint = self._endpoint_observations.get(endpoint_id)
                    if prior_endpoint and prior_endpoint.get("ip_address") != ip:
                        add_anomaly(
                            "RAPID_IP_CHURN",
                            endpoint_id=endpoint_id,
                            previous_ip=prior_endpoint.get("ip_address"),
                            current_ip=ip,
                            interface=interface,
                        )
                    if prior_endpoint and prior_endpoint.get("mac_address") != mac:
                        add_anomaly(
                            "RAPID_MAC_CHURN",
                            endpoint_id=endpoint_id,
                            previous_mac=prior_endpoint.get("mac_address"),
                            current_mac=mac,
                            interface=interface,
                        )
                    endpoint_seen[endpoint_id] = {
                        "ip_address": ip,
                        "mac_address": mac,
                        "hostname": hostname,
                    }
                gateway_key = (interface.lower(), segment or "UNKNOWN", ip)
                if role == "GATEWAY" and mac:
                    previous_gateway = self._gateway_baselines.get(gateway_key) or {}
                    previous_gateway_mac = previous_gateway.get("mac_address")
                    if previous_gateway_mac and previous_gateway_mac != mac:
                        add_anomaly(
                            "GATEWAY_IDENTITY_CHANGED",
                            classification="SUSPICIOUS",
                            interface=interface,
                            segment=segment,
                            gateway_ip=ip,
                            previous_mac=previous_gateway_mac,
                            current_mac=mac,
                            first_seen=previous_gateway.get("first_seen", now),
                            last_seen=now,
                        )
                    if not previous_gateway_mac or previous_gateway_mac != mac:
                        self._gateway_baselines[gateway_key] = {
                            "mac_address": mac,
                            "first_seen": now,
                            "last_seen": now,
                        }
                    else:
                        previous_gateway["last_seen"] = now
                observed_name = (dns_index.get(ip) or [None])[0]
                if hostname and observed_name and hostname != observed_name:
                    add_anomaly(
                        "DNS_IDENTITY_MISMATCH",
                        endpoint_id=endpoint_id,
                        ip_address=ip,
                        hostname=hostname,
                        observed_name=observed_name,
                    )
                if bool(item.get("expected_agent_heartbeat")) and not bool(item.get("heartbeat_alive")):
                    add_anomaly(
                        "ACTIVE_PEER_WITHOUT_EXPECTED_AGENT_HEARTBEAT",
                        endpoint_id=endpoint_id,
                        ip_address=ip,
                        interface=interface,
                    )
                identity_state = "IDENTIFIED" if endpoint_id else ("PARTIAL" if (hostname or mac) else "UNKNOWN")
                trust_state = {
                    "AUTHORIZED": "AUTHORIZED",
                    "DENIED": "SUSPICIOUS",
                    "REVOKED": "SUSPICIOUS",
                }.get(trust.status, "UNVERIFIED")
                row = {
                    "device_id": identity,
                    "endpoint_id": endpoint_id,
                    "hostname": hostname,
                    "lab_label": _bounded_text(item.get("lab_label"), 128) or None,
                    "identity_state": identity_state,
                    "identity_evidence": [
                        source for source, present in (
                            ("AGENT_ENROLLMENT", bool(endpoint_id)),
                            ("NEIGHBOR_CACHE", True),
                            ("REVERSE_DNS", bool(observed_name)),
                        ) if present
                    ],
                    "observed_name": observed_name,
                    "ip_address": ip,
                    "mac_address": mac,
                    "interface": interface,
                    "segment": segment,
                    "neighbor_state": state,
                    "online": True,
                    "presence_state": "ACTIVE",
                    "first_seen": float(previous.get("first_seen", now)),
                    "last_seen": now,
                    "trust": trust.status,
                    "trust_state": trust_state,
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
                    "user_binding": {
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
                    row["presence_state"] = "STALE"
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
                process_evidence = item.get("process") if isinstance(item.get("process"), dict) else {
                    "attribution_status": "UNAVAILABLE",
                    "pid": int(item.get("pid", 0) or 0),
                    "attribution_confidence": "UNVERIFIED",
                    "evidence_provenance": ["PID_UNAVAILABLE"],
                    "authority": "NONE",
                    "authorization": "NOT_GRANTED",
                }
                bounded_connections.append({
                    "local_ip": _normalize_ip(item.get("local_ip")),
                    "local_port": int(item.get("local_port", 0) or 0),
                    "remote_ip": remote_ip,
                    "remote_port": int(item.get("remote_port", 0) or 0),
                    "status": _bounded_text(item.get("status"), 32).upper() or "UNKNOWN",
                    "pid": int(item.get("pid", 0) or 0),
                    "process": process_evidence,
                    "risk_evidence": [{
                        "type": "NETWORK_PROCESS_CORRELATION",
                        "remote_ip": remote_ip,
                        "pid": int(item.get("pid", 0) or 0),
                        "attribution_confidence": _bounded_text(process_evidence.get("attribution_confidence"), 24).upper() or "UNVERIFIED",
                        "authority": "NONE",
                        "authorization": "NOT_GRANTED",
                    }],
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
            self._endpoint_observations.update(endpoint_seen)
            online_devices = [row for row in devices if row.get("online")]
            if self.verifier is not None:
                try:
                    verification = self.verifier.verify(online_devices)
                except Exception as exc:
                    verification = {
                        "schema": "cyberdefender.network-verification.v0.1.0",
                        "version": "0.1.0",
                        "mode": "BOUNDED_ACTIVE_VERIFICATION",
                        "status": "DEGRADED",
                        "enabled": False,
                        "dns_resolution": False,
                        "active_scan_enabled": False,
                        "authority": "NONE",
                        "authoritative": False,
                        "authorization": "NOT_GRANTED",
                        "results": [],
                        "failures": 1,
                        "last_error": type(exc).__name__,
                    }
                result_by_ip = {
                    str(item.get("ip_address")): item
                    for item in verification.get("results", [])
                    if isinstance(item, dict) and item.get("ip_address")
                }
                for row in online_devices:
                    evidence = result_by_ip.get(str(row.get("ip_address")))
                    if not evidence:
                        continue
                    row["network_verification"] = evidence
                    observed_name = evidence.get("observed_name")
                    if observed_name:
                        row["observed_name"] = observed_name
            else:
                verification = {
                    "schema": "cyberdefender.network-verification.v0.1.0",
                    "version": "0.1.0",
                    "mode": "DISABLED",
                    "status": "DISABLED",
                    "enabled": False,
                    "dns_resolution": False,
                    "active_scan_enabled": False,
                    "authority": "NONE",
                    "authoritative": False,
                    "authorization": "NOT_GRANTED",
                    "results": [],
                }
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
                "schema": "cyberdefender.network-inventory.v0.1.9",
                "version": self.VERSION,
                "mode": (
                    "PASSIVE_PLUS_BOUNDED_VERIFICATION"
                    if verification.get("enabled")
                    else self.MODE
                ),
                "authority": self.AUTHORITY,
                "authoritative": False,
                "active_scan_enabled": bool(verification.get("active_scan_enabled", False)),
                "packet_injection": False,
                "firewall_mutation": False,
                "dns_resolution": bool(verification.get("dns_resolution", False)),
                "dns_cache_observation": True,
                "flow_telemetry_observation": True,
                "packet_capture": False,
                "per_connection_byte_attribution": False,
                "external_dns_queries": False,
                "reverse_dns_lookup": bool(verification.get("dns_resolution", False)),
                "user_identity_inference": False,
                "unknown_is_unauthorized": False,
                "network_verification": verification,
                "anomaly_evidence": anomaly_evidence[: self.max_devices * 4],
                "anomaly_count": len(anomaly_evidence),
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
                    "flow_rx_5s_avg": float((((flow_telemetry.get("aggregate") or {}).get("window_5s") or {}).get("rx_bytes_per_second_avg", 0.0)) or 0.0),
                    "flow_tx_5s_avg": float((((flow_telemetry.get("aggregate") or {}).get("window_5s") or {}).get("tx_bytes_per_second_avg", 0.0)) or 0.0),
                    "flow_continuity_percent": float(((flow_telemetry.get("continuity") or {}).get("coverage_percent", 0.0)) or 0.0),
                    "flow_gap_events": int(((flow_telemetry.get("continuity") or {}).get("gap_events", 0)) or 0),
                    "flow_sequence": int(flow_telemetry.get("sequence", 0) or 0),
                    "flow_baseline_status": _bounded_text(((flow_telemetry.get("baseline_analysis") or {}).get("status")), 24).upper() or "WARMING",
                    "flow_baseline_confidence_percent": float(((flow_telemetry.get("baseline_analysis") or {}).get("confidence_percent", 0.0)) or 0.0),
                    "flow_anomaly_candidate": bool(((flow_telemetry.get("baseline_analysis") or {}).get("anomaly_candidate", False))),
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

    def fast_flow_snapshot(self) -> dict[str, Any] | None:
        """Return memory-only fresh flow telemetry without a full inventory scan.

        This method performs no PowerShell, DNS, socket enumeration, packet
        capture, or remote I/O. It only snapshots the bounded in-memory 1 Hz
        sampler so the runtime/dashboard can refresh flow telemetry between
        heavier inventory samples.
        """
        sampler = self.flow_continuity_sampler
        if sampler is None:
            return None
        return sampler.snapshot(set(self._last_active_interface_names))

    @staticmethod
    def merge_fast_flow(snapshot: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
        """Merge non-authoritative fast-path flow evidence into a copied snapshot."""
        if not isinstance(snapshot, dict) or not isinstance(flow, dict):
            return snapshot
        snapshot["flow_telemetry"] = flow
        summary = snapshot.get("summary")
        if not isinstance(summary, dict):
            summary = {}
            snapshot["summary"] = summary
        aggregate = flow.get("aggregate") if isinstance(flow.get("aggregate"), dict) else {}
        continuity = flow.get("continuity") if isinstance(flow.get("continuity"), dict) else {}
        window_5 = aggregate.get("window_5s") if isinstance(aggregate.get("window_5s"), dict) else {}
        summary["flow_active_interfaces"] = int(aggregate.get("active_interfaces", 0) or 0)
        summary["flow_baseline_ready"] = bool(aggregate.get("baseline_ready", False))
        summary["flow_rx_bytes_per_second"] = float(aggregate.get("rx_bytes_per_second", 0.0) or 0.0)
        summary["flow_tx_bytes_per_second"] = float(aggregate.get("tx_bytes_per_second", 0.0) or 0.0)
        summary["flow_rx_5s_avg"] = float(window_5.get("rx_bytes_per_second_avg", 0.0) or 0.0)
        summary["flow_tx_5s_avg"] = float(window_5.get("tx_bytes_per_second_avg", 0.0) or 0.0)
        summary["flow_continuity_percent"] = float(continuity.get("coverage_percent", 0.0) or 0.0)
        summary["flow_gap_events"] = int(continuity.get("gap_events", 0) or 0)
        summary["flow_sequence"] = int(flow.get("sequence", 0) or 0)
        baseline = flow.get("baseline_analysis") if isinstance(flow.get("baseline_analysis"), dict) else {}
        summary["flow_baseline_status"] = _bounded_text(baseline.get("status"), 24).upper() or "WARMING"
        summary["flow_baseline_confidence_percent"] = float(baseline.get("confidence_percent", 0.0) or 0.0)
        summary["flow_anomaly_candidate"] = bool(baseline.get("anomaly_candidate", False))
        return snapshot

    def close(self) -> None:
        sampler = self.flow_continuity_sampler
        if sampler is not None:
            try:
                sampler.close()
            except Exception:
                pass
        method = getattr(self.provider, "close", None)
        if callable(method):
            try:
                method()
            except Exception:
                pass

    def health_check(self) -> dict[str, Any]:
        try:
            health_now = float(self.clock())
        except Exception:
            # Health inspection must remain read-only even when a deterministic
            # fixture clock is exhausted; preserve the last known sample time.
            health_now = float(self.last_sample_at or 0.0)
        sample_age = (
            max(0.0, health_now - self.last_sample_at)
            if self.last_sample_at is not None
            else None
        )
        process_health: dict[str, Any] = {}
        provider_health: dict[str, Any] = {}
        provider_method = getattr(self.provider, "health_check", None)
        if callable(provider_method):
            try:
                candidate = provider_method()
                if isinstance(candidate, dict):
                    provider_health = candidate
            except Exception as exc:
                provider_health = {"status": "DEGRADED", "error": type(exc).__name__, "authority": "NONE"}
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
            "status": (
                "DEGRADED"
                if self.last_error is not None
                or (sample_age is not None and sample_age > 120.0)
                else "HEALTHY"
            ),
            "mode": (
                "PASSIVE_PLUS_BOUNDED_VERIFICATION"
                if self.verifier is not None and getattr(self.verifier.policy, "enabled", False)
                else self.MODE
            ),
            "authority": self.AUTHORITY,
            "authoritative": False,
            "active_scan_enabled": bool(
                self.verifier is not None
                and getattr(self.verifier.policy, "enabled", False)
                and getattr(self.verifier.policy, "active_probe", False)
            ),
            "dns_cache_observation": True,
            "flow_telemetry_observation": True,
            "flow_continuity_observation": self.flow_continuity_sampler is not None,
            "flow_fastpath_memory_only": self.flow_continuity_sampler is not None,
            "flow_baseline_analysis": self.flow_continuity_sampler is not None,
            "packet_capture": False,
            "per_connection_byte_attribution": False,
            "external_dns_queries": False,
            "reverse_dns_lookup": bool(
                self.verifier is not None
                and getattr(self.verifier.policy, "enabled", False)
                and getattr(self.verifier.policy, "dns_resolution", False)
            ),
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
            "last_sample_age_seconds": sample_age,
            "stale_after_seconds": 120.0,
            "fresh": bool(sample_age is not None and sample_age <= 120.0),
            "process_attribution": process_health,
            "provider": provider_health,
            "trust_registry": {
                "authority": "NONE",
                "rules_loaded": len(self._trust),
                "reloads": self.trust_registry_reloads,
                "failures": self.trust_registry_failures,
                "last_error": self.trust_registry_last_error,
                "auto_whitelist": False,
            },
            "network_verification": (
                self.verifier.health_check()
                if self.verifier is not None
                else {
                    "status": "DISABLED",
                    "enabled": False,
                    "active_scan_enabled": False,
                    "dns_resolution": False,
                    "authority": "NONE",
                    "authoritative": False,
                    "authorization": "NOT_GRANTED",
                }
            ),
        }
