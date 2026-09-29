from __future__ import annotations

"""Policy-gated network identity verification.

This module is deliberately separate from the passive inventory provider.  It
can enrich an already observed peer with bounded reverse-DNS and ICMP evidence
when an explicitly approved, private-network policy is supplied.  It never
changes trust, authorization, firewall state, or response decisions.
"""

import ipaddress
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
_ALLOWED_METHODS = frozenset({"ICMP"})


def _bounded_text(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def _normalize_ip(value: Any) -> str | None:
    text = _bounded_text(value, 96).split("%", 1)[0]
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_reserved
        or address.is_link_local
    ):
        return None
    return str(address)


def _normalize_hostname(value: Any) -> str | None:
    text = _bounded_text(value, 253).rstrip(".").lower()
    if not text or not _DOMAIN_RE.fullmatch(text):
        return None
    return text


class NetworkVerificationPolicyError(ValueError):
    """Raised when an active verification policy is unsafe or incomplete."""


@dataclass(frozen=True)
class NetworkVerificationPolicy:
    """Explicit admission policy for optional network verification.

    A disabled policy is the default.  Enabling it requires an operator
    approval reference, private allowlisted networks, and bounded limits.
    """

    SCHEMA = "cyberdefender.network-verification-policy.v0.1"
    enabled: bool = False
    role: str = "CENTRAL_ONLY"
    operator_approved: bool = False
    approval_ref: str | None = None
    allowed_cidrs: tuple[str, ...] = ()
    dns_resolution: bool = False
    active_probe: bool = False
    probe_methods: tuple[str, ...] = ("ICMP",)
    resolver_addresses: tuple[str, ...] = ()
    max_targets: int = 32
    max_dns_queries: int = 32
    max_probes: int = 32
    timeout_seconds: float = 1.0
    cooldown_seconds: float = 30.0
    operation_budget_seconds: float = 5.0

    @classmethod
    def disabled(cls) -> "NetworkVerificationPolicy":
        return cls()

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        admission_check: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> "NetworkVerificationPolicy":
        if not isinstance(payload, Mapping):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_NOT_OBJECT")
        if payload.get("schema") != cls.SCHEMA:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_SCHEMA_INVALID")

        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_ENABLED_INVALID")
        role = _bounded_text(payload.get("role", "CENTRAL_ONLY"), 32).upper()
        if role not in {"CENTRAL_ONLY", "DISABLED"}:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_ROLE_INVALID")
        if enabled and role != "CENTRAL_ONLY":
            raise NetworkVerificationPolicyError("NETWORK_POLICY_CENTRAL_ROLE_REQUIRED")

        raw_cidrs = payload.get("allowed_cidrs", [])
        if not isinstance(raw_cidrs, list):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_CIDRS_INVALID")
        if enabled and not raw_cidrs:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_CIDRS_REQUIRED")
        if len(raw_cidrs) > 16:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_CIDRS_TOO_MANY")

        networks: list[ipaddress._BaseNetwork] = []
        for raw in raw_cidrs:
            try:
                network = ipaddress.ip_network(str(raw), strict=False)
            except ValueError as exc:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_CIDR_INVALID") from exc
            if (
                network.is_global
                or network.is_multicast
                or network.is_unspecified
                or network.is_reserved
                or network.is_link_local
            ):
                raise NetworkVerificationPolicyError("NETWORK_POLICY_PUBLIC_NETWORK")
            if network.version == 4 and network.prefixlen < 16:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_NETWORK_TOO_WIDE")
            if network.version == 6 and network.prefixlen < 64:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_NETWORK_TOO_WIDE")
            if network.num_addresses > 4096:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_TARGET_SPACE_TOO_LARGE")
            networks.append(network)

        methods = payload.get("probe_methods", ["ICMP"])
        if not isinstance(methods, list) or not methods:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_METHODS_INVALID")
        methods_tuple = tuple(_bounded_text(item, 16).upper() for item in methods)
        if any(item not in _ALLOWED_METHODS for item in methods_tuple):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_METHOD_NOT_ALLOWED")

        raw_resolvers = payload.get("resolver_addresses", [])
        if not isinstance(raw_resolvers, list):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_RESOLVERS_INVALID")
        resolvers: list[str] = []
        for raw in raw_resolvers[:8]:
            address = _normalize_ip(raw)
            if not address:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_RESOLVER_INVALID")
            parsed = ipaddress.ip_address(address)
            if parsed.is_global or parsed.is_multicast:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_EXTERNAL_RESOLVER")
            resolvers.append(address)

        dns_resolution = payload.get("dns_resolution", False)
        active_probe = payload.get("active_probe", False)
        if not isinstance(dns_resolution, bool) or not isinstance(active_probe, bool):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_FEATURE_FLAG_INVALID")
        if enabled and dns_resolution and not resolvers:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_RESOLVER_REQUIRED")
        if enabled and active_probe and "ICMP" not in methods_tuple:
            raise NetworkVerificationPolicyError("NETWORK_POLICY_ICMP_REQUIRED")

        approved = payload.get("operator_approved", False)
        approval_ref = _bounded_text(payload.get("approval_ref"), 128) or None
        if enabled and (approved is not True or not approval_ref):
            raise NetworkVerificationPolicyError("NETWORK_POLICY_OPERATOR_APPROVAL_REQUIRED")
        if enabled:
            if not callable(admission_check):
                raise NetworkVerificationPolicyError("NETWORK_POLICY_ADMISSION_REQUIRED")
            try:
                admitted = admission_check(payload)
            except Exception as exc:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_ADMISSION_FAILED") from exc
            if admitted is not True:
                raise NetworkVerificationPolicyError("NETWORK_POLICY_ADMISSION_REJECTED")

        if enabled and dns_resolution:
            parsed_networks = tuple(ipaddress.ip_network(item, strict=False) for item in networks)
            if any(
                not any(ipaddress.ip_address(resolver) in network for network in parsed_networks)
                for resolver in resolvers
            ):
                raise NetworkVerificationPolicyError("NETWORK_POLICY_RESOLVER_OUT_OF_SCOPE")

        def bounded_int(name: str, low: int, high: int, default: int) -> int:
            value = payload.get(name, default)
            if isinstance(value, bool):
                raise NetworkVerificationPolicyError(f"NETWORK_POLICY_{name.upper()}_INVALID")
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise NetworkVerificationPolicyError(f"NETWORK_POLICY_{name.upper()}_INVALID") from exc
            if not low <= value <= high:
                raise NetworkVerificationPolicyError(f"NETWORK_POLICY_{name.upper()}_OUT_OF_RANGE")
            return value

        def bounded_float(name: str, low: float, high: float, default: float) -> float:
            value = payload.get(name, default)
            if isinstance(value, bool):
                raise NetworkVerificationPolicyError(f"NETWORK_POLICY_{name.upper()}_INVALID")
            try:
                value = float(value)
            except (TypeError, ValueError) as exc:
                raise NetworkVerificationPolicyError(f"NETWORK_POLICY_{name.upper()}_INVALID") from exc
            if not low <= value <= high:
                raise NetworkVerificationPolicyError(f"NETWORK_POLICY_{name.upper()}_OUT_OF_RANGE")
            return value

        return cls(
            enabled=enabled,
            role=role,
            operator_approved=bool(approved),
            approval_ref=approval_ref,
            allowed_cidrs=tuple(str(item) for item in networks),
            dns_resolution=dns_resolution if enabled else False,
            active_probe=active_probe if enabled else False,
            probe_methods=methods_tuple,
            resolver_addresses=tuple(resolvers),
            max_targets=bounded_int("max_targets", 1, 256, 32),
            max_dns_queries=bounded_int("max_dns_queries", 0, 256, 32),
            max_probes=bounded_int("max_probes", 0, 256, 32),
            timeout_seconds=bounded_float("timeout_seconds", 0.1, 3.0, 1.0),
            cooldown_seconds=bounded_float("cooldown_seconds", 1.0, 3600.0, 30.0),
            operation_budget_seconds=bounded_float("operation_budget_seconds", 0.25, 30.0, 5.0),
        )

    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(item, strict=False) for item in self.allowed_cidrs)

    def allows(self, address: str) -> bool:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            parsed.is_global
            or parsed.is_multicast
            or parsed.is_unspecified
            or parsed.is_loopback
            or parsed.is_reserved
            or parsed.is_link_local
        ):
            return False
        return any(parsed in network for network in self.networks())


Resolver = Callable[[str, float, tuple[str, ...]], Mapping[str, Any]]
Prober = Callable[[str, str, float], Mapping[str, Any]]


def _default_reverse_dns(ip: str, timeout_seconds: float, resolver_addresses: tuple[str, ...]) -> Mapping[str, Any]:
    if os.name != "nt" or not resolver_addresses:
        return {"status": "UNAVAILABLE"}
    # The input was already validated as an IP and private resolver address.
    server = resolver_addresses[0]
    command = (
        "$ErrorActionPreference='Stop';"
        f"$r=Resolve-DnsName -Name '{ip}' -Type PTR -DnsOnly -Server '{server}';"
        "$r | Select-Object -First 1 -ExpandProperty NameHost | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=False,
            timeout=max(0.1, min(float(timeout_seconds), 3.0)),
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "UNAVAILABLE"}
    if completed.returncode != 0:
        return {"status": "NO_MATCH"}
    try:
        text = bytes(completed.stdout or b"").decode("utf-8-sig", errors="strict").strip()
        value = json.loads(text) if text else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "UNAVAILABLE"}
    hostname = _normalize_hostname(value)
    return {"status": "RESOLVED", "hostname": hostname} if hostname else {"status": "NO_MATCH"}


def _default_icmp_probe(ip: str, method: str, timeout_seconds: float) -> Mapping[str, Any]:
    if os.name != "nt" or method != "ICMP":
        return {"status": "UNAVAILABLE"}
    timeout_ms = max(100, min(int(float(timeout_seconds) * 1000.0), 3000))
    try:
        completed = subprocess.run(
            ["ping.exe", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            text=False,
            timeout=max(0.2, float(timeout_seconds) + 0.25),
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "UNAVAILABLE"}
    return {"status": "REACHABLE" if completed.returncode == 0 else "UNREACHABLE"}


class BoundedNetworkVerifier:
    """Enrich already observed peers with bounded active evidence."""

    VERSION = "0.1.0"
    MODE = "BOUNDED_ACTIVE_VERIFICATION"
    AUTHORITY = "NONE"

    def __init__(
        self,
        policy: NetworkVerificationPolicy | None = None,
        *,
        resolver: Resolver | None = None,
        prober: Prober | None = None,
        clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy or NetworkVerificationPolicy.disabled()
        if not isinstance(self.policy, NetworkVerificationPolicy):
            raise TypeError("NETWORK_POLICY_REQUIRED")
        self.resolver = resolver or _default_reverse_dns
        self.prober = prober or _default_icmp_probe
        self.clock = clock
        self.monotonic_clock = monotonic_clock
        self._last_probe_at: dict[str, float] = {}
        self.samples = 0
        self.targets_examined = 0
        self.dns_queries = 0
        self.probes = 0
        self.failures = 0
        self.last_error: str | None = None

    def _classification(self, target: Mapping[str, Any]) -> str:
        trust = _bounded_text(target.get("trust"), 32).upper()
        if trust == "AUTHORIZED":
            return "AUTHORIZED_OBSERVED"
        if trust in {"DENIED", "REVOKED"}:
            return "SUSPICIOUS_UNAUTHORIZED"
        return "OBSERVED_UNVERIFIED"

    @staticmethod
    def _safe_result(mapping: Mapping[str, Any] | Any, *, default: str) -> dict[str, Any]:
        if not isinstance(mapping, Mapping):
            return {"status": default}
        status = _bounded_text(mapping.get("status"), 32).upper() or default
        if status not in {"RESOLVED", "NO_MATCH", "UNAVAILABLE", "REACHABLE", "UNREACHABLE"}:
            status = default
        result: dict[str, Any] = {"status": status}
        hostname = _normalize_hostname(mapping.get("hostname"))
        if hostname:
            result["hostname"] = hostname
        return result

    def verify(self, targets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        now = float(self.clock())
        if not self.policy.enabled:
            return self._report([], status="DISABLED")

        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        raw_count = 0
        operation_started = self.monotonic_clock()
        budget_exceeded = False
        for raw in targets:
            if self.monotonic_clock() - operation_started >= self.policy.operation_budget_seconds:
                budget_exceeded = True
                break
            raw_count += 1
            if raw_count > self.policy.max_targets:
                break
            if not isinstance(raw, Mapping):
                continue
            ip = _normalize_ip(raw.get("ip_address") or raw.get("ip"))
            if not ip or ip in seen:
                continue
            seen.add(ip)
            self.targets_examined += 1
            result: dict[str, Any] = {
                "device_id": _bounded_text(raw.get("device_id"), 160) or f"ip:{ip}",
                "ip_address": ip,
                "mac_address": _bounded_text(raw.get("mac_address"), 32) or None,
                "classification": self._classification(raw),
                "allowed_target": bool(self.policy.allows(ip)),
                "dns": {"status": "NOT_RUN"},
                "probe": {"status": "NOT_RUN"},
                "authority": self.AUTHORITY,
                "authoritative": False,
                "authorization": "NOT_GRANTED",
            }
            observation_source = _bounded_text(raw.get("source"), 48).upper()
            if observation_source not in {"NEIGHBOR_CACHE", "PASSIVE_INVENTORY"} or raw.get("online") is False:
                result["allowed_target"] = False
                result["verification_state"] = "REVIEW_REQUIRED"
                result["admission_reason"] = "OBSERVATION_NOT_ADMITTED"
                results.append(result)
                continue
            if not self.policy.allows(ip):
                result["verification_state"] = "REVIEW_REQUIRED"
                result["admission_reason"] = "TARGET_OUT_OF_SCOPE"
                results.append(result)
                continue

            last_probe = self._last_probe_at.get(ip)
            if last_probe is not None and now - last_probe < self.policy.cooldown_seconds:
                result["verification_state"] = "COOLDOWN"
                results.append(result)
                continue

            if self.policy.dns_resolution and self.dns_queries < self.policy.max_dns_queries:
                try:
                    dns = self._safe_result(
                        self.resolver(ip, self.policy.timeout_seconds, self.policy.resolver_addresses),
                        default="UNAVAILABLE",
                    )
                    self.dns_queries += 1
                except Exception:
                    self.failures += 1
                    dns = {"status": "UNAVAILABLE"}
                dns.update({
                    "source": "CONFIGURED_INTERNAL_RESOLVER",
                    "authoritative": False,
                    "authority": "NONE",
                    "authorization": "NOT_GRANTED",
                })
                result["dns"] = dns

            if self.policy.active_probe and self.probes < self.policy.max_probes:
                try:
                    probe = self._safe_result(
                        self.prober(ip, self.policy.probe_methods[0], self.policy.timeout_seconds),
                        default="UNAVAILABLE",
                    )
                    self.probes += 1
                except Exception:
                    self.failures += 1
                    probe = {"status": "UNAVAILABLE"}
                probe.update({
                    "method": self.policy.probe_methods[0],
                    "authoritative": False,
                    "authority": "NONE",
                    "authorization": "NOT_GRANTED",
                })
                result["probe"] = probe

            observed_name = result.get("dns", {}).get("hostname")
            if observed_name:
                result["observed_name"] = observed_name
            result["verification_state"] = (
                "SUSPICIOUS_UNAUTHORIZED"
                if result["classification"] == "SUSPICIOUS_UNAUTHORIZED"
                else "OBSERVED"
            )
            self._last_probe_at[ip] = now
            results.append(result)

        self.samples += 1
        self.last_error = "OPERATION_BUDGET_EXCEEDED" if budget_exceeded else None
        return self._report(results, status="DEGRADED" if budget_exceeded else "HEALTHY")

    def _report(self, results: list[dict[str, Any]], *, status: str) -> dict[str, Any]:
        return {
            "schema": "cyberdefender.network-verification.v0.1.0",
            "version": self.VERSION,
            "mode": self.MODE,
            "status": status,
            "enabled": bool(self.policy.enabled),
            "role": self.policy.role,
            "dns_resolution": bool(self.policy.enabled and self.policy.dns_resolution),
            "active_scan_enabled": bool(self.policy.enabled and self.policy.active_probe),
            "authority": self.AUTHORITY,
            "authoritative": False,
            "authorization": "NOT_GRANTED",
            "results": results[: self.policy.max_targets],
            "bounds": {
                "max_targets": self.policy.max_targets,
                "max_dns_queries": self.policy.max_dns_queries,
                "max_probes": self.policy.max_probes,
                "timeout_seconds": self.policy.timeout_seconds,
                "cooldown_seconds": self.policy.cooldown_seconds,
                "max_concurrency": 1,
                "operation_budget_seconds": self.policy.operation_budget_seconds,
            },
            "samples": self.samples,
            "targets_examined": self.targets_examined,
            "dns_queries": self.dns_queries,
            "probes": self.probes,
            "failures": self.failures,
            "last_error": self.last_error,
            "max_concurrency": 1,
            "operation_budget_seconds": self.policy.operation_budget_seconds,
        }

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "BoundedNetworkVerifier",
            "version": self.VERSION,
            "status": "HEALTHY" if self.last_error is None else "DEGRADED",
            "mode": self.MODE,
            "enabled": bool(self.policy.enabled),
            "role": self.policy.role,
            "active_scan_enabled": bool(self.policy.enabled and self.policy.active_probe),
            "dns_resolution": bool(self.policy.enabled and self.policy.dns_resolution),
            "authority": self.AUTHORITY,
            "authoritative": False,
            "authorization": "NOT_GRANTED",
            "samples": self.samples,
            "targets_examined": self.targets_examined,
            "dns_queries": self.dns_queries,
            "probes": self.probes,
            "failures": self.failures,
            "last_error": self.last_error,
        }


__all__ = [
    "BoundedNetworkVerifier",
    "NetworkVerificationPolicy",
    "NetworkVerificationPolicyError",
]
