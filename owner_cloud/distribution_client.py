from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

from control_plane.xdr_compat import (
    normalize_capabilities,
    validate_endpoint_id,
    validate_hostname,
    validate_response_evidence,
    validate_runtime_version,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DistributionClient:
    MAX_RESPONSE = 1024 * 1024
    _INSTALL_STATES = frozenset({"PENDING", "INSTALLED", "FAILED", "REVOKED"})
    _HEALTH_STATES = frozenset({"UNKNOWN", "HEALTHY", "DEGRADED", "CRITICAL", "OFFLINE"})
    _SERVICE_STATES = frozenset({
        "UNKNOWN", "REGISTERED", "STARTING", "RUNNING", "DEGRADED",
        "STOPPING", "STOPPED", "FAILED",
    })
    _RESOURCE_STATES = frozenset({"UNKNOWN", "NORMAL", "DEGRADED", "CRITICAL"})

    _TENANT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

    def __init__(self, base_url: str, token: str, *, tenant_id: str = "", timeout: float = 3.0):
        self.base_url = str(base_url).rstrip("/")
        self.token = str(token)
        self.tenant_id = str(tenant_id).strip().lower()
        if self.tenant_id and not self._TENANT_RE.fullmatch(self.tenant_id):
            raise ValueError("invalid tenant")
        self.timeout = max(0.5, min(float(timeout), 10.0))
        self._opener = urllib.request.build_opener(_NoRedirect)

    @classmethod
    def _normalized_endpoint(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("invalid endpoint")
        allowed = {
            "endpoint_id", "hostname", "install_state", "health_state",
            "service_state", "runtime_version", "resource_state", "first_seen",
            "last_seen", "telemetry_schema", "telemetry_schema_version",
            "capabilities", "last_observed_at",
        }
        if set(value) != allowed:
            raise ValueError("invalid endpoint fields")

        def state(name: str, accepted: frozenset[str]) -> str:
            current = value.get(name)
            if not isinstance(current, str) or current not in accepted:
                raise ValueError("invalid endpoint state")
            return current

        def timestamp(name: str, *, optional: bool = False) -> float | None:
            current = value.get(name)
            if optional and current is None:
                return None
            if isinstance(current, bool) or not isinstance(current, (int, float)):
                raise ValueError("invalid endpoint timestamp")
            current = float(current)
            if not math.isfinite(current) or current < 0:
                raise ValueError("invalid endpoint timestamp")
            return current

        schema = value.get("telemetry_schema")
        schema_version = value.get("telemetry_schema_version")
        capabilities = value.get("capabilities")
        if schema == "ocsf" and schema_version == "1.9.0":
            capabilities = list(normalize_capabilities(capabilities))
        elif schema == "legacy" and schema_version == "unversioned" and capabilities == []:
            capabilities = []
        else:
            raise ValueError("unsupported endpoint telemetry contract")
        first_seen = timestamp("first_seen")
        last_seen = timestamp("last_seen")
        observed = timestamp("last_observed_at", optional=True)
        if first_seen > last_seen or (observed is not None and observed > last_seen + 300.0):
            raise ValueError("invalid endpoint time ordering")
        return {
            "endpoint_id": validate_endpoint_id(value.get("endpoint_id")),
            "hostname": validate_hostname(value.get("hostname")),
            "install_state": state("install_state", cls._INSTALL_STATES),
            "health_state": state("health_state", cls._HEALTH_STATES),
            "service_state": state("service_state", cls._SERVICE_STATES),
            "runtime_version": validate_runtime_version(value.get("runtime_version")),
            "resource_state": state("resource_state", cls._RESOURCE_STATES),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "telemetry_schema": schema,
            "telemetry_schema_version": schema_version,
            "capabilities": capabilities,
            "last_observed_at": observed,
        }

    @staticmethod
    def _normalized_state(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("status") != "HEALTHY" or value.get("read_only") is not True:
            raise ValueError("healthy read-only state required")
        raw_summary = value.get("summary")
        if not isinstance(raw_summary, dict):
            raise ValueError("summary object required")
        summary = {}
        for key in (
            "downloads_total", "downloads_completed", "downloads_failed",
            "endpoints_total", "installed", "pending", "install_failed",
            "revoked", "online", "offline", "degraded", "critical",
            "responses_total", "responses_quarantined", "responses_restored",
        ):
            item = raw_summary.get(key, 0)
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise ValueError("invalid summary value")
            summary[key] = item
        latency_max = raw_summary.get("response_latency_ms_max")
        if latency_max is not None:
            if (
                isinstance(latency_max, bool)
                or not isinstance(latency_max, (int, float))
                or not math.isfinite(float(latency_max))
                or latency_max < 0
            ):
                raise ValueError("invalid response latency summary")
            latency_max = round(float(latency_max), 3)
        summary["response_latency_ms_max"] = latency_max
        xdr = value.get("xdr")
        if not isinstance(xdr, dict):
            raise ValueError("XDR status required")
        if (
            xdr.get("status") != "READY"
            or xdr.get("schema") != "OCSF"
            or xdr.get("schema_version") != "1.9.0"
            or xdr.get("ingest_protocol") != "cyberdefender.fleet.v1"
            or xdr.get("signed_ingest") is not True
            or xdr.get("replay_protection") is not True
            or xdr.get("runtime_contract_validation") is not True
        ):
            raise ValueError("unsupported XDR status")
        expected_class = {
            "class_uid": 5001,
            "class_name": "Device Inventory Info",
            "activity_id": 2,
        }
        if xdr.get("event_classes") != [expected_class]:
            raise ValueError("unsupported XDR event class contract")
        endpoints = value.get("endpoints")
        if not isinstance(endpoints, list) or len(endpoints) > 100:
            raise ValueError("invalid endpoint list")
        endpoints = [DistributionClient._normalized_endpoint(item) for item in endpoints]
        raw_responses = value.get("responses")
        if not isinstance(raw_responses, list) or len(raw_responses) > 100:
            raise ValueError("invalid response evidence list")
        responses = []
        for raw in raw_responses:
            if not isinstance(raw, dict):
                raise ValueError("invalid response evidence")
            endpoint_id = raw.get("endpoint_id")
            evidence_fields = {
                key: item
                for key, item in raw.items()
                if key not in {"endpoint_id", "observed_at", "received_at"}
            }
            normalized = validate_response_evidence(evidence_fields, endpoint_id=endpoint_id)
            for timestamp_field in ("observed_at", "received_at"):
                timestamp = raw.get(timestamp_field)
                if (
                    isinstance(timestamp, bool)
                    or not isinstance(timestamp, (int, float))
                    or not math.isfinite(float(timestamp))
                    or timestamp < 0
                ):
                    raise ValueError("invalid response evidence timestamp")
                normalized[timestamp_field] = float(timestamp)
            responses.append(normalized)
        return {
            "status": "HEALTHY",
            "summary": summary,
            "endpoints": endpoints,
            "responses": responses,
            "recent_events": [],
            "event_summary": [],
            "capabilities": {
                "endpoint_diagnostics": False,
                "event_investigation": False,
                "response_evidence": True,
            },
            "read_only": True,
            "xdr": xdr,
        }

    @classmethod
    def _normalized_v2_state(cls, value: Any, *, tenant_id: str) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("schema") != "cyberdefender.fleet-read-model.v2":
            raise ValueError("fleet read model required")
        if value.get("tenant_id") != tenant_id or value.get("read_only") is not True:
            raise ValueError("tenant read boundary mismatch")
        if value.get("privileged_actions") != "DISABLED":
            raise ValueError("privileged actions must remain disabled")
        generated = value.get("generated_at")
        freshness = value.get("online_after_seconds")
        if (isinstance(generated, bool) or not isinstance(generated, (int, float)) or
                not math.isfinite(float(generated)) or float(generated) < 0):
            raise ValueError("invalid read model timestamp")
        if (isinstance(freshness, bool) or not isinstance(freshness, (int, float)) or
                not 30 <= float(freshness) <= 300):
            raise ValueError("invalid freshness window")
        raw_summary = value.get("summary")
        if not isinstance(raw_summary, dict) or set(raw_summary) != {"total", "online", "offline", "degraded", "critical"}:
            raise ValueError("invalid fleet summary")
        counts = {}
        for name, item in raw_summary.items():
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise ValueError("invalid fleet summary")
            counts[name] = item
        if counts["online"] + counts["offline"] != counts["total"]:
            raise ValueError("inconsistent fleet summary")
        raw_endpoints = value.get("endpoints")
        if not isinstance(raw_endpoints, list) or len(raw_endpoints) > 100:
            raise ValueError("invalid endpoint list")
        endpoints = []
        legacy_endpoint_fields = {
            "endpoint_id", "hostname", "status", "health_state", "service_state", "resource_state",
            "runtime_version", "last_verified_heartbeat", "last_observed_at", "component_failures",
            "cycle", "cpu_percent", "memory_percent", "telemetry_status",
        }
        diagnostic_fields = {"spool_pending", "spool_bytes", "spool_status", "accepted_through"}
        endpoint_diagnostics_available = "recent_events" in value
        for item in raw_endpoints:
            if not isinstance(item, dict) or frozenset(item) not in {frozenset(legacy_endpoint_fields), frozenset(legacy_endpoint_fields | diagnostic_fields)}:
                raise ValueError("invalid endpoint fields")
            has_diagnostics = diagnostic_fields.issubset(item)
            endpoint_diagnostics_available = endpoint_diagnostics_available and has_diagnostics
            endpoint_id = validate_endpoint_id(item.get("endpoint_id"))
            hostname = validate_hostname(item.get("hostname"))
            if item.get("status") not in {"ONLINE", "OFFLINE", "REVOKED"}:
                raise ValueError("invalid endpoint status")
            if item.get("health_state") not in {"UNKNOWN", "HEALTHY", "DEGRADED", "CRITICAL", "OFFLINE"}:
                raise ValueError("invalid endpoint health")
            if item.get("service_state") not in cls._SERVICE_STATES or item.get("resource_state") not in cls._RESOURCE_STATES:
                raise ValueError("invalid endpoint runtime state")
            for name in ("component_failures", "cycle"):
                current = item.get(name)
                if isinstance(current, bool) or not isinstance(current, int) or current < 0:
                    raise ValueError("invalid endpoint counter")
            if has_diagnostics:
                for name in ("spool_pending", "spool_bytes", "accepted_through"):
                    current = item.get(name)
                    if isinstance(current, bool) or not isinstance(current, int) or current < 0:
                        raise ValueError("invalid endpoint diagnostic")
            for name in ("last_verified_heartbeat", "last_observed_at", "cpu_percent", "memory_percent"):
                current = item.get(name)
                if current is not None and (isinstance(current, bool) or not isinstance(current, (int, float)) or
                                            not math.isfinite(float(current)) or float(current) < 0):
                    raise ValueError("invalid endpoint measurement")
            if any(item.get(name) is not None and float(item[name]) > 100 for name in ("cpu_percent", "memory_percent")):
                raise ValueError("invalid endpoint resource percentage")
            if item.get("status") != "ONLINE" and (item.get("cpu_percent") is not None or item.get("memory_percent") is not None):
                raise ValueError("stale endpoint exposes live resources")
            heartbeat = item.get("last_verified_heartbeat")
            cutoff = float(generated) - float(freshness)
            if item.get("status") == "ONLINE":
                if (heartbeat is None or float(heartbeat) < cutoff or item.get("cpu_percent") is None or
                        item.get("memory_percent") is None or item.get("health_state") == "OFFLINE"):
                    raise ValueError("unverified online endpoint")
            elif heartbeat is not None and float(heartbeat) >= cutoff:
                raise ValueError("fresh endpoint marked offline")
            observed = item.get("last_observed_at")
            if observed is not None and heartbeat is not None and float(observed) > float(heartbeat) + 300.0:
                raise ValueError("invalid endpoint observation time")
            telemetry = item.get("telemetry_status")
            if telemetry not in {"HEALTHY", "DEGRADED", "BLOCKED", "STALE"}:
                raise ValueError("invalid telemetry status")
            if has_diagnostics and item.get("spool_status") not in {"HEALTHY", "DEGRADED", "BLOCKED", "STALE"}:
                raise ValueError("invalid spool status")
            endpoints.append({**item, **({} if has_diagnostics else {
                                  "spool_pending": None, "spool_bytes": None,
                                  "spool_status": "UNAVAILABLE", "accepted_through": None,
                              }), "endpoint_id": endpoint_id, "hostname": hostname,
                              "runtime_version": validate_runtime_version(item.get("runtime_version"))})
        actual = {
            "total": len(endpoints),
            "online": sum(item["status"] == "ONLINE" for item in endpoints),
            "offline": sum(item["status"] != "ONLINE" for item in endpoints),
            "degraded": sum(item["health_state"] == "DEGRADED" for item in endpoints),
            "critical": sum(item["health_state"] == "CRITICAL" for item in endpoints),
        }
        if counts != actual:
            raise ValueError("fleet summary does not match endpoint evidence")
        event_summary = value.get("event_summary")
        if not isinstance(event_summary, list) or len(event_summary) > 64:
            raise ValueError("invalid event summary")
        normalized_events = []
        for row in event_summary:
            if (not isinstance(row, dict) or set(row) != {"event_type", "priority", "count"} or
                    not isinstance(row["event_type"], str) or len(row["event_type"]) > 64 or
                    row["priority"] not in {"LOW", "NORMAL", "HIGH", "CRITICAL"} or
                    isinstance(row["count"], bool) or not isinstance(row["count"], int) or row["count"] < 0):
                raise ValueError("invalid event summary")
            normalized_events.append(dict(row))
        recent_events_available = "recent_events" in value
        recent_events = value.get("recent_events", [])
        if not isinstance(recent_events, list) or len(recent_events) > 100:
            raise ValueError("invalid recent events")
        normalized_recent = []
        recent_fields = {"event_id", "endpoint_id", "observed_at", "received_at", "event_type", "priority"}
        event_types = {"DETECTION", "INCIDENT", "ATTACK_GRAPH", "RISK", "QUARANTINE", "AUDIT"}
        for row in recent_events:
            if not isinstance(row, dict) or set(row) != recent_fields:
                raise ValueError("invalid recent event fields")
            event_id = str(row.get("event_id", ""))
            if not event_id or len(event_id) > 128:
                raise ValueError("invalid recent event id")
            endpoint_id = validate_endpoint_id(row.get("endpoint_id"))
            if row.get("event_type") not in event_types or row.get("priority") not in {"LOW", "NORMAL", "HIGH", "CRITICAL"}:
                raise ValueError("invalid recent event classification")
            normalized = dict(row)
            normalized["event_id"] = event_id
            normalized["endpoint_id"] = endpoint_id
            for name in ("observed_at", "received_at"):
                current = normalized.get(name)
                if (isinstance(current, bool) or not isinstance(current, (int, float)) or
                        not math.isfinite(float(current)) or float(current) < 0):
                    raise ValueError("invalid recent event timestamp")
                normalized[name] = float(current)
            normalized_recent.append(normalized)
        return {
            "status": "HEALTHY",
            "tenant_id": tenant_id,
            "summary": {
                "downloads_total": 0, "downloads_completed": 0, "downloads_failed": 0,
                "endpoints_total": counts["total"], "installed": counts["total"], "pending": 0,
                "install_failed": 0, "revoked": sum(1 for item in endpoints if item["status"] == "REVOKED"),
                "online": counts["online"], "offline": counts["offline"],
                "degraded": counts["degraded"], "critical": counts["critical"],
                "responses_total": 0, "responses_quarantined": 0, "responses_restored": 0,
                "response_latency_ms_max": None,
            },
            "endpoints": endpoints,
            "responses": [],
            "event_summary": normalized_events,
            "recent_events": normalized_recent,
            "capabilities": {
                "endpoint_diagnostics": endpoint_diagnostics_available,
                "event_investigation": recent_events_available,
                "response_evidence": False,
            },
            "read_only": True,
            "generated_at": float(generated),
            "xdr": {
                "status": "READY", "schema": "OCSF", "schema_version": "1.9.0",
                "ingest_protocol": "cyberdefender.cloud.v2", "signed_ingest": True,
                "replay_protection": True, "runtime_contract_validation": True,
                "event_classes": [{"class_uid": 5001, "class_name": "Device Inventory Info", "activity_id": 2}],
            },
        }

    def state(self) -> dict[str, Any]:
        if not self.base_url or not self.token:
            return {"status": "UNAVAILABLE", "reason": "NOT_CONFIGURED"}
        path = ("/api/v2/owner/tenants/" + quote(self.tenant_id, safe="") + "/fleet") if self.tenant_id else "/api/v1/owner/summary"
        request = urllib.request.Request(
            self.base_url + path,
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + self.token,
                "User-Agent": "CyberDefenderOwnerCloud",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.MAX_RESPONSE + 1)
                content_type = response.headers.get_content_type()
                if response.status != 200 or len(raw) > self.MAX_RESPONSE or content_type != "application/json":
                    return {"status": "UNAVAILABLE", "reason": "UPSTREAM_RESPONSE_REJECTED"}
            value = json.loads(raw.decode("utf-8"))
            value = (self._normalized_v2_state(value, tenant_id=self.tenant_id)
                     if self.tenant_id else self._normalized_state(value))
            value["transport"] = "RAILWAY_PRIVATE_AUTHENTICATED"
            return value
        except urllib.error.HTTPError as exc:
            exc.close()
            return {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"}
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
            return {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"}
