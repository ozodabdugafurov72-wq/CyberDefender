from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
from typing import Any

from control_plane.xdr_compat import validate_response_evidence


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DistributionClient:
    MAX_RESPONSE = 1024 * 1024

    def __init__(self, base_url: str, token: str, *, timeout: float = 3.0):
        self.base_url = str(base_url).rstrip("/")
        self.token = str(token)
        self.timeout = max(0.5, min(float(timeout), 10.0))
        self._opener = urllib.request.build_opener(_NoRedirect)

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
            "read_only": True,
            "xdr": xdr,
        }

    def state(self) -> dict[str, Any]:
        if not self.base_url or not self.token:
            return {"status": "UNAVAILABLE", "reason": "NOT_CONFIGURED"}
        request = urllib.request.Request(
            self.base_url + "/api/v1/owner/summary",
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
            value = self._normalized_state(value)
            value["transport"] = "RAILWAY_PRIVATE_AUTHENTICATED"
            return value
        except urllib.error.HTTPError as exc:
            exc.close()
            return {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"}
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
            return {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"}
