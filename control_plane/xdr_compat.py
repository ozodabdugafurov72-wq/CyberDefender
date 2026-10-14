from __future__ import annotations

import json
import hashlib
import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from control_plane.fleet_protocol import PROTOCOL_VERSION


OCSF_SCHEMA_NAME = "ocsf"
OCSF_SCHEMA_VERSION = "1.9.0"
OCSF_DEVICE_INVENTORY_CLASS_UID = 5001
OCSF_DEVICE_INVENTORY_ACTIVITY_ID = 2
OCSF_DEVICE_INVENTORY_TYPE_UID = 500102
OCSF_INCIDENT_FINDING_CLASS_UID = 2005

_OCSF_SEVERITY_IDS = {
    "UNKNOWN": 0,
    "INFO": 1,
    "INFORMATIONAL": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
    "FATAL": 6,
}

CAPABILITY_ENDPOINT_HEALTH = "endpoint-health"
CAPABILITY_DEVICE_INVENTORY = "ocsf-device-inventory"
CAPABILITY_RESPONSE_EVIDENCE = "verified-response-evidence"
RESPONSE_EVIDENCE_SCHEMA = "cyberdefender.response-evidence.v1"
SUPPORTED_CAPABILITIES = frozenset(
    {CAPABILITY_ENDPOINT_HEALTH, CAPABILITY_DEVICE_INVENTORY, CAPABILITY_RESPONSE_EVIDENCE}
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$")


def _required_text(value: Any, field: str, limit: int, *, pattern: re.Pattern[str] | None = None) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError(f"invalid {field}")
    if pattern is not None and not pattern.fullmatch(text):
        raise ValueError(f"invalid {field}")
    return text


def validate_endpoint_id(value: Any) -> str:
    return _required_text(value, "endpoint_id", 128, pattern=_IDENTIFIER_RE)


def validate_hostname(value: Any) -> str:
    return _required_text(value, "hostname", 255)


def validate_runtime_version(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "unversioned"
    return _required_text(text, "runtime_version", 64, pattern=_VERSION_RE)


def normalize_capabilities(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ValueError("invalid capabilities")
    capabilities = tuple(sorted({_required_text(item, "capability", 64) for item in value}))
    if not set(capabilities).issubset(SUPPORTED_CAPABILITIES):
        raise ValueError("unsupported capability")
    if CAPABILITY_ENDPOINT_HEALTH not in capabilities:
        raise ValueError("endpoint health capability required")
    return capabilities


def validate_ingest_contract(payload: Mapping[str, Any], *, signed_timestamp: int) -> dict[str, Any]:
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol_version")
    if str(payload.get("telemetry_schema") or "").lower() != OCSF_SCHEMA_NAME:
        raise ValueError("unsupported telemetry_schema")
    if payload.get("telemetry_schema_version") != OCSF_SCHEMA_VERSION:
        raise ValueError("unsupported telemetry_schema_version")
    class_uids = payload.get("xdr_event_class_uids")
    if not isinstance(class_uids, list) or class_uids != [OCSF_DEVICE_INVENTORY_CLASS_UID]:
        raise ValueError("unsupported xdr_event_class_uids")
    capabilities = normalize_capabilities(payload.get("capabilities"))
    observed_at = payload.get("observed_at")
    if isinstance(observed_at, bool) or not isinstance(observed_at, (int, float)):
        raise ValueError("invalid observed_at")
    observed_at = float(observed_at)
    if not math.isfinite(observed_at):
        raise ValueError("invalid observed_at")
    observed_seconds = observed_at / 1000.0
    if abs(observed_seconds - float(signed_timestamp)) > 30.0:
        raise ValueError("observed_at does not match signed timestamp")
    return {
        "endpoint_id": validate_endpoint_id(payload.get("endpoint_id")),
        "hostname": validate_hostname(payload.get("hostname")),
        "runtime_version": validate_runtime_version(payload.get("runtime_version")),
        "telemetry_schema": OCSF_SCHEMA_NAME,
        "telemetry_schema_version": OCSF_SCHEMA_VERSION,
        "capabilities": capabilities,
        "observed_at": observed_seconds,
    }


def validate_response_evidence(value: Any, *, endpoint_id: Any) -> dict[str, Any]:
    """Validate the bounded, non-secret response proof carried by signed fleet ingest."""
    evidence = _required_mapping(value, "response_evidence")
    allowed = {
        "schema", "evidence_id", "incident_id", "event_id", "target_name", "target_sha256",
        "detection_types", "risk_score", "risk_level", "policy_outcome", "policy_reason",
        "verifier_outcome", "action_state", "verification_outcome", "response_latency_ms",
        "execution_latency_ms", "detection_to_response_ms", "restore_latency_ms", "evidence_ref",
        "production_authorization", "lab_authorization", "receipt_integrity",
        "post_action_verification", "authorization_policy_id",
    }
    if set(evidence) - allowed:
        raise ValueError("unsupported response evidence field")
    if evidence.get("schema") != RESPONSE_EVIDENCE_SCHEMA:
        raise ValueError("unsupported response evidence schema")
    endpoint = validate_endpoint_id(endpoint_id)
    evidence_id = _required_text(evidence.get("evidence_id"), "evidence_id", 128, pattern=_IDENTIFIER_RE)
    incident_id = _required_text(evidence.get("incident_id"), "incident_id", 160)
    event_id = _required_text(evidence.get("event_id"), "event_id", 256)
    target_name = _required_text(evidence.get("target_name"), "target_name", 255)
    if target_name in {".", ".."} or "/" in target_name or "\\" in target_name:
        raise ValueError("target_name must be a basename")
    target_sha256 = str(evidence.get("target_sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", target_sha256):
        raise ValueError("invalid target_sha256")
    detection_types = evidence.get("detection_types")
    if not isinstance(detection_types, list) or not detection_types or len(detection_types) > 16:
        raise ValueError("invalid detection_types")
    normalized_detections = []
    for item in detection_types:
        detection = _required_text(item, "detection_type", 128)
        if detection not in normalized_detections:
            normalized_detections.append(detection)
    risk_score = evidence.get("risk_score")
    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise ValueError("invalid risk_score")
    risk_score = float(risk_score)
    if not math.isfinite(risk_score) or not 0 <= risk_score <= 100:
        raise ValueError("invalid risk_score")
    risk_level = _required_text(evidence.get("risk_level"), "risk_level", 24).upper()
    if risk_level not in _OCSF_SEVERITY_IDS:
        raise ValueError("invalid risk_level")
    policy_outcome = _required_text(evidence.get("policy_outcome"), "policy_outcome", 64)
    if policy_outcome not in {"REQUIRE_VERIFICATION", "AUTHORIZED_AUTONOMOUS_QUARANTINE"}:
        raise ValueError("invalid policy_outcome")
    policy_reason = _required_text(evidence.get("policy_reason"), "policy_reason", 256)
    verifier_outcome = _required_text(evidence.get("verifier_outcome"), "verifier_outcome", 64)
    if verifier_outcome != "VERIFIED":
        raise ValueError("invalid verifier_outcome")
    action_state = _required_text(evidence.get("action_state"), "action_state", 32)
    if action_state not in {"QUARANTINED", "RESTORED"}:
        raise ValueError("invalid action_state")
    verification_outcome = _required_text(
        evidence.get("verification_outcome"), "verification_outcome", 64
    )
    expected_outcome = "RESTORED_VERIFIED" if action_state == "RESTORED" else "QUARANTINED_VERIFIED"
    if verification_outcome != expected_outcome:
        raise ValueError("invalid verification_outcome")

    def latency(field: str, *, optional: bool = False) -> float | None:
        raw = evidence.get(field)
        if raw is None and optional:
            return None
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"invalid {field}")
        measured = float(raw)
        if not math.isfinite(measured) or not 0 <= measured <= 86_400_000:
            raise ValueError(f"invalid {field}")
        return round(measured, 3)

    response_latency_ms = latency("response_latency_ms")
    execution_latency_ms = latency("execution_latency_ms")
    detection_to_response_ms = latency("detection_to_response_ms")
    restore_latency_ms = latency("restore_latency_ms", optional=True)
    if action_state == "RESTORED" and restore_latency_ms is None:
        raise ValueError("restore latency required")
    evidence_ref = _required_text(evidence.get("evidence_ref"), "evidence_ref", 256)
    production_authorization = _required_text(
        evidence.get("production_authorization"), "production_authorization", 64
    )
    lab_authorization = _required_text(evidence.get("lab_authorization"), "lab_authorization", 96)
    expected_lab = "RESTORE_CAPABILITY_CONSUMED" if action_state == "RESTORED" else "QUARANTINE_CAPABILITY_CONSUMED"
    authorization_policy_id = None
    if production_authorization == "NOT_GRANTED":
        if lab_authorization != expected_lab or policy_outcome != "REQUIRE_VERIFICATION":
            raise ValueError("invalid lab authorization")
    elif production_authorization == "SIGNED_POLICY_CAPABILITY_CONSUMED":
        if action_state != "QUARANTINED" or lab_authorization != "NOT_APPLICABLE":
            raise ValueError("invalid production authorization")
        if policy_outcome != "AUTHORIZED_AUTONOMOUS_QUARANTINE":
            raise ValueError("production policy outcome mismatch")
        authorization_policy_id = _required_text(
            evidence.get("authorization_policy_id"), "authorization_policy_id", 128
        )
    else:
        raise ValueError("production authorization claim rejected")
    if evidence.get("receipt_integrity") is not True or evidence.get("post_action_verification") is not True:
        raise ValueError("unverified response evidence")
    return {
        "schema": RESPONSE_EVIDENCE_SCHEMA,
        "evidence_id": evidence_id,
        "endpoint_id": endpoint,
        "incident_id": incident_id,
        "event_id": event_id,
        "target_name": target_name,
        "target_sha256": target_sha256,
        "detection_types": normalized_detections,
        "risk_score": round(risk_score, 3),
        "risk_level": risk_level,
        "policy_outcome": policy_outcome,
        "policy_reason": policy_reason,
        "verifier_outcome": verifier_outcome,
        "action_state": action_state,
        "verification_outcome": verification_outcome,
        "response_latency_ms": response_latency_ms,
        "execution_latency_ms": execution_latency_ms,
        "detection_to_response_ms": detection_to_response_ms,
        "restore_latency_ms": restore_latency_ms,
        "evidence_ref": evidence_ref,
        "production_authorization": production_authorization,
        "lab_authorization": lab_authorization,
        "authorization_policy_id": authorization_policy_id,
        "receipt_integrity": True,
        "post_action_verification": True,
    }


def capabilities_json(capabilities: Iterable[str]) -> str:
    return json.dumps(sorted(set(capabilities)), separators=(",", ":"), ensure_ascii=True)


def device_inventory_event(row: Mapping[str, Any]) -> dict[str, Any]:
    endpoint_id = validate_endpoint_id(row.get("endpoint_id"))
    hostname = validate_hostname(row.get("hostname"))
    runtime_version = validate_runtime_version(row.get("runtime_version"))
    first_seen_ms = int(float(row.get("first_seen") or 0) * 1000)
    last_seen_ms = int(float(row.get("last_seen") or 0) * 1000)
    health_state = str(row.get("health_state") or "UNKNOWN").upper()
    severity_id = 4 if health_state == "CRITICAL" else (3 if health_state == "DEGRADED" else 1)
    event = {
        "activity_id": OCSF_DEVICE_INVENTORY_ACTIVITY_ID,
        "activity_name": "Collect",
        "category_name": "Discovery",
        "category_uid": 5,
        "class_name": "Device Inventory Info",
        "class_uid": OCSF_DEVICE_INVENTORY_CLASS_UID,
        "type_name": "Device Inventory Info: Collect",
        "type_uid": OCSF_DEVICE_INVENTORY_TYPE_UID,
        "severity_id": severity_id,
        "time": last_seen_ms,
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "uid": "cyberdefender",
                "name": "CyberDefender",
                "vendor_name": "CyberDefender",
                "version": runtime_version,
            },
            "original_event_uid": f"fleet:{endpoint_id}:{last_seen_ms}",
        },
        "device": {
            "uid": endpoint_id,
            "hostname": hostname,
            "name": hostname,
            "type_id": 0,
            "is_managed": True,
            "first_seen_time": first_seen_ms,
            "last_seen_time": last_seen_ms,
        },
        "unmapped": {
            "cyberdefender_health_state": health_state,
            "cyberdefender_install_state": str(row.get("install_state") or "UNKNOWN"),
            "cyberdefender_service_state": str(row.get("service_state") or "UNKNOWN"),
            "cyberdefender_resource_state": str(row.get("resource_state") or "UNKNOWN"),
        },
    }
    validate_device_inventory_event(event)
    return event


def _required_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"invalid {field}")
    return value


def _timestamp_ms(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"invalid {field}")
    return value


def validate_device_inventory_event(event: Mapping[str, Any]) -> None:
    """Enforce the required OCSF 1.9 Device Inventory contract at export time."""
    value = _required_mapping(event, "event")
    expected = {
        "activity_id": OCSF_DEVICE_INVENTORY_ACTIVITY_ID,
        "category_uid": 5,
        "class_uid": OCSF_DEVICE_INVENTORY_CLASS_UID,
        "type_uid": OCSF_DEVICE_INVENTORY_TYPE_UID,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise ValueError("invalid OCSF Device Inventory classification")
    _timestamp_ms(value.get("time"), "time")
    severity_id = value.get("severity_id")
    if isinstance(severity_id, bool) or severity_id not in set(_OCSF_SEVERITY_IDS.values()):
        raise ValueError("invalid severity_id")
    metadata = _required_mapping(value.get("metadata"), "metadata")
    if metadata.get("version") != OCSF_SCHEMA_VERSION:
        raise ValueError("invalid metadata.version")
    product = _required_mapping(metadata.get("product"), "metadata.product")
    if product.get("uid") != "cyberdefender" or product.get("name") != "CyberDefender":
        raise ValueError("invalid metadata.product")
    device = _required_mapping(value.get("device"), "device")
    validate_endpoint_id(device.get("uid"))
    validate_hostname(device.get("hostname"))
    type_id = device.get("type_id")
    if isinstance(type_id, bool) or not isinstance(type_id, int):
        raise ValueError("invalid device.type_id")
    first_seen = _timestamp_ms(device.get("first_seen_time"), "device.first_seen_time")
    last_seen = _timestamp_ms(device.get("last_seen_time"), "device.last_seen_time")
    if first_seen > last_seen:
        raise ValueError("invalid device observation order")


def device_inventory_events(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [device_inventory_event(row) for row in rows]


def _bounded_incident_text(value: Any, field: str, limit: int = 256) -> str:
    return _required_text(value, field, limit)


def _incident_timestamp(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid {field}")
    observed = float(value)
    if not math.isfinite(observed) or observed < 0:
        raise ValueError(f"invalid {field}")
    return int(observed * 1000)


def incident_finding_event(incident: Mapping[str, Any], *, product_version: str = "unversioned") -> dict[str, Any]:
    """Map a bounded correlation incident to an OCSF 1.9 Incident Finding.

    This mapper is intentionally transport-independent. Connecting the local
    incident outbox to cloud ingest remains a separately gated integration.
    """
    value = _required_mapping(incident, "incident")
    if value.get("event_type") != "INCIDENT":
        raise ValueError("invalid incident event_type")
    incident_id = _bounded_incident_text(value.get("incident_id"), "incident_id", 160)
    created_time = _incident_timestamp(value.get("created_at"), "created_at")
    updated_time = _incident_timestamp(value.get("updated_at"), "updated_at")
    if created_time > updated_time:
        raise ValueError("invalid incident timestamp order")
    active = value.get("active_now")
    if not isinstance(active, bool):
        raise ValueError("invalid active_now")
    event_count = value.get("event_count")
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 1:
        raise ValueError("invalid event_count")
    risk_score = value.get("risk_score")
    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise ValueError("invalid risk_score")
    risk_score = float(risk_score)
    if not math.isfinite(risk_score) or not 0 <= risk_score <= 100:
        raise ValueError("invalid risk_score")
    severity = _bounded_incident_text(value.get("severity"), "severity", 24).upper()
    if severity not in _OCSF_SEVERITY_IDS:
        raise ValueError("invalid severity")
    detections = value.get("detections")
    if not isinstance(detections, list) or not detections or len(detections) > 128:
        raise ValueError("invalid detections")

    finding_info_list: list[dict[str, Any]] = []
    for index, detection in enumerate(detections):
        item = _required_mapping(detection, f"detections[{index}]")
        source_uid = str(item.get("source_event_id") or "").strip()
        if source_uid:
            finding_uid = _bounded_incident_text(source_uid, "source_event_id", 256)
        else:
            canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
            finding_uid = f"{incident_id}:sha256:{hashlib.sha256(canonical).hexdigest()}"
        finding_type = _bounded_incident_text(item.get("type") or "Unknown detection", "detection.type", 128)
        observed = item.get("timestamp", value.get("updated_at"))
        observed_ms = _incident_timestamp(observed, "detection.timestamp")
        finding_info_list.append(
            {
                "uid": finding_uid,
                "title": finding_type,
                "types": [finding_type],
                "first_seen_time": observed_ms,
                "last_seen_time": observed_ms,
                "product": {
                    "uid": "cyberdefender",
                    "name": "CyberDefender",
                    "vendor_name": "CyberDefender",
                    "version": validate_runtime_version(product_version),
                },
            }
        )

    if not active:
        activity_id, activity_name, status_id, status = 3, "Close", 4, "Resolved"
    elif event_count == 1:
        activity_id, activity_name, status_id, status = 1, "Create", 1, "New"
    else:
        activity_id, activity_name, status_id, status = 2, "Update", 2, "In Progress"
    type_uid = OCSF_INCIDENT_FINDING_CLASS_UID * 100 + activity_id
    incident_family = str(value.get("incident_family") or "security incident").strip()[:128]
    event = {
        "activity_id": activity_id,
        "activity_name": activity_name,
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Incident Finding",
        "class_uid": OCSF_INCIDENT_FINDING_CLASS_UID,
        "type_name": f"Incident Finding: {activity_name}",
        "type_uid": type_uid,
        "severity_id": _OCSF_SEVERITY_IDS[severity],
        "time": created_time,
        "start_time": created_time,
        "end_time": updated_time,
        "status_id": status_id,
        "status": status,
        "message": f"CyberDefender incident {incident_id}: {incident_family}",
        "desc": incident_family,
        "impact_score": int(round(risk_score)),
        "finding_info_list": finding_info_list,
        "assignee_group": {"name": "CyberDefender automated triage"},
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "profiles": ["incident"],
            "product": {
                "uid": "cyberdefender",
                "name": "CyberDefender",
                "vendor_name": "CyberDefender",
                "version": validate_runtime_version(product_version),
            },
            "original_event_uid": incident_id,
        },
        "unmapped": {
            "cyberdefender_correlation_key": str(value.get("correlation_key") or "")[:256],
            "cyberdefender_event_count": event_count,
            "cyberdefender_evidence_count": len(finding_info_list),
            "cyberdefender_risk_score": risk_score,
        },
    }
    tenant_id = str(value.get("tenant_id") or "").strip()
    if tenant_id:
        event["metadata"]["tenant_uid"] = _bounded_incident_text(tenant_id, "tenant_id", 128)
    validate_incident_finding_event(event)
    return event


def validate_incident_finding_event(event: Mapping[str, Any]) -> None:
    value = _required_mapping(event, "event")
    activity_id = value.get("activity_id")
    if activity_id not in {1, 2, 3}:
        raise ValueError("invalid incident activity_id")
    expected = {
        "category_uid": 2,
        "class_uid": OCSF_INCIDENT_FINDING_CLASS_UID,
        "type_uid": OCSF_INCIDENT_FINDING_CLASS_UID * 100 + int(activity_id),
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise ValueError("invalid OCSF Incident Finding classification")
    created = _timestamp_ms(value.get("time"), "time")
    start = _timestamp_ms(value.get("start_time"), "start_time")
    end = _timestamp_ms(value.get("end_time"), "end_time")
    if created != start or start > end:
        raise ValueError("invalid incident time range")
    status_id = value.get("status_id")
    if status_id not in {1, 2, 4}:
        raise ValueError("invalid incident status_id")
    metadata = _required_mapping(value.get("metadata"), "metadata")
    if metadata.get("version") != OCSF_SCHEMA_VERSION or "incident" not in metadata.get("profiles", []):
        raise ValueError("invalid incident metadata")
    _required_mapping(metadata.get("product"), "metadata.product")
    findings = value.get("finding_info_list")
    if not isinstance(findings, list) or not findings or len(findings) > 128:
        raise ValueError("invalid finding_info_list")
    for index, finding in enumerate(findings):
        finding_value = _required_mapping(finding, f"finding_info_list[{index}]")
        _bounded_incident_text(finding_value.get("uid"), "finding_info.uid", 512)
    assignee_group = _required_mapping(value.get("assignee_group"), "assignee_group")
    _bounded_incident_text(assignee_group.get("name"), "assignee_group.name", 128)


def compatibility_status() -> dict[str, Any]:
    return {
        "status": "READY",
        "ingest_protocol": PROTOCOL_VERSION,
        "signed_ingest": True,
        "replay_protection": True,
        "schema": "OCSF",
        "schema_version": OCSF_SCHEMA_VERSION,
        "runtime_contract_validation": True,
        "export_path": "/api/v1/owner/xdr/ocsf/device-inventory",
        "event_classes": [
            {
                "class_uid": OCSF_DEVICE_INVENTORY_CLASS_UID,
                "class_name": "Device Inventory Info",
                "activity_id": OCSF_DEVICE_INVENTORY_ACTIVITY_ID,
            }
        ],
        "prepared_mappers": [
            {
                "class_uid": OCSF_INCIDENT_FINDING_CLASS_UID,
                "class_name": "Incident Finding",
                "transport_connected": False,
            }
        ],
    }
