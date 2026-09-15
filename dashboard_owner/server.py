from __future__ import annotations

import json
import mimetypes
import os
import socket
import sqlite3
import time
from datetime import datetime, timezone
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent.demo_scenario import CriticalThreatDemoScenario
from dashboard_owner.read_model import OwnerReadModel
from dashboard_owner.fleet_read_model import FleetReadModel
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(os.environ.get("CYBERDEFENDER_ROOT", Path(__file__).resolve().parent.parent)).resolve()
STATE_ROOT = Path(os.environ.get("CYBERDEFENDER_STATE_DIR", ROOT / "state")).expanduser().resolve()
if os.environ.get("CYBERDEFENDER_LOG_DIR"):
    LOG_ROOT = Path(os.environ["CYBERDEFENDER_LOG_DIR"]).expanduser().resolve()
elif os.environ.get("CYBERDEFENDER_STATE_DIR"):
    LOG_ROOT = STATE_ROOT / "logs"
else:
    LOG_ROOT = ROOT / "logs"
STATE_FILE = STATE_ROOT / "dashboard_runtime.json"
DATA_DB_FILE = STATE_ROOT / "data" / "cyberdefender.db"
DISTRIBUTION_DB_FILE = Path(os.environ.get("CYBERDEFENDER_DISTRIBUTION_DB", STATE_ROOT / "control_plane" / "distribution.db")).expanduser().resolve()
LOG_FILE = LOG_ROOT / "events.jsonl"
STATIC = Path(__file__).resolve().parent / "static"
ADMIN_STATIC = STATIC / "admin"
HOST = "127.0.0.1"
PORT = int(os.environ.get("CYBERDEFENDER_OWNER_PORT", "8775"))
RUNTIME_STALE_AFTER = 15.0
MAX_EVENTS = 160
MAX_EVENT_LOG_TAIL_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_API_QUERY_CHARS = 96

SECURITY_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
}


def safe_json(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): safe_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [safe_json(v) for v in value]
    return str(value)


def read_json(path: Path) -> dict:
    try:
        if not path.exists() or not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _read_jsonl_tail(path: Path, requested: int, byte_budget: int) -> tuple[list[dict], int]:
    """Return newest-first JSON objects from one bounded JSONL file tail."""
    if requested <= 0 or byte_budget <= 0 or not path.is_file():
        return [], 0

    consumed = 0
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            buffer = b""
            chunk_size = 64 * 1024

            while (
                position > 0
                and buffer.count(b"\n") <= requested
                and len(buffer) < byte_budget
            ):
                read_size = min(
                    chunk_size,
                    position,
                    byte_budget - len(buffer),
                )
                if read_size <= 0:
                    break
                position -= read_size
                handle.seek(position)
                chunk = handle.read(read_size)
                consumed += len(chunk)
                buffer = chunk + buffer

        lines = buffer.splitlines()
        if position > 0 and lines:
            lines = lines[1:]
        lines = lines[-requested:]
    except (OSError, ValueError, TypeError):
        return [], consumed

    events: list[dict] = []
    for raw_line in reversed(lines):
        try:
            item = json.loads(raw_line.decode("utf-8"))
            if isinstance(item, dict):
                events.append(item)
        except (UnicodeDecodeError, ValueError, TypeError):
            continue
    return events, consumed


def read_events(limit: int = MAX_EVENTS) -> list[dict]:
    """Read a bounded newest-first view across active and rotated JSONL logs.

    EventLogger keeps events.jsonl plus numbered backups (events.jsonl.1 is the
    newest rotated segment). The dashboard walks only enough segments to fill
    the requested live window and enforces one total byte budget.
    """
    requested = max(1, min(int(limit), MAX_EVENTS))
    try:
        configured_backups = int(os.environ.get("CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT", "6"))
    except (TypeError, ValueError):
        configured_backups = 6
    configured_backups = max(0, min(configured_backups, 64))

    paths = [LOG_FILE] + [
        LOG_FILE.with_name(f"{LOG_FILE.name}.{index}")
        for index in range(1, configured_backups + 1)
    ]

    remaining = requested
    budget = MAX_EVENT_LOG_TAIL_BYTES
    events: list[dict] = []

    for path in paths:
        if remaining <= 0 or budget <= 0:
            break
        chunk, consumed = _read_jsonl_tail(path, remaining, budget)
        events.extend(chunk)
        remaining = requested - len(events)
        budget = max(0, budget - consumed)

    return events[:requested]

def owner_read_model() -> OwnerReadModel:
    return OwnerReadModel(DATA_DB_FILE)

def fleet_read_model() -> FleetReadModel:
    return FleetReadModel(DISTRIBUTION_DB_FILE)

def fleet_snapshot() -> dict:
    try:
        return fleet_read_model().snapshot(limit=100, online_after_seconds=90.0)
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        return {
            "status": "UNAVAILABLE", "version": FleetReadModel.VERSION,
            "read_only": True, "authoritative": False,
            "exact_download_events": True, "people_identity_counted": False,
            "summary": {
                "downloads_total": 0, "downloads_completed": 0, "downloads_failed": 0,
                "endpoints_total": 0, "installed": 0, "pending": 0, "install_failed": 0,
                "revoked": 0, "online": 0, "offline": 0, "degraded": 0, "critical": 0,
            },
            "endpoints": [], "error": type(exc).__name__,
        }


def _query_arg(query: dict[str, list[str]], name: str, default: str = "") -> str:
    values = query.get(name, [])
    if not values:
        return default
    return str(values[0])[:MAX_API_QUERY_CHARS]


def query_incidents(params: dict[str, list[str]]) -> dict:
    reader = owner_read_model()
    try:
        limit = int(_query_arg(params, "limit", "50"))
    except (TypeError, ValueError):
        limit = 50
    try:
        incidents = reader.search_incidents(
            query=_query_arg(params, "q"),
            severity=_query_arg(params, "severity"),
            incident_class=_query_arg(params, "class"),
            limit=limit,
        )
        return {
            "status": "OK",
            "authoritative": False,
            "read_only": True,
            "count": len(incidents),
            "incidents": incidents,
        }
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        return {
            "status": "UNAVAILABLE",
            "authoritative": False,
            "read_only": True,
            "count": 0,
            "incidents": [],
            "error": type(exc).__name__,
        }


def incident_detail(incident_id: str) -> dict | None:
    try:
        return owner_read_model().get_incident(incident_id)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return None


def endpoint_detail() -> dict | None:
    try:
        return owner_read_model().endpoint_details(decision_limit=20)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return None


def freshness(snapshot: dict) -> dict:
    publisher = snapshot.get("publisher", {})
    generated_at = publisher.get("generated_at") if isinstance(publisher, dict) else None
    try:
        age = max(0.0, time.time() - float(generated_at))
        return {
            "available": True,
            "stale": age > RUNTIME_STALE_AFTER,
            "age_seconds": round(age, 2),
            "threshold_seconds": RUNTIME_STALE_AFTER,
        }
    except (TypeError, ValueError):
        return {"available": False, "stale": True, "age_seconds": None, "threshold_seconds": RUNTIME_STALE_AFTER}


def component_rows(health: dict) -> list[dict]:
    preferred = [
        ("Safety Core", "safety_core"), ("Key Manager", "key_manager"),
        ("Resource Guard", "resource_guard"), ("Event Bus", "event_bus"),
        ("Admission Gateway", "admission_gateway"), ("Detection", "detector"),
        ("Correlation", "correlation_engine"), ("Process Graph", "process_graph"),
        ("Process Authority", "process_sensor_authority"), ("Rust Canary", "rust_process_canary"),
        ("Attack Graph", "attack_graph"), ("Risk Engine", "risk_engine"),
        ("Policy Engine", "policy_engine"), ("Independent Verifier", "independent_verifier"),
        ("Authorization Gate", "authorization_gate"), ("Action Gateway", "action_gateway"),
        ("Data Store", "data_repository"), ("Runtime Publisher", "dashboard_publisher"),
    ]
    rows = []
    for label, key in preferred:
        value = health.get(key, {})
        if not isinstance(value, dict):
            value = {}

        operational_status = str(value.get("status", "UNKNOWN")).upper()
        display_status = operational_status

        # ResourceGuard intentionally separates component health from host
        # pressure state: status=HEALTHY can coexist with state=DEGRADED.
        # The dashboard component matrix must surface the pressure state so
        # operators are not told that resource posture is nominal.
        if key == "resource_guard":
            resource_state = str(value.get("state", "")).upper().strip()
            if resource_state == "NORMAL":
                display_status = "HEALTHY"
            elif resource_state in {"DEGRADED", "CRITICAL"}:
                display_status = resource_state

        rows.append({
            "name": label, "key": key,
            "status": display_status,
            "operational_status": operational_status,
            "version": value.get("version"),
            "failures": value.get("failed", value.get("failures", 0)),
            "details": safe_json(value),
        })
    return rows

def classify_incident(incident: dict) -> str:
    """Classify an incident without confusing resource pressure with threat activity.

    Incident payloads can carry the originating detection under nested evidence,
    detection_types, events, or metadata. We inspect a bounded recursive textual
    representation so resource incidents remain RESOURCE even when their top-level
    correlation key is generic. Unknown/mixed incidents remain SECURITY by default
    rather than silently lowering a security signal.
    """
    def _collect(value, depth=0):
        if depth > 4:
            return []
        if isinstance(value, dict):
            out = []
            for key, item in list(value.items())[:64]:
                out.append(str(key))
                out.extend(_collect(item, depth + 1))
            return out
        if isinstance(value, (list, tuple, set)):
            out = []
            for item in list(value)[:64]:
                out.extend(_collect(item, depth + 1))
            return out
        return [str(value)]

    text = " ".join(_collect(incident)).lower().replace("-", "_")
    resource_words = (
        "memory", "high_memory_usage", "low_available_memory",
        "available_memory", "memory_percent", "cpu", "cpu_percent",
        "disk", "disk_percent", "resource", "process count",
        "process_count", "systemobserver", "system_observer",
    )
    return "RESOURCE" if any(word in text for word in resource_words) else "SECURITY"


def incident_summary(incidents: list[dict]) -> dict:
    all_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    security_counts = dict(all_counts)
    resource_counts = dict(all_counts)
    resource = security = 0

    for incident in incidents:
        if not isinstance(incident, dict):
            continue

        level = str(incident.get("severity", incident.get("risk_level", "INFO"))).upper()
        if level not in all_counts:
            level = "INFO"
        all_counts[level] += 1

        incident_class = classify_incident(incident)
        if incident_class == "RESOURCE":
            resource += 1
            resource_counts[level] += 1
        else:
            security += 1
            security_counts[level] += 1

    return {
        "severity_counts": all_counts,
        "security_severity_counts": security_counts,
        "resource_severity_counts": resource_counts,
        "critical_security_incidents": security_counts["CRITICAL"],
        "critical_resource_incidents": resource_counts["CRITICAL"],
        "resource_incidents": resource,
        "security_incidents": security,
    }

def dedupe_events(events: list[dict], limit: int = 18) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for event in events:
        kind = str(event.get("event_type", event.get("type", event.get("name", "EVENT"))))
        level = str(event.get("severity", event.get("level", event.get("risk_level", "INFO")))).upper()
        detail = event.get("message", event.get("details", event.get("description", event.get("reason", event.get("admission_reason", "Runtime evidence")))))
        detail_text = detail if isinstance(detail, str) else json.dumps(safe_json(detail), ensure_ascii=False, sort_keys=True)
        key = (kind, level, detail_text)
        row = grouped.get(key)
        ts = event.get("timestamp", event.get("generated_at", event.get("created_at")))
        if row is None:
            grouped[key] = {"kind": kind, "level": level, "detail": detail_text, "count": 1, "first": ts, "last": ts}
        else:
            row["count"] += 1
            row["last"] = ts
            if row.get("first") is None:
                row["first"] = ts
    def _timestamp_sort_key(value) -> float:
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return 0.0
        try:
            return float(text)
        except (TypeError, ValueError):
            pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            return 0.0

    rows = list(grouped.values())
    rows.sort(key=lambda x: _timestamp_sort_key(x.get("last")), reverse=True)
    return rows[:limit]


def derive_control_state(health: dict, runtime: dict, fresh: dict) -> dict:
    safety = health.get("safety_core", {}) if isinstance(health.get("safety_core"), dict) else {}
    auth = health.get("authorization_gate", {}) if isinstance(health.get("authorization_gate"), dict) else {}
    gateway = health.get("action_gateway", {}) if isinstance(health.get("action_gateway"), dict) else {}
    policy = health.get("policy_engine", {}) if isinstance(health.get("policy_engine"), dict) else {}
    verifier = health.get("independent_verifier", {}) if isinstance(health.get("independent_verifier"), dict) else {}
    safe_mode = bool(safety.get("safe_mode", False))
    shutdown = bool(safety.get("shutdown_requested", False))
    running = bool(runtime.get("running", False))
    live = bool(fresh.get("available")) and not fresh.get("stale") and running
    return {
        "status": "ACTIVE" if live else "STANDBY",
        # Backward-compatible field: `unlocked` means only that the local
        # operator control surface is available.  It MUST NOT be interpreted
        # as privileged execution authority.
        "unlocked": True,
        "unlocked_semantics": "CONTROL_SURFACE_ONLY",
        "operator_session": "ACTIVE" if live else "STANDBY",
        "control_surface": "AVAILABLE" if live else "STANDBY",
        "mode": "DRY_RUN_CONTROL",
        "execution_mode": "DRY_RUN_ONLY",
        "safety_enforced": True,
        "privileged_execution": "PROTECTED",
        "real_world_effect": False,
        "safe_mode": safe_mode,
        "shutdown_requested": shutdown,
        "authorization_ready": auth.get("status") == "HEALTHY" and bool(auth.get("dry_run_only", True)),
        "verification_ready": verifier.get("status") == "HEALTHY",
        "policy_ready": policy.get("status") == "HEALTHY",
        "gateway_ready": gateway.get("status") == "HEALTHY" and gateway.get("real_world_effect") is False,
    }


def sensor_plane_state(health: dict, runtime: dict) -> dict:
    authority = health.get("process_sensor_authority", {})
    canary = health.get("rust_process_canary", {})
    shadow = health.get("rust_process_shadow", {})
    graph = health.get("process_graph", {})
    python_sensor = health.get("process_sensor", {})
    if not isinstance(authority, dict): authority = {}
    if not isinstance(canary, dict): canary = {}
    if not isinstance(shadow, dict): shadow = {}
    if not isinstance(graph, dict): graph = {}
    if not isinstance(python_sensor, dict): python_sensor = {}

    comparison = canary.get("comparison", {})
    if not isinstance(comparison, dict): comparison = {}
    last_result = canary.get("last_result", {})
    if not comparison and isinstance(last_result, dict):
        candidate = last_result.get("comparison", {})
        comparison = candidate if isinstance(candidate, dict) else {}

    snapshot_summary = canary.get("snapshot_summary", {})
    if not isinstance(snapshot_summary, dict): snapshot_summary = {}
    if not snapshot_summary and isinstance(last_result, dict):
        candidate = last_result.get("snapshot_summary", {})
        snapshot_summary = candidate if isinstance(candidate, dict) else {}

    supervisor = canary.get("supervisor", {})
    if not isinstance(supervisor, dict): supervisor = {}
    extra = snapshot_summary.get("extra_enrichment", {})
    if not isinstance(extra, dict): extra = {}
    fields = comparison.get("fields", {})
    if not isinstance(fields, dict): fields = {}

    def _count(section: str) -> int | None:
        value = comparison.get(section, {})
        if not isinstance(value, dict):
            return None
        try:
            return int(value.get("count"))
        except (TypeError, ValueError):
            return None

    def _field(name: str) -> dict:
        value = fields.get(name, {})
        if not isinstance(value, dict): value = {}
        return {
            "matches": value.get("matches"),
            "exact_matches": value.get("exact_matches"),
            "mismatches": value.get("mismatches"),
            "missing": value.get("missing"),
            "coverage_rate": value.get("coverage_rate"),
            "parity_rate": value.get("parity_rate"),
            "sid_backed_display_variants": value.get("sid_backed_display_variants", 0),
            "display_variant_examples": (
                value.get("display_variant_examples", [])[:5]
                if isinstance(value.get("display_variant_examples", []), list)
                else []
            ),
        }

    mode = str(authority.get("mode") or runtime.get("process_sensor_mode") or "PYTHON_ONLY").upper()
    authoritative_sensor = str(authority.get("authoritative_sensor") or "ProcessSensor")
    primary_enabled = bool(authority.get("compiled_primary_enabled", False))
    canary_status = str(canary.get("status", "DISABLED")).upper()

    return safe_json({
        "schema": "cyberdefender.sensor-plane.v1",
        "mode": mode,
        "authoritative_sensor": authoritative_sensor,
        "python_sensor_status": str(python_sensor.get("status", "UNKNOWN")).upper(),
        "process_graph_status": str(graph.get("status", "UNKNOWN")).upper(),
        "primary_compiled_enabled": primary_enabled,
        "primary_lock": "OPEN" if primary_enabled else "CLOSED",
        "single_authority": True,
        "canary": {
            "enabled": bool(runtime.get("rust_process_canary_enabled", mode == "RUST_CANARY")),
            "status": canary_status,
            "sensor_version": canary.get("sensor_version"),
            "authoritative": bool(canary.get("authoritative", False)),
            "promotion_bound": bool(canary.get("promotion_bound", False)),
            "candidate_ready": bool(canary.get("candidate_ready", False)),
            "readiness_reason": canary.get("readiness_reason"),
            "binary_trusted": bool(canary.get("binary_trusted", False)),
            "sample_count": canary.get("sample_count", 0),
            "success_count": canary.get("success_count", 0),
            "failure_count": canary.get("failure_count", 0),
            "last_sample_age_seconds": canary.get("last_sample_age_seconds"),
            "last_sample_latency_ms": canary.get("last_sample_latency_ms"),
            "process_count": snapshot_summary.get("process_count"),
            "partial": snapshot_summary.get("partial"),
            "skipped": snapshot_summary.get("skipped"),
            "coverage_safe": snapshot_summary.get("coverage_safe"),
        },
        "ipc": {
            "protocol": supervisor.get("protocol"),
            "status": supervisor.get("status"),
            "generation": supervisor.get("generation"),
            "sequence": supervisor.get("sequence"),
            "sensor_epoch": supervisor.get("sensor_epoch"),
            "sensor_pid": supervisor.get("sensor_pid"),
            "child_alive": supervisor.get("child_alive"),
            "launch_binding_verified": supervisor.get("launch_binding_verified"),
            "direct_pid_verified": supervisor.get("direct_pid_verified"),
            "restart_count": supervisor.get("restart_count", 0),
            "failures": supervisor.get("failures", 0),
            "last_error": supervisor.get("last_error"),
        },
        "parity": {
            "verdict": comparison.get("verdict"),
            "common_processes": comparison.get("common_processes"),
            "identity_disagreements": _count("identity_disagreements"),
            "parent_disagreements": _count("parent_disagreements"),
            "canonical_name_conflicts": _count("canonical_name_conflicts"),
            "known_system_aliases": _count("known_system_name_aliases"),
            "exe": _field("exe"),
            "username": _field("username"),
            "cmdline": _field("cmdline"),
        },
        "native_enrichment": {
            "sid": extra.get("sid", {}),
            "session_id": extra.get("session_id", {}),
            "integrity_level": extra.get("integrity_level", {}),
        },
        "legacy_shadow": {
            "status": str(shadow.get("status", "DISABLED")).upper(),
            "enabled": bool(runtime.get("rust_process_shadow_enabled", False)),
        },
        "invariants": {
            "rust_enters_process_graph": False,
            "rust_enters_event_bus": False,
            "rust_grants_authorization": False,
            "dashboard_direct_os_access": False,
            "python_remains_authoritative": authoritative_sensor == "ProcessSensor",
        },
    })


def build_admin_state() -> dict:
    owner = build_state()
    health = owner.get("health", {}) if isinstance(owner.get("health"), dict) else {}
    runtime = owner.get("runtime", {}) if isinstance(owner.get("runtime"), dict) else {}
    pipeline_keys = (
        "key_manager", "replay_guard", "admission_gateway", "runtime_pipeline",
        "spool", "pipeline", "event_bus", "correlation_engine", "process_graph",
        "attack_graph", "risk_engine", "policy_engine", "independent_verifier",
        "authorization_gate", "action_gateway",
    )
    pipeline = []
    for key in pipeline_keys:
        value = health.get(key, {})
        if not isinstance(value, dict): value = {}
        pipeline.append({
            "key": key,
            "component": value.get("component", key),
            "status": str(value.get("status", "UNKNOWN")).upper(),
            "version": value.get("version"),
            "failed": value.get("failed", value.get("failures", 0)),
        })
    return safe_json({
        "schema": "cyberdefender.admin-operations.v1",
        "timestamp": time.time(),
        "read_only": True,
        "authoritative": False,
        "loopback_only": True,
        "overall_status": owner.get("overall_status"),
        "runtime_freshness": owner.get("runtime_freshness"),
        "runtime": runtime,
        "resource_state": owner.get("resource_state", {}),
        "process_inventory": owner.get("process_inventory", [])[:24],
        "sensor_plane": owner.get("sensor_plane", {}),
        "pipeline": pipeline,
        "incident_summary": owner.get("incident_summary", {}),
        "event_groups": owner.get("event_groups", [])[:24],
        "components": owner.get("components", []),
        "publisher": owner.get("publisher", {}),
        "safety": owner.get("safety", {}),
        "governance": owner.get("governance", {}),
    })


def build_state() -> dict:
    snapshot = read_json(STATE_FILE)
    fresh = freshness(snapshot)
    runtime = snapshot.get("runtime", {}) if isinstance(snapshot.get("runtime"), dict) else {}
    health = snapshot.get("health", {}) if isinstance(snapshot.get("health"), dict) else {}
    observation = snapshot.get("observation", {}) if isinstance(snapshot.get("observation"), dict) else {}
    incidents = snapshot.get("incidents", []) if isinstance(snapshot.get("incidents"), list) else []
    risk = health.get("risk_engine", {}) if isinstance(health.get("risk_engine"), dict) else {}
    resources = health.get("resource_guard", {}) if isinstance(health.get("resource_guard"), dict) else {}
    safety = health.get("safety_core", {}) if isinstance(health.get("safety_core"), dict) else {}
    policy = health.get("policy_engine", {}) if isinstance(health.get("policy_engine"), dict) else {}
    verifier = health.get("independent_verifier", {}) if isinstance(health.get("independent_verifier"), dict) else {}
    auth = health.get("authorization_gate", {}) if isinstance(health.get("authorization_gate"), dict) else {}
    gateway = health.get("action_gateway", {}) if isinstance(health.get("action_gateway"), dict) else {}
    data_repository = health.get("data_repository", {}) if isinstance(health.get("data_repository"), dict) else {}
    runtime_health = health.get("runtime", {}) if isinstance(health.get("runtime"), dict) else {}
    overall = "AGENT_OFFLINE" if not fresh["available"] else "STALE" if fresh["stale"] else str(runtime_health.get("status") or runtime.get("status") or "UNKNOWN").upper()
    risk_data = runtime.get("risk", {}) if isinstance(runtime.get("risk"), dict) else {}

    # Keep threat risk separate from aggregate runtime/resource risk.
    # The Risk Engine's overall score can be dominated by resource pressure,
    # so it must never be shown as SECURITY POSTURE.
    summary = incident_summary(incidents)

    def _incident_score(incident: dict) -> float | None:
        value = incident.get("risk_score", incident.get("score", incident.get("severity_score")))
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            severity = str(incident.get("severity", incident.get("risk_level", ""))).upper()
            return {"CRITICAL": 100.0, "HIGH": 80.0, "MEDIUM": 60.0, "LOW": 30.0, "INFO": 10.0}.get(severity)

    security_incident_rows = [
        incident for incident in incidents
        if isinstance(incident, dict) and classify_incident(incident) == "SECURITY"
    ]
    security_scores = [score for score in (_incident_score(i) for i in security_incident_rows) if score is not None]
    security_risk_score = round(max(security_scores)) if security_scores else 0

    # Aggregate score remains available for diagnostics, but is deliberately
    # not used for the Security Posture ring.
    aggregate_risk_score = risk_data.get(
        "overall_risk_score",
        risk_data.get("overall_score", risk.get("overall_risk_score", risk.get("overall_score", risk.get("score"))))
    )
    try:
        aggregate_risk_score = round(float(aggregate_risk_score)) if aggregate_risk_score is not None else None
    except (TypeError, ValueError):
        aggregate_risk_score = None

    if security_risk_score >= 80:
        security_risk = "CRITICAL"
    elif security_risk_score >= 60:
        security_risk = "ELEVATED"
    elif security_risk_score > 0:
        security_risk = "GUARDED"
    else:
        security_risk = "CLEAR"
    # Resource posture is independent from threat posture. Prefer the
    # authoritative ResourceGuard status; fall back to bounded incident
    # evidence when the health record is unavailable.
    # ResourceGuard exposes two independent dimensions:
    #   status -> component operational health
    #   state  -> host pressure state (NORMAL/DEGRADED/CRITICAL)
    # Prefer state for Resource Posture; falling back to operational status
    # previously made a 90%+ memory host appear HEALTHY in the UI.
    resource_state_value = str(resources.get("state") or "").upper().strip()
    if resource_state_value == "NORMAL":
        resource_status = "HEALTHY"
    elif resource_state_value in {"DEGRADED", "CRITICAL"}:
        resource_status = resource_state_value
    else:
        resource_status = str(resources.get("status") or "").upper().strip()
        if resource_status in {"HEALTHY", "READY", "OK", "SAFE"}:
            resource_status = "HEALTHY"
        elif resource_status in {"DEGRADED", "WARNING", "ELEVATED", "CONSTRAINED"}:
            resource_status = "DEGRADED" if resource_status in {"DEGRADED", "WARNING"} else "ELEVATED"
        elif resource_status in {"CRITICAL", "RESOURCE_CRITICAL"}:
            resource_status = "CRITICAL"
        else:
            resource_status = "ELEVATED" if summary.get("resource_incidents", 0) > 0 else "UNKNOWN"

    threat_status = security_risk

    # Observer uses memory_available_mb. Older dashboard snapshots/tests used
    # available_memory_mb. Normalize both so the endpoint card never shows
    # an empty value when live telemetry is present.
    available_memory_mb = observation.get("memory_available_mb")
    if available_memory_mb is None:
        available_memory_mb = observation.get("available_memory_mb")

    evidence_events = read_events()

    chain = [
        ("Telemetry", "OBSERVE"), ("Detection", "ANALYZE"), ("Correlation", "ANALYZE"),
        ("Attack Graph", "ANALYZE"), ("Risk Engine", risk.get("status", "UNKNOWN")),
        ("Policy Engine", policy.get("status", "UNKNOWN")), ("Independent Verifier", verifier.get("status", "UNKNOWN")),
        ("Safety Core", safety.get("status", "UNKNOWN")),
        ("Authorization Gate", "DRY_RUN_ONLY" if auth.get("dry_run_only", True) else "REVIEW"),
        ("Action Gateway", "NO_REAL_WORLD_EFFECT" if gateway.get("real_world_effect", False) is False else "BLOCKED"),
    ]
    return safe_json({
        "schema": "cyberdefender.owner-master-control.v3.5",
        "timestamp": time.time(),
        "endpoint": {"hostname": socket.gethostname(), "scope": "LOCAL_ENDPOINT", "transport": "LOOPBACK"},
        "overall_status": overall,
        "security_posture": security_risk,
        "threat_status": threat_status,
        "resource_posture": resource_status,
        "risk_score": security_risk_score,
        "security_risk_score": security_risk_score,
        "aggregate_risk_score": aggregate_risk_score,
        "runtime_freshness": fresh,
        "ui_revision": "owner-v3.6-sensor-plane",
        "sensor_plane": sensor_plane_state(health, runtime),
        "master_control": derive_control_state(health, runtime, fresh),
        "runtime": runtime,
        "observation": observation,
        "process_inventory": (
            runtime.get("process_inventory", [])[:24]
            if isinstance(runtime.get("process_inventory", []), list)
            else []
        ),
        "health": health,
        "resource_state": {
            "status": resource_status,
            "cpu_percent": observation.get("cpu_percent"),
            "memory_percent": observation.get("memory_percent"),
            "disk_percent": observation.get("disk_percent"),
            "process_count": observation.get("process_count"),
            "available_memory_mb": available_memory_mb,
        },
        "components": component_rows(health),
        "data_store": {
            "status": str(data_repository.get("status", "UNKNOWN")).upper(),
            "version": data_repository.get("version"),
            "schema_version": data_repository.get("schema_version"),
            "authoritative": bool(data_repository.get("authoritative", False)),
            "sync_count": data_repository.get("sync_count", 0),
            "failed": data_repository.get("failed", 0),
            "db_bytes": data_repository.get("db_bytes", 0),
            "owner_read_model": {
                "component": "OwnerReadModel",
                "version": OwnerReadModel.VERSION,
                "status": "READY" if DATA_DB_FILE.is_file() else "UNAVAILABLE",
                "authoritative": False,
                "read_only": True,
            },
        },
        "fleet": fleet_snapshot(),
        "application_foundation": {
            "milestone": "P0.8.5",
            "windows_service": True,
            "auto_start_contract": True,
            "machine_state_root": "PROGRAMDATA",
            "distribution_telemetry": True,
            "native_process_canary": True,
            "admin_operations_surface": "/admin",
            "signed_setup_exe": False,
            "presentation_click_installer": True,
            "note": "24/7 service foundation is implemented. Presentation package includes a click-to-install launcher; a code-signed Setup.exe remains a later signing step.",
        },
        "demo_operations": {
            "version": "P0.8.1",
            "incident_drilldown": True,
            "evidence_timeline": True,
            "endpoint_details": True,
            "sql_history_search": True,
            "critical_threat_simulation": True,
            "synthetic_only": True,
            "real_world_effect": False,
        },
        "incidents": incidents[:50],
        "incident_summary": summary,
        "security_chain": [{"name": n, "status": str(s).upper()} for n, s in chain],
        "decision": {
            "risk_level": security_risk,
            "risk_score": security_risk_score,
        "security_risk_score": security_risk_score,
        "aggregate_risk_score": aggregate_risk_score,
            "policy_outcome": runtime.get("policy", {}).get("outcome") if isinstance(runtime.get("policy"), dict) else None,
            "policy_authorization": runtime.get("policy", {}).get("authorization") if isinstance(runtime.get("policy"), dict) else None,
            "verification_outcome": runtime.get("verification", {}).get("outcome") if isinstance(runtime.get("verification"), dict) else None,
            "verification_authorization": runtime.get("verification", {}).get("authorization") if isinstance(runtime.get("verification"), dict) else None,
            "safe_mode": bool(safety.get("safe_mode", False)),
        },
        "safety": {"status": str(safety.get("status", "UNKNOWN")).upper(), "safe_mode": bool(safety.get("safe_mode", False)), "shutdown_requested": bool(safety.get("shutdown_requested", False)), "enforcement": "ACTIVE"},
        "governance": {
            "risk_authorization_separated": True,
            "ai_privileged_authority": "NONE",
            "human_approval_for_l6": True,
            "dashboard_direct_os_access": False,
            "post_action_verification": "DEPLOYED_DRY_RUN",
            "recovery": "PLAN_ONLY_DEPLOYED",
        },
        "events": evidence_events,
        "event_groups": dedupe_events(evidence_events),
        "publisher": snapshot.get("publisher", {}),
    })


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberDefenderOwner/3.5"
    def log_message(self, format, *args):
        return
    def send_data(self, data: bytes, content_type: str, status: int = 200):
        if len(data) > MAX_RESPONSE_BYTES:
            data = b'{"error":"RESPONSE_TOO_LARGE"}'
            status = 500
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_response(302); self.send_header("Location", "/owner"); self.end_headers(); return
        if path == "/admin":
            self.send_data((ADMIN_STATIC / "index.html").read_bytes(), "text/html; charset=utf-8"); return
        if path == "/admin/api/state":
            payload = json.dumps(build_admin_state(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path.startswith("/admin/static/"):
            relative = path[len("/admin/static/"):]
            target = (ADMIN_STATIC / relative).resolve(); root = ADMIN_STATIC.resolve()
            try: inside = os.path.commonpath((str(root), str(target))) == str(root)
            except ValueError: inside = False
            if not inside or not target.is_file(): self.send_data(b"Not Found", "text/plain; charset=utf-8", 404); return
            self.send_data(target.read_bytes(), mimetypes.guess_type(str(target))[0] or "application/octet-stream"); return
        if path == "/owner":
            self.send_data((STATIC / "index.html").read_bytes(), "text/html; charset=utf-8"); return
        if path == "/owner/api/state":
            payload = json.dumps(build_state(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path == "/owner/api/incidents":
            params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            payload = json.dumps(query_incidents(params), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path.startswith("/owner/api/incidents/"):
            incident_id = unquote(path[len("/owner/api/incidents/"):])[:128]
            item = incident_detail(incident_id)
            if item is None:
                self.send_data(b'{"error":"INCIDENT_NOT_FOUND"}', "application/json; charset=utf-8", 404); return
            payload = json.dumps({"status":"OK","authoritative":False,"read_only":True,"incident":item}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path == "/owner/api/endpoint":
            item = endpoint_detail()
            if item is None:
                self.send_data(b'{"error":"ENDPOINT_NOT_FOUND"}', "application/json; charset=utf-8", 404); return
            payload = json.dumps({"status":"OK","authoritative":False,"read_only":True,"endpoint":item}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path == "/owner/api/fleet":
            payload = json.dumps(fleet_snapshot(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path == "/owner/api/demo/critical-threat":
            payload = json.dumps(CriticalThreatDemoScenario.build(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_data(payload, "application/json; charset=utf-8"); return
        if path.startswith("/owner/static/"):
            relative = path[len("/owner/static/"):]
            target = (STATIC / relative).resolve(); root = STATIC.resolve()
            try: inside = os.path.commonpath((str(root), str(target))) == str(root)
            except ValueError: inside = False
            if not inside or not target.is_file(): self.send_data(b"Not Found", "text/plain; charset=utf-8", 404); return
            self.send_data(target.read_bytes(), mimetypes.guess_type(str(target))[0] or "application/octet-stream"); return
        self.send_data(b"Not Found", "text/plain; charset=utf-8", 404)


def serve() -> None:
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    print(f"CyberDefender Owner Master Control v3.5: http://{HOST}:{PORT}/owner")
    print(f"CyberDefender Admin Operations: http://{HOST}:{PORT}/admin")
    serve()
