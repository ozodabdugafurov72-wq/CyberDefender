from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from control_plane.xdr_compat import validate_hostname, validate_runtime_version


PROTOCOL = "cyberdefender.cloud.v2"
MAX_BODY_BYTES = 64 * 1024
MAX_EVENTS = 128
MAX_EVENT_BYTES = 8 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
MAX_RETENTION_RECORDS_PER_ENDPOINT = 50_000
MAX_NONCES_PER_ENDPOINT = 2_048
NONCE_RETENTION_SECONDS = MAX_CLOCK_SKEW_SECONDS * 2

HEADER_PROTOCOL = "X-CyberDefender-Protocol"
HEADER_CREDENTIAL = "X-CyberDefender-Credential-ID"
HEADER_TIMESTAMP = "X-CyberDefender-Timestamp"
HEADER_NONCE = "X-CyberDefender-Nonce"
HEADER_SEQUENCE = "X-CyberDefender-Sequence"
HEADER_DIGEST = "X-CyberDefender-Content-SHA256"
HEADER_SIGNATURE = "X-CyberDefender-Signature"

_TENANT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEALTH = frozenset({"UNKNOWN", "HEALTHY", "DEGRADED", "CRITICAL"})
_SERVICE = frozenset({"STARTING", "RUNNING", "DEGRADED", "STOPPING", "STOPPED", "FAILED"})
_RESOURCE = frozenset({"UNKNOWN", "NORMAL", "DEGRADED", "CRITICAL"})
_PRIORITY = frozenset({"LOW", "NORMAL", "HIGH", "CRITICAL"})
_EVENT_TYPES = frozenset({"DETECTION", "INCIDENT", "ATTACK_GRAPH", "RISK", "QUARANTINE", "AUDIT"})
_EVENT_FIELD_ALLOWLIST = frozenset({
    "action", "category", "component", "count", "detection_id", "duration_ms", "edge_count",
    "file_hash", "incident_id", "node_count", "outcome", "parent_id", "path_hash", "policy",
    "process_hash", "reason", "result", "risk", "rule", "score", "severity", "source",
    "status", "tactic", "target_hash", "technique", "verified",
})


class CloudSocError(ValueError):
    def __init__(self, code: str, *, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def _header(headers: Mapping[str, str], name: str) -> str:
    expected = name.lower()
    for key, value in headers.items():
        if str(key).lower() == expected:
            return str(value).strip()
    return ""


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str, *, size: int) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
    except (ValueError, TypeError) as exc:
        raise CloudSocError("ENCODING_INVALID") from exc
    if len(raw) != size:
        raise CloudSocError("ENCODING_INVALID")
    return raw


def _tenant(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if not _TENANT_RE.fullmatch(normalized):
        raise CloudSocError("TENANT_INVALID")
    return normalized


def _identifier(value: Any, code: str = "IDENTIFIER_INVALID") -> str:
    normalized = str(value or "").strip()
    if not _ID_RE.fullmatch(normalized):
        raise CloudSocError(code)
    return normalized


def _uuid(value: Any, code: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CloudSocError(code) from exc
    if str(parsed) != str(value).lower():
        raise CloudSocError(code)
    return str(parsed)


def _timestamp(value: Any, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CloudSocError(code)
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise CloudSocError(code)
    return result


def _exact_mapping(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CloudSocError("PAYLOAD_INVALID")
    optional = optional or set()
    if not required.issubset(value) or set(value) - required - optional:
        raise CloudSocError("PAYLOAD_FIELDS_INVALID")
    return value


def _bounded_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        raise CloudSocError("EVENT_PAYLOAD_TOO_DEEP")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise CloudSocError("EVENT_VALUE_INVALID")
        return value
    if isinstance(value, str):
        if len(value) > 512 or any(ord(ch) < 0x20 and ch not in "\t" for ch in value):
            raise CloudSocError("EVENT_VALUE_INVALID")
        return value
    if isinstance(value, list):
        if len(value) > 32:
            raise CloudSocError("EVENT_LIST_TOO_LARGE")
        return [_bounded_json(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 32:
            raise CloudSocError("EVENT_OBJECT_TOO_LARGE")
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _ID_RE.fullmatch(key) or key not in _EVENT_FIELD_ALLOWLIST:
                raise CloudSocError("EVENT_FIELD_INVALID")
            result[key] = _bounded_json(item, depth=depth + 1)
        return result
    raise CloudSocError("EVENT_VALUE_INVALID")


def canonical_request(*, method: str, path: str, credential_id: str, timestamp: int,
                      nonce: str, sequence: int, digest: str) -> bytes:
    if method.upper() != "POST" or not path.startswith("/api/v2/") or "\r" in path or "\n" in path:
        raise CloudSocError("REQUEST_TARGET_INVALID")
    credential_id = _uuid(credential_id, "CREDENTIAL_INVALID")
    if not _NONCE_RE.fullmatch(nonce) or not _SHA256_RE.fullmatch(digest):
        raise CloudSocError("REQUEST_AUTH_INVALID", status=401)
    if isinstance(sequence, bool) or not 1 <= int(sequence) <= 2**63 - 1:
        raise CloudSocError("SEQUENCE_INVALID")
    return "\n".join((PROTOCOL, "POST", path, credential_id, str(int(timestamp)), nonce,
                       str(int(sequence)), digest)).encode("ascii")


def signature_headers(private_key: Ed25519PrivateKey, *, credential_id: str, path: str,
                      body: bytes, sequence: int, timestamp: int | None = None,
                      nonce: str | None = None) -> dict[str, str]:
    if len(body) > MAX_BODY_BYTES:
        raise CloudSocError("REQUEST_TOO_LARGE", status=413)
    observed = int(time.time() if timestamp is None else timestamp)
    request_nonce = secrets.token_hex(16) if nonce is None else str(nonce).lower()
    digest = hashlib.sha256(body).hexdigest()
    canonical = canonical_request(method="POST", path=path, credential_id=credential_id,
                                  timestamp=observed, nonce=request_nonce,
                                  sequence=sequence, digest=digest)
    return {
        HEADER_PROTOCOL: PROTOCOL,
        HEADER_CREDENTIAL: credential_id,
        HEADER_TIMESTAMP: str(observed),
        HEADER_NONCE: request_nonce,
        HEADER_SEQUENCE: str(sequence),
        HEADER_DIGEST: digest,
        HEADER_SIGNATURE: _b64e(private_key.sign(canonical)),
    }


@dataclass(frozen=True)
class VerifiedRequest:
    credential_id: str
    timestamp: int
    nonce: str
    sequence: int
    digest: str


def verify_signature(public_key: bytes, *, path: str, body: bytes, headers: Mapping[str, str],
                     now: float | None = None) -> VerifiedRequest:
    if len(body) > MAX_BODY_BYTES:
        raise CloudSocError("REQUEST_TOO_LARGE", status=413)
    if _header(headers, HEADER_PROTOCOL) != PROTOCOL:
        raise CloudSocError("PROTOCOL_REQUIRED", status=401)
    credential_id = _uuid(_header(headers, HEADER_CREDENTIAL), "CREDENTIAL_INVALID")
    nonce = _header(headers, HEADER_NONCE).lower()
    digest = _header(headers, HEADER_DIGEST).lower()
    try:
        timestamp = int(_header(headers, HEADER_TIMESTAMP))
        sequence = int(_header(headers, HEADER_SEQUENCE))
    except (TypeError, ValueError) as exc:
        raise CloudSocError("REQUEST_AUTH_INVALID", status=401) from exc
    current = float(time.time() if now is None else now)
    if abs(current - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        raise CloudSocError("STALE_REQUEST", status=401)
    actual = hashlib.sha256(body).hexdigest()
    if not secrets.compare_digest(actual, digest):
        raise CloudSocError("CONTENT_DIGEST_MISMATCH", status=401)
    canonical = canonical_request(method="POST", path=path, credential_id=credential_id,
                                  timestamp=timestamp, nonce=nonce, sequence=sequence,
                                  digest=actual)
    try:
        signature = _b64d(_header(headers, HEADER_SIGNATURE), size=64)
    except CloudSocError as exc:
        raise CloudSocError("SIGNATURE_INVALID", status=401) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical)
    except (InvalidSignature, ValueError) as exc:
        raise CloudSocError("SIGNATURE_INVALID", status=401) from exc
    return VerifiedRequest(credential_id, timestamp, nonce, sequence, actual)


def validate_heartbeat(value: Any, *, endpoint_id: str, expected_sequence: int) -> dict[str, Any]:
    required = {"schema", "heartbeat_id", "endpoint_id", "boot_id", "seq", "observed_at",
                "health_state", "service_state", "resource_state", "runtime_version",
                "component_failures", "cycle", "cpu_percent", "memory_percent", "spool"}
    body = _exact_mapping(value, required)
    if body["schema"] != "cyberdefender.heartbeat.v2" or body["endpoint_id"] != endpoint_id:
        raise CloudSocError("ENDPOINT_BINDING_MISMATCH", status=403)
    sequence = body["seq"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != expected_sequence:
        raise CloudSocError("SEQUENCE_INVALID")
    failures = body["component_failures"]
    cycle = body["cycle"]
    if isinstance(failures, bool) or not isinstance(failures, int) or failures < 0:
        raise CloudSocError("HEALTH_INVALID")
    if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
        raise CloudSocError("HEALTH_INVALID")
    cpu, memory = body["cpu_percent"], body["memory_percent"]
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) or
           not math.isfinite(float(item)) or not 0 <= float(item) <= 100 for item in (cpu, memory)):
        raise CloudSocError("RESOURCE_INVALID")
    spool = _exact_mapping(body["spool"], {"pending", "bytes", "status"})
    if (isinstance(spool["pending"], bool) or not isinstance(spool["pending"], int) or spool["pending"] < 0 or
            isinstance(spool["bytes"], bool) or not isinstance(spool["bytes"], int) or spool["bytes"] < 0 or
            spool["status"] not in {"HEALTHY", "DEGRADED", "BLOCKED"}):
        raise CloudSocError("SPOOL_INVALID")
    return {
        "request_id": _identifier(body["heartbeat_id"], "HEARTBEAT_ID_INVALID"),
        "endpoint_id": endpoint_id,
        "boot_id": _uuid(body["boot_id"], "BOOT_ID_INVALID"),
        "first_sequence": sequence,
        "last_sequence": sequence,
        "observed_at": _timestamp(body["observed_at"], "OBSERVED_AT_INVALID"),
        "health_state": body["health_state"] if body["health_state"] in _HEALTH else _raise("HEALTH_INVALID"),
        "service_state": body["service_state"] if body["service_state"] in _SERVICE else _raise("SERVICE_INVALID"),
        "resource_state": body["resource_state"] if body["resource_state"] in _RESOURCE else _raise("RESOURCE_INVALID"),
        "runtime_version": validate_runtime_version(body["runtime_version"]),
        "component_failures": failures,
        "cycle": cycle,
        "cpu_percent": round(float(cpu), 3),
        "memory_percent": round(float(memory), 3),
        "spool": dict(spool),
    }


def _raise(code: str):
    raise CloudSocError(code)


def validate_event_batch(value: Any, *, endpoint_id: str, expected_sequence: int) -> dict[str, Any]:
    required = {"schema", "batch_id", "endpoint_id", "boot_id", "first_seq", "last_seq", "events"}
    body = _exact_mapping(value, required)
    if body["schema"] != "cyberdefender.event-batch.v2" or body["endpoint_id"] != endpoint_id:
        raise CloudSocError("ENDPOINT_BINDING_MISMATCH", status=403)
    first, last, events = body["first_seq"], body["last_seq"], body["events"]
    if (isinstance(first, bool) or not isinstance(first, int) or isinstance(last, bool) or
            not isinstance(last, int) or first < 1 or last != expected_sequence or last < first):
        raise CloudSocError("SEQUENCE_INVALID")
    if not isinstance(events, list) or not events or len(events) > MAX_EVENTS or len(events) != last - first + 1:
        raise CloudSocError("EVENT_BATCH_INVALID")
    normalized = []
    seen = set()
    for offset, raw in enumerate(events):
        event = _exact_mapping(raw, {"event_id", "seq", "observed_at", "type", "priority", "payload"})
        event_id = _identifier(event["event_id"], "EVENT_ID_INVALID")
        if event_id in seen or event["seq"] != first + offset:
            raise CloudSocError("EVENT_BATCH_INVALID")
        if event["type"] not in _EVENT_TYPES or event["priority"] not in _PRIORITY:
            raise CloudSocError("EVENT_TYPE_INVALID")
        payload = _bounded_json(event["payload"])
        if len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")) > MAX_EVENT_BYTES:
            raise CloudSocError("EVENT_TOO_LARGE")
        normalized.append({"event_id": event_id, "seq": event["seq"],
                           "observed_at": _timestamp(event["observed_at"], "OBSERVED_AT_INVALID"),
                           "type": event["type"], "priority": event["priority"], "payload": payload})
        seen.add(event_id)
    return {"request_id": _identifier(body["batch_id"], "BATCH_ID_INVALID"),
            "endpoint_id": endpoint_id, "boot_id": _uuid(body["boot_id"], "BOOT_ID_INVALID"),
            "first_sequence": first, "last_sequence": last, "events": normalized}


class CloudSocRepository:
    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._conn = sqlite3.connect(str(self.db_path), timeout=2.0, isolation_level=None,
                                    check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA trusted_schema=OFF")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS cloud_soc_schema(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS cloud_enrollment_codes(
              code_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, expires_at REAL NOT NULL,
              consumed_at REAL, created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cloud_endpoints(
              endpoint_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_instance_id TEXT NOT NULL,
              hostname TEXT NOT NULL, credential_generation INTEGER NOT NULL, state TEXT NOT NULL,
              last_sequence INTEGER NOT NULL DEFAULT 0, last_boot_id TEXT,
              last_heartbeat_received REAL, last_observed_at REAL, health_state TEXT NOT NULL DEFAULT 'UNKNOWN',
              service_state TEXT NOT NULL DEFAULT 'STOPPED', resource_state TEXT NOT NULL DEFAULT 'UNKNOWN',
              runtime_version TEXT NOT NULL DEFAULT 'unversioned', component_failures INTEGER NOT NULL DEFAULT 0,
              cycle INTEGER NOT NULL DEFAULT 0, cpu_percent REAL, memory_percent REAL,
              spool_pending INTEGER NOT NULL DEFAULT 0, spool_bytes INTEGER NOT NULL DEFAULT 0,
              spool_status TEXT NOT NULL DEFAULT 'HEALTHY', created_at REAL NOT NULL,
              UNIQUE(tenant_id, agent_instance_id), UNIQUE(tenant_id, endpoint_id)
            );
            CREATE TABLE IF NOT EXISTS cloud_endpoint_credentials(
              credential_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
              generation INTEGER NOT NULL, public_key BLOB NOT NULL, state TEXT NOT NULL,
              not_before REAL NOT NULL, not_after REAL, revoked_at REAL,
              UNIQUE(tenant_id, endpoint_id, generation),
              FOREIGN KEY(endpoint_id) REFERENCES cloud_endpoints(endpoint_id)
            );
            CREATE TABLE IF NOT EXISTS cloud_request_nonces(
              tenant_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, nonce TEXT NOT NULL, received_at REAL NOT NULL,
              PRIMARY KEY(tenant_id, endpoint_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS cloud_ingest_records(
              tenant_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, request_id TEXT NOT NULL, kind TEXT NOT NULL,
              first_sequence INTEGER NOT NULL, last_sequence INTEGER NOT NULL, boot_id TEXT NOT NULL,
              observed_at REAL, received_at REAL NOT NULL, payload_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL,
              PRIMARY KEY(tenant_id, endpoint_id, request_id),
              UNIQUE(tenant_id, endpoint_id, first_sequence, last_sequence)
            );
            CREATE TABLE IF NOT EXISTS cloud_events(
              tenant_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, event_id TEXT NOT NULL,
              sequence INTEGER NOT NULL, observed_at REAL NOT NULL, received_at REAL NOT NULL,
              event_type TEXT NOT NULL, priority TEXT NOT NULL, payload_json TEXT NOT NULL,
              PRIMARY KEY(tenant_id, endpoint_id, event_id),
              UNIQUE(tenant_id, endpoint_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS idx_cloud_endpoints_tenant_seen
              ON cloud_endpoints(tenant_id, last_heartbeat_received DESC);
            CREATE INDEX IF NOT EXISTS idx_cloud_events_tenant_time
              ON cloud_events(tenant_id, received_at DESC);
            INSERT OR IGNORE INTO cloud_soc_schema(version, applied_at) VALUES(1, strftime('%s','now'));
            COMMIT;
            """)

    @staticmethod
    def _code_hash(code: str) -> str:
        return hashlib.sha256(str(code).encode("ascii", "strict")).hexdigest()

    def issue_enrollment_code(self, tenant_id: str, *, now: float | None = None,
                              ttl_seconds: int = 600) -> str:
        tenant_id = _tenant(tenant_id)
        current = float(time.time() if now is None else now)
        ttl = max(60, min(int(ttl_seconds), 3600))
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._conn.execute(
                "INSERT INTO cloud_enrollment_codes(code_hash,tenant_id,expires_at,created_at) VALUES(?,?,?,?)",
                (self._code_hash(code), tenant_id, current + ttl, current),
            )
        return code

    def enroll(self, value: Any, *, now: float | None = None) -> dict[str, Any]:
        body = _exact_mapping(value, {"schema", "one_time_code", "agent_instance_id",
                                      "device_public_key", "hostname", "runtime_version", "capabilities"})
        if body["schema"] != "cyberdefender.enrollment.v2":
            raise CloudSocError("SCHEMA_INVALID")
        code = str(body["one_time_code"])
        if not 32 <= len(code) <= 128:
            raise CloudSocError("ENROLLMENT_CODE_INVALID", status=401)
        agent_instance = _uuid(body["agent_instance_id"], "AGENT_INSTANCE_INVALID")
        public_key = _b64d(body["device_public_key"], size=32)
        hostname = validate_hostname(body["hostname"])
        runtime_version = validate_runtime_version(body["runtime_version"])
        capabilities = body["capabilities"]
        if (not isinstance(capabilities, list) or not capabilities or len(capabilities) > 16 or
                any(not isinstance(item, str) or not _ID_RE.fullmatch(item) for item in capabilities)):
            raise CloudSocError("CAPABILITIES_INVALID")
        current = float(time.time() if now is None else now)
        endpoint_id, credential_id = str(uuid.uuid4()), str(uuid.uuid4())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM cloud_enrollment_codes WHERE code_hash=?",
                    (self._code_hash(code),),
                ).fetchone()
                if row is None or row["consumed_at"] is not None or float(row["expires_at"]) < current:
                    raise CloudSocError("ENROLLMENT_CODE_REJECTED", status=401)
                tenant_id = _tenant(row["tenant_id"])
                self._conn.execute(
                    """INSERT INTO cloud_endpoints(
                      endpoint_id,tenant_id,agent_instance_id,hostname,credential_generation,state,
                      runtime_version,created_at) VALUES(?,?,?,?,1,'ENROLLED',?,?)""",
                    (endpoint_id, tenant_id, agent_instance, hostname, runtime_version, current),
                )
                self._conn.execute(
                    """INSERT INTO cloud_endpoint_credentials(
                      credential_id,tenant_id,endpoint_id,generation,public_key,state,not_before)
                      VALUES(?,?,?,?,?,'ACTIVE',?)""",
                    (credential_id, tenant_id, endpoint_id, 1, public_key, current),
                )
                updated = self._conn.execute(
                    "UPDATE cloud_enrollment_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL",
                    (current, self._code_hash(code)),
                ).rowcount
                if updated != 1:
                    raise CloudSocError("ENROLLMENT_CODE_REJECTED", status=401)
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return {"schema": "cyberdefender.enrollment-result.v2", "tenant_id": tenant_id,
                "endpoint_id": endpoint_id, "credential_id": credential_id,
                "credential_generation": 1, "server_time": current,
                "private_key_returned": False}

    def credential(self, credential_id: str, *, now: float | None = None) -> dict[str, Any]:
        try:
            credential_id = _uuid(credential_id, "CREDENTIAL_INVALID")
        except CloudSocError as exc:
            raise CloudSocError("CREDENTIAL_REJECTED", status=401) from exc
        current = float(time.time() if now is None else now)
        with self._lock:
            row = self._conn.execute(
                """SELECT c.*,e.state endpoint_state FROM cloud_endpoint_credentials c
                   JOIN cloud_endpoints e ON e.endpoint_id=c.endpoint_id WHERE c.credential_id=?""",
                (credential_id,),
            ).fetchone()
        if row is None or row["endpoint_state"] != "ENROLLED" or row["state"] not in {"ACTIVE", "GRACE"}:
            raise CloudSocError("CREDENTIAL_REJECTED", status=401)
        if float(row["not_before"]) > current or (row["not_after"] is not None and float(row["not_after"]) < current):
            raise CloudSocError("CREDENTIAL_REJECTED", status=401)
        return dict(row)

    def rotate_credential(self, *, tenant_id: str, endpoint_id: str, current_credential_id: str,
                          new_public_key: str, now: float | None = None,
                          overlap_seconds: int = 300) -> dict[str, Any]:
        tenant_id, endpoint_id = _tenant(tenant_id), _uuid(endpoint_id, "ENDPOINT_INVALID")
        current_credential_id = _uuid(current_credential_id, "CREDENTIAL_INVALID")
        public_key = _b64d(new_public_key, size=32)
        current = float(time.time() if now is None else now)
        overlap = max(0, min(int(overlap_seconds), 900))
        new_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    """SELECT generation,state FROM cloud_endpoint_credentials
                       WHERE credential_id=? AND tenant_id=? AND endpoint_id=?""",
                    (current_credential_id, tenant_id, endpoint_id),
                ).fetchone()
                if row is None or row["state"] != "ACTIVE":
                    raise CloudSocError("CREDENTIAL_REJECTED", status=401)
                generation = int(row["generation"]) + 1
                self._conn.execute(
                    "UPDATE cloud_endpoint_credentials SET state='GRACE',not_after=? WHERE credential_id=?",
                    (current + overlap, current_credential_id),
                )
                self._conn.execute(
                    """INSERT INTO cloud_endpoint_credentials(
                      credential_id,tenant_id,endpoint_id,generation,public_key,state,not_before)
                      VALUES(?,?,?,?,?,'ACTIVE',?)""",
                    (new_id, tenant_id, endpoint_id, generation, public_key, current),
                )
                self._conn.execute(
                    "UPDATE cloud_endpoints SET credential_generation=? WHERE tenant_id=? AND endpoint_id=?",
                    (generation, tenant_id, endpoint_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return {"credential_id": new_id, "generation": generation, "overlap_until": current + overlap}

    def revoke_endpoint(self, tenant_id: str, endpoint_id: str, *, now: float | None = None) -> None:
        tenant_id, endpoint_id = _tenant(tenant_id), _uuid(endpoint_id, "ENDPOINT_INVALID")
        current = float(time.time() if now is None else now)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                updated = self._conn.execute(
                    "UPDATE cloud_endpoints SET state='REVOKED' WHERE tenant_id=? AND endpoint_id=?",
                    (tenant_id, endpoint_id),
                ).rowcount
                if updated != 1:
                    raise CloudSocError("ENDPOINT_NOT_FOUND", status=404)
                self._conn.execute(
                    "UPDATE cloud_endpoint_credentials SET state='REVOKED',revoked_at=? WHERE tenant_id=? AND endpoint_id=?",
                    (current, tenant_id, endpoint_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def ingest(self, *, binding: Mapping[str, Any], verified: VerifiedRequest,
               kind: str, normalized: Mapping[str, Any], raw_body: bytes,
               now: float | None = None) -> dict[str, Any]:
        tenant_id, endpoint_id = _tenant(binding["tenant_id"]), str(binding["endpoint_id"])
        if verified.credential_id != binding["credential_id"] or normalized["endpoint_id"] != endpoint_id:
            raise CloudSocError("ENDPOINT_BINDING_MISMATCH", status=403)
        first, last = int(normalized["first_sequence"]), int(normalized["last_sequence"])
        if verified.sequence != last:
            raise CloudSocError("SEQUENCE_INVALID", status=409)
        received = float(time.time() if now is None else now)
        payload_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        request_id = str(normalized["request_id"])
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "DELETE FROM cloud_request_nonces WHERE tenant_id=? AND endpoint_id=? AND received_at<?",
                    (tenant_id, endpoint_id, received - NONCE_RETENTION_SECONDS),
                )
                nonce_count = self._conn.execute(
                    "SELECT COUNT(*) n FROM cloud_request_nonces WHERE tenant_id=? AND endpoint_id=?",
                    (tenant_id, endpoint_id),
                ).fetchone()["n"]
                if int(nonce_count) >= MAX_NONCES_PER_ENDPOINT:
                    raise CloudSocError("NONCE_WINDOW_SATURATED", status=429)
                try:
                    self._conn.execute(
                        "INSERT INTO cloud_request_nonces(tenant_id,endpoint_id,nonce,received_at) VALUES(?,?,?,?)",
                        (tenant_id, endpoint_id, verified.nonce, received),
                    )
                except sqlite3.IntegrityError as exc:
                    raise CloudSocError("REPLAY_DETECTED", status=409) from exc
                existing = self._conn.execute(
                    """SELECT * FROM cloud_ingest_records
                       WHERE tenant_id=? AND endpoint_id=? AND request_id=?""",
                    (tenant_id, endpoint_id, request_id),
                ).fetchone()
                if existing is not None:
                    if (existing["payload_sha256"] == verified.digest and existing["kind"] == kind and
                            int(existing["first_sequence"]) == first and int(existing["last_sequence"]) == last):
                        self._conn.execute("COMMIT")
                        return {"status": "DUPLICATE_ACK", "accepted_through": last}
                    raise CloudSocError("IDEMPOTENCY_CONFLICT", status=409)
                endpoint = self._conn.execute(
                    "SELECT * FROM cloud_endpoints WHERE tenant_id=? AND endpoint_id=?",
                    (tenant_id, endpoint_id),
                ).fetchone()
                if endpoint is None or endpoint["state"] != "ENROLLED":
                    raise CloudSocError("ENDPOINT_REJECTED", status=403)
                if first != int(endpoint["last_sequence"]) + 1:
                    raise CloudSocError("SEQUENCE_GAP", status=409)
                self._conn.execute(
                    """INSERT INTO cloud_ingest_records(
                      tenant_id,endpoint_id,request_id,kind,first_sequence,last_sequence,boot_id,
                      observed_at,received_at,payload_sha256,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (tenant_id, endpoint_id, request_id, kind, first, last, normalized["boot_id"],
                     normalized.get("observed_at"), received, verified.digest, payload_json),
                )
                if kind == "HEARTBEAT":
                    self._conn.execute(
                        """UPDATE cloud_endpoints SET last_sequence=?,last_boot_id=?,last_heartbeat_received=?,
                          last_observed_at=?,health_state=?,service_state=?,resource_state=?,runtime_version=?,
                          component_failures=?,cycle=?,cpu_percent=?,memory_percent=?,spool_pending=?,
                          spool_bytes=?,spool_status=? WHERE tenant_id=? AND endpoint_id=?""",
                        (last, normalized["boot_id"], received, normalized["observed_at"],
                         normalized["health_state"], normalized["service_state"], normalized["resource_state"],
                         normalized["runtime_version"], normalized["component_failures"], normalized["cycle"],
                         normalized["cpu_percent"], normalized["memory_percent"], normalized["spool"]["pending"],
                         normalized["spool"]["bytes"], normalized["spool"]["status"], tenant_id, endpoint_id),
                    )
                else:
                    for event in normalized["events"]:
                        self._conn.execute(
                            """INSERT INTO cloud_events(
                              tenant_id,endpoint_id,event_id,sequence,observed_at,received_at,event_type,
                              priority,payload_json) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (tenant_id, endpoint_id, event["event_id"], event["seq"], event["observed_at"],
                             received, event["type"], event["priority"],
                             json.dumps(event["payload"], sort_keys=True, separators=(",", ":"))),
                        )
                    self._conn.execute(
                        "UPDATE cloud_endpoints SET last_sequence=?,last_boot_id=? WHERE tenant_id=? AND endpoint_id=?",
                        (last, normalized["boot_id"], tenant_id, endpoint_id),
                    )
                count = self._conn.execute(
                    "SELECT COUNT(*) n FROM cloud_ingest_records WHERE tenant_id=? AND endpoint_id=?",
                    (tenant_id, endpoint_id),
                ).fetchone()["n"]
                if int(count) > MAX_RETENTION_RECORDS_PER_ENDPOINT:
                    raise CloudSocError("RETENTION_LIMIT_REACHED", status=429)
                self._conn.execute("COMMIT")
                return {"status": "ACK", "accepted_through": last, "server_time": received}
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def tenant_snapshot(self, tenant_id: str, *, now: float | None = None,
                        online_after_seconds: int = 90, limit: int = 100) -> dict[str, Any]:
        tenant_id = _tenant(tenant_id)
        current = float(time.time() if now is None else now)
        cutoff = current - max(30, min(int(online_after_seconds), 300))
        limit = max(1, min(int(limit), 100))
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM cloud_endpoints WHERE tenant_id=?
                   ORDER BY last_heartbeat_received DESC LIMIT ?""", (tenant_id, limit)).fetchall()
            event_rows = self._conn.execute(
                """SELECT event_type,priority,COUNT(*) count FROM cloud_events WHERE tenant_id=?
                   GROUP BY event_type,priority""", (tenant_id,)).fetchall()
            recent_event_rows = self._conn.execute(
                """SELECT event_id,endpoint_id,observed_at,received_at,event_type,priority
                   FROM cloud_events WHERE tenant_id=?
                   ORDER BY received_at DESC, sequence DESC LIMIT 100""", (tenant_id,)).fetchall()
        endpoints = []
        for row in rows:
            active = row["state"] == "ENROLLED"
            fresh = active and row["last_heartbeat_received"] is not None and float(row["last_heartbeat_received"]) >= cutoff
            endpoints.append({
                "endpoint_id": row["endpoint_id"], "hostname": row["hostname"],
                "status": "ONLINE" if fresh else ("REVOKED" if not active else "OFFLINE"),
                "health_state": row["health_state"] if fresh else "OFFLINE",
                "service_state": row["service_state"] if fresh else "UNKNOWN",
                "resource_state": row["resource_state"] if fresh else "UNKNOWN",
                "runtime_version": row["runtime_version"], "last_verified_heartbeat": row["last_heartbeat_received"],
                "last_observed_at": row["last_observed_at"], "component_failures": row["component_failures"],
                "cycle": row["cycle"], "cpu_percent": row["cpu_percent"] if fresh else None,
                "memory_percent": row["memory_percent"] if fresh else None,
                "telemetry_status": row["spool_status"] if fresh else "STALE",
                "spool_pending": row["spool_pending"],
                "spool_bytes": row["spool_bytes"],
                "spool_status": row["spool_status"] if fresh else "STALE",
                "accepted_through": row["last_sequence"],
            })
        counts = {"total": len(endpoints), "online": 0, "offline": 0, "degraded": 0, "critical": 0}
        for endpoint in endpoints:
            counts["online" if endpoint["status"] == "ONLINE" else "offline"] += 1
            if endpoint["health_state"] in {"DEGRADED", "CRITICAL"}:
                counts[endpoint["health_state"].lower()] += 1
        return {"schema": "cyberdefender.fleet-read-model.v2", "tenant_id": tenant_id,
                "generated_at": current, "online_after_seconds": current - cutoff,
                "summary": counts, "endpoints": endpoints,
                "event_summary": [dict(row) for row in event_rows],
                "recent_events": [dict(row) for row in recent_event_rows], "read_only": True,
                "privileged_actions": "DISABLED"}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class CloudSocService:
    def __init__(self, repository: CloudSocRepository, *, clock=time.time):
        self.repository = repository
        self.clock = clock

    def _verified(self, *, path: str, raw_body: bytes, headers: Mapping[str, str]) -> tuple[dict[str, Any], VerifiedRequest]:
        credential_id = _header(headers, HEADER_CREDENTIAL)
        binding = self.repository.credential(credential_id, now=self.clock())
        verified = verify_signature(binding["public_key"], path=path, body=raw_body,
                                    headers=headers, now=self.clock())
        return binding, verified

    def ingest_heartbeat(self, endpoint_id: str, raw_body: bytes,
                         headers: Mapping[str, str]) -> dict[str, Any]:
        endpoint_id = _uuid(endpoint_id, "ENDPOINT_INVALID")
        path = f"/api/v2/endpoints/{endpoint_id}/heartbeat"
        binding, verified = self._verified(path=path, raw_body=raw_body, headers=headers)
        if binding["endpoint_id"] != endpoint_id:
            raise CloudSocError("ENDPOINT_BINDING_MISMATCH", status=403)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CloudSocError("PAYLOAD_INVALID") from exc
        normalized = validate_heartbeat(payload, endpoint_id=endpoint_id,
                                        expected_sequence=verified.sequence)
        return self.repository.ingest(binding=binding, verified=verified, kind="HEARTBEAT",
                                      normalized=normalized, raw_body=raw_body, now=self.clock())

    def ingest_events(self, endpoint_id: str, raw_body: bytes,
                      headers: Mapping[str, str]) -> dict[str, Any]:
        endpoint_id = _uuid(endpoint_id, "ENDPOINT_INVALID")
        path = f"/api/v2/endpoints/{endpoint_id}/event-batches"
        binding, verified = self._verified(path=path, raw_body=raw_body, headers=headers)
        if binding["endpoint_id"] != endpoint_id:
            raise CloudSocError("ENDPOINT_BINDING_MISMATCH", status=403)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CloudSocError("PAYLOAD_INVALID") from exc
        normalized = validate_event_batch(payload, endpoint_id=endpoint_id,
                                          expected_sequence=verified.sequence)
        return self.repository.ingest(binding=binding, verified=verified, kind="EVENT_BATCH",
                                      normalized=normalized, raw_body=raw_body, now=self.clock())
