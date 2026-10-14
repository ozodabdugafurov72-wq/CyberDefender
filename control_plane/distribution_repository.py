from __future__ import annotations

import sqlite3
import time
import uuid
import math
import json
from pathlib import Path
from threading import RLock
from typing import Any

from control_plane.xdr_compat import (
    OCSF_SCHEMA_NAME,
    OCSF_SCHEMA_VERSION,
    capabilities_json,
    normalize_capabilities,
    validate_endpoint_id,
    validate_hostname,
    validate_runtime_version,
    validate_response_evidence,
)


class DistributionRepository:
    """Operational telemetry store for downloads, installs and fleet presence.

    This store is deliberately separate from the endpoint security database.
    It is NOT an authorization source and never participates in Policy, Safety,
    crypto admission, replay protection or durable event delivery.
    """

    VERSION = "1.3"
    SCHEMA_VERSION = 4
    VALID_INSTALL_STATES = {"PENDING", "INSTALLED", "FAILED", "REVOKED"}
    VALID_HEALTH_STATES = {"UNKNOWN", "HEALTHY", "DEGRADED", "CRITICAL", "OFFLINE"}
    VALID_SERVICE_STATES = {
        "UNKNOWN", "REGISTERED", "STARTING", "RUNNING", "DEGRADED",
        "STOPPING", "STOPPED", "FAILED",
    }
    VALID_RESOURCE_STATES = {"UNKNOWN", "NORMAL", "DEGRADED", "CRITICAL"}

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._conn = sqlite3.connect(str(self.db_path), timeout=2.0, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=2000")
        self._conn.execute("PRAGMA trusted_schema=OFF")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS distribution_schema (
                        version INTEGER PRIMARY KEY,
                        applied_at REAL NOT NULL
                    )
                """)
                current = self._conn.execute("SELECT COALESCE(MAX(version),0) AS v FROM distribution_schema").fetchone()["v"]
                if int(current) < 1:
                    self._conn.execute("""
                        CREATE TABLE IF NOT EXISTS downloads (
                            download_id TEXT PRIMARY KEY,
                            requested_at REAL NOT NULL,
                            completed_at REAL,
                            status TEXT NOT NULL,
                            artifact_name TEXT NOT NULL,
                            version TEXT,
                            channel TEXT NOT NULL,
                            bytes_sent INTEGER NOT NULL DEFAULT 0
                        )
                    """)
                    self._conn.execute("CREATE INDEX IF NOT EXISTS idx_downloads_requested ON downloads(requested_at DESC)")
                    self._conn.execute("CREATE INDEX IF NOT EXISTS idx_downloads_status ON downloads(status, requested_at DESC)")
                    self._conn.execute("""
                        CREATE TABLE IF NOT EXISTS fleet_endpoints (
                            endpoint_id TEXT PRIMARY KEY,
                            hostname TEXT NOT NULL,
                            download_id TEXT,
                            install_state TEXT NOT NULL,
                            health_state TEXT NOT NULL,
                            service_state TEXT NOT NULL,
                            runtime_version TEXT,
                            resource_state TEXT,
                            first_seen REAL NOT NULL,
                            last_seen REAL NOT NULL,
                            last_error TEXT,
                            FOREIGN KEY(download_id) REFERENCES downloads(download_id)
                        )
                    """)
                    self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_last_seen ON fleet_endpoints(last_seen DESC)")
                    self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_install_state ON fleet_endpoints(install_state, last_seen DESC)")
                    self._conn.execute("INSERT INTO distribution_schema(version, applied_at) VALUES(1, ?)", (time.time(),))
                    current = 1
                if int(current) < 2:
                    columns = {
                        row["name"]
                        for row in self._conn.execute("PRAGMA table_info(fleet_endpoints)").fetchall()
                    }
                    additions = {
                        "telemetry_schema": "TEXT NOT NULL DEFAULT 'legacy'",
                        "telemetry_schema_version": "TEXT NOT NULL DEFAULT 'unversioned'",
                        "capabilities_json": "TEXT NOT NULL DEFAULT '[]'",
                        "last_observed_at": "REAL",
                    }
                    for name, definition in additions.items():
                        if name not in columns:
                            self._conn.execute(
                                f"ALTER TABLE fleet_endpoints ADD COLUMN {name} {definition}"
                            )
                    self._conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS fleet_request_nonces (
                            nonce TEXT PRIMARY KEY,
                            endpoint_id TEXT NOT NULL,
                            observed_at REAL NOT NULL
                        )
                        """
                    )
                    self._conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_fleet_nonces_time "
                        "ON fleet_request_nonces(observed_at)"
                    )
                    self._conn.execute(
                        "INSERT INTO distribution_schema(version, applied_at) VALUES(2, ?)",
                        (time.time(),),
                    )
                    current = 2
                if int(current) < 3:
                    self._conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS fleet_response_evidence (
                            evidence_id TEXT PRIMARY KEY,
                            endpoint_id TEXT NOT NULL,
                            incident_id TEXT NOT NULL,
                            event_id TEXT NOT NULL,
                            observed_at REAL NOT NULL,
                            received_at REAL NOT NULL,
                            target_name TEXT NOT NULL,
                            target_sha256 TEXT NOT NULL,
                            detection_types_json TEXT NOT NULL,
                            risk_score REAL NOT NULL,
                            risk_level TEXT NOT NULL,
                            policy_outcome TEXT NOT NULL,
                            policy_reason TEXT NOT NULL,
                            verifier_outcome TEXT NOT NULL,
                            action_state TEXT NOT NULL,
                            verification_outcome TEXT NOT NULL,
                            response_latency_ms REAL NOT NULL,
                            execution_latency_ms REAL NOT NULL,
                            detection_to_response_ms REAL NOT NULL,
                            restore_latency_ms REAL,
                            evidence_ref TEXT NOT NULL,
                            production_authorization TEXT NOT NULL,
                            lab_authorization TEXT NOT NULL,
                            receipt_integrity INTEGER NOT NULL,
                            post_action_verification INTEGER NOT NULL,
                            FOREIGN KEY(endpoint_id) REFERENCES fleet_endpoints(endpoint_id)
                        )
                        """
                    )
                    self._conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_response_evidence_received "
                        "ON fleet_response_evidence(received_at DESC)"
                    )
                    self._conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_response_evidence_endpoint "
                        "ON fleet_response_evidence(endpoint_id, received_at DESC)"
                    )
                    self._conn.execute(
                        "INSERT INTO distribution_schema(version, applied_at) VALUES(3, ?)",
                        (time.time(),),
                    )
                    current = 3
                if int(current) < 4:
                    columns = {
                        row["name"]
                        for row in self._conn.execute("PRAGMA table_info(fleet_response_evidence)").fetchall()
                    }
                    if "authorization_policy_id" not in columns:
                        self._conn.execute(
                            "ALTER TABLE fleet_response_evidence ADD COLUMN authorization_policy_id TEXT"
                        )
                    self._conn.execute(
                        "INSERT INTO distribution_schema(version, applied_at) VALUES(4, ?)",
                        (time.time(),),
                    )
                final = self._conn.execute("SELECT COALESCE(MAX(version),0) AS v FROM distribution_schema").fetchone()["v"]
                if int(final) != self.SCHEMA_VERSION:
                    raise RuntimeError(f"distribution schema mismatch: {final}")
                self._conn.execute("COMMIT")
            except Exception:
                try: self._conn.execute("ROLLBACK")
                except Exception: pass
                raise

    def begin_download(self, *, artifact_name: str, version: str = "", channel: str = "stable") -> str:
        download_id = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO downloads(download_id,requested_at,status,artifact_name,version,channel,bytes_sent) VALUES(?,?,?,?,?,?,0)",
                (download_id, now, "STARTED", str(artifact_name)[:255], str(version)[:64], str(channel)[:32]),
            )
        return download_id

    def complete_download(self, download_id: str, *, bytes_sent: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE downloads SET status='COMPLETED', completed_at=?, bytes_sent=? WHERE download_id=?",
                (time.time(), max(0, int(bytes_sent)), str(download_id)),
            )

    def fail_download(self, download_id: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE downloads SET status='FAILED' WHERE download_id=?", (str(download_id),))

    def register_endpoint(self, *, endpoint_id: str, hostname: str, download_id: str | None = None,
                          runtime_version: str = "", install_state: str = "INSTALLED",
                          health_state: str = "UNKNOWN", service_state: str = "REGISTERED",
                          telemetry_schema: str = "legacy", telemetry_schema_version: str = "unversioned",
                          capabilities: tuple[str, ...] = (), observed_at: float | None = None) -> None:
        endpoint_id = validate_endpoint_id(endpoint_id)
        hostname = validate_hostname(hostname)
        runtime_version = validate_runtime_version(runtime_version)
        install_state = str(install_state).upper()
        health_state = str(health_state).upper()
        service_state = str(service_state).upper()
        if install_state not in self.VALID_INSTALL_STATES: raise ValueError("invalid install_state")
        if health_state not in self.VALID_HEALTH_STATES: raise ValueError("invalid health_state")
        if service_state not in self.VALID_SERVICE_STATES: raise ValueError("invalid service_state")
        telemetry_schema, telemetry_schema_version, capability_value = self._telemetry_contract(
            telemetry_schema, telemetry_schema_version, capabilities
        )
        now = time.time()
        observed = now if observed_at is None else float(observed_at)
        if not math.isfinite(observed):
            raise ValueError("invalid observed_at")
        with self._lock:
            self._conn.execute("""
                INSERT INTO fleet_endpoints(endpoint_id,hostname,download_id,install_state,health_state,service_state,runtime_version,resource_state,first_seen,last_seen,last_error,telemetry_schema,telemetry_schema_version,capabilities_json,last_observed_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?)
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    download_id=COALESCE(excluded.download_id,fleet_endpoints.download_id),
                    install_state=excluded.install_state,
                    health_state=excluded.health_state,
                    service_state=excluded.service_state,
                    runtime_version=excluded.runtime_version,
                    last_seen=excluded.last_seen,
                    telemetry_schema=excluded.telemetry_schema,
                    telemetry_schema_version=excluded.telemetry_schema_version,
                    capabilities_json=excluded.capabilities_json,
                    last_observed_at=excluded.last_observed_at
            """, (endpoint_id, hostname, download_id, install_state, health_state,
                  service_state, runtime_version, "UNKNOWN", now, now,
                  telemetry_schema, telemetry_schema_version, capability_value, observed))

    def heartbeat(self, *, endpoint_id: str, hostname: str, runtime_version: str,
                  health_state: str, service_state: str, resource_state: str = "",
                  last_error: str | None = None, telemetry_schema: str = "legacy",
                  telemetry_schema_version: str = "unversioned",
                  capabilities: tuple[str, ...] = (), observed_at: float | None = None) -> None:
        endpoint_id = validate_endpoint_id(endpoint_id)
        hostname = validate_hostname(hostname)
        runtime_version = validate_runtime_version(runtime_version)
        health_state = str(health_state).upper()
        service_state = str(service_state).upper()
        resource_state = str(resource_state or "UNKNOWN").upper()
        if health_state not in self.VALID_HEALTH_STATES: raise ValueError("invalid health_state")
        if service_state not in self.VALID_SERVICE_STATES: raise ValueError("invalid service_state")
        if resource_state not in self.VALID_RESOURCE_STATES: raise ValueError("invalid resource_state")
        telemetry_schema, telemetry_schema_version, capability_value = self._telemetry_contract(
            telemetry_schema, telemetry_schema_version, capabilities
        )
        now = time.time()
        observed = now if observed_at is None else float(observed_at)
        if not math.isfinite(observed):
            raise ValueError("invalid observed_at")
        if last_error is not None:
            if not isinstance(last_error, str) or any(ord(char) < 0x20 for char in last_error):
                raise ValueError("invalid last_error")
            last_error = last_error[:255]
        with self._lock:
            self._conn.execute("""
                INSERT INTO fleet_endpoints(endpoint_id,hostname,download_id,install_state,health_state,service_state,runtime_version,resource_state,first_seen,last_seen,last_error,telemetry_schema,telemetry_schema_version,capabilities_json,last_observed_at)
                VALUES(?,?,NULL,'INSTALLED',?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    health_state=excluded.health_state,
                    service_state=excluded.service_state,
                    runtime_version=excluded.runtime_version,
                    resource_state=excluded.resource_state,
                    last_seen=excluded.last_seen,
                    last_error=excluded.last_error,
                    telemetry_schema=excluded.telemetry_schema,
                    telemetry_schema_version=excluded.telemetry_schema_version,
                    capabilities_json=excluded.capabilities_json,
                    last_observed_at=excluded.last_observed_at
            """, (endpoint_id, hostname, health_state, service_state,
                  runtime_version, resource_state, now, now, last_error or None,
                  telemetry_schema, telemetry_schema_version, capability_value, observed))

    @staticmethod
    def _telemetry_contract(schema: str, version: str, capabilities: tuple[str, ...]) -> tuple[str, str, str]:
        normalized_schema = str(schema or "legacy").strip().lower()
        normalized_version = str(version or "unversioned").strip()
        normalized_capabilities = tuple(sorted(set(str(item) for item in capabilities)))
        if normalized_schema == "legacy":
            if normalized_version != "unversioned" or normalized_capabilities:
                raise ValueError("invalid legacy telemetry contract")
        elif normalized_schema == OCSF_SCHEMA_NAME:
            if normalized_version != OCSF_SCHEMA_VERSION:
                raise ValueError("unsupported telemetry schema version")
            normalized_capabilities = normalize_capabilities(list(normalized_capabilities))
        else:
            raise ValueError("unsupported telemetry schema")
        return normalized_schema, normalized_version, capabilities_json(normalized_capabilities)

    def accept_request_nonce(
        self,
        *,
        nonce: str,
        endpoint_id: str,
        observed_at: float,
        retain_seconds: float = 900.0,
    ) -> bool:
        endpoint_id = validate_endpoint_id(endpoint_id)
        nonce = str(nonce).strip().lower()
        if len(nonce) < 32 or len(nonce) > 64 or any(char not in "0123456789abcdef" for char in nonce):
            raise ValueError("invalid nonce")
        observed_at = float(observed_at)
        if not math.isfinite(observed_at):
            raise ValueError("invalid observed_at")
        cutoff = observed_at - max(600.0, float(retain_seconds))
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM fleet_request_nonces WHERE observed_at < ?", (cutoff,))
                self._conn.execute(
                    "INSERT INTO fleet_request_nonces(nonce,endpoint_id,observed_at) VALUES(?,?,?)",
                    (nonce, endpoint_id, observed_at),
                )
                self._conn.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                self._conn.execute("ROLLBACK")
                return False
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_response_evidence(self, value: dict[str, Any], *, endpoint_id: str,
                                 observed_at: float) -> dict[str, Any]:
        evidence = validate_response_evidence(value, endpoint_id=endpoint_id)
        observed = float(observed_at)
        if not math.isfinite(observed):
            raise ValueError("invalid observed_at")
        received = time.time()
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO fleet_response_evidence(
                    evidence_id,endpoint_id,incident_id,event_id,observed_at,received_at,
                    target_name,target_sha256,detection_types_json,risk_score,risk_level,
                    policy_outcome,policy_reason,verifier_outcome,action_state,verification_outcome,
                    response_latency_ms,execution_latency_ms,detection_to_response_ms,restore_latency_ms,
                    evidence_ref,production_authorization,lab_authorization,authorization_policy_id,receipt_integrity,
                    post_action_verification
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                    evidence["evidence_id"], evidence["endpoint_id"], evidence["incident_id"],
                    evidence["event_id"], observed, received, evidence["target_name"],
                    evidence["target_sha256"], json.dumps(evidence["detection_types"], separators=(",", ":")),
                    evidence["risk_score"], evidence["risk_level"], evidence["policy_outcome"],
                    evidence["policy_reason"], evidence["verifier_outcome"], evidence["action_state"],
                    evidence["verification_outcome"], evidence["response_latency_ms"],
                    evidence["execution_latency_ms"], evidence["detection_to_response_ms"],
                    evidence["restore_latency_ms"], evidence["evidence_ref"],
                    evidence["production_authorization"], evidence["lab_authorization"],
                    evidence.get("authorization_policy_id"), 1, 1,
                    ),
                )
            except sqlite3.IntegrityError:
                # A client can lose the 200 response after the durable commit.
                # Accept only an exact retry of the same evidence identity;
                # conflicting reuse remains fail-closed.
                row = self._conn.execute(
                    "SELECT * FROM fleet_response_evidence WHERE evidence_id=?",
                    (evidence["evidence_id"],),
                ).fetchone()
                if row is None:
                    raise
                existing = dict(row)
                try:
                    existing_detections = json.loads(existing["detection_types_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    raise ValueError("stored response evidence is invalid") from None
                comparable = {
                    "evidence_id": existing["evidence_id"],
                    "endpoint_id": existing["endpoint_id"],
                    "incident_id": existing["incident_id"],
                    "event_id": existing["event_id"],
                    "target_name": existing["target_name"],
                    "target_sha256": existing["target_sha256"],
                    "detection_types": existing_detections,
                    "risk_score": existing["risk_score"],
                    "risk_level": existing["risk_level"],
                    "policy_outcome": existing["policy_outcome"],
                    "policy_reason": existing["policy_reason"],
                    "verifier_outcome": existing["verifier_outcome"],
                    "action_state": existing["action_state"],
                    "verification_outcome": existing["verification_outcome"],
                    "response_latency_ms": existing["response_latency_ms"],
                    "execution_latency_ms": existing["execution_latency_ms"],
                    "detection_to_response_ms": existing["detection_to_response_ms"],
                    "restore_latency_ms": existing["restore_latency_ms"],
                    "evidence_ref": existing["evidence_ref"],
                    "production_authorization": existing["production_authorization"],
                    "lab_authorization": existing["lab_authorization"],
                    "authorization_policy_id": existing["authorization_policy_id"],
                    "receipt_integrity": existing["receipt_integrity"] == 1,
                    "post_action_verification": existing["post_action_verification"] == 1,
                }
                expected = {key: evidence[key] for key in comparable}
                if comparable != expected:
                    raise ValueError("conflicting response evidence identity")
                return dict(
                    evidence,
                    observed_at=float(existing["observed_at"]),
                    received_at=float(existing["received_at"]),
                    idempotent_reuse=True,
                )
        return dict(evidence, observed_at=observed, received_at=received)

    def recent_response_evidence(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 100))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM fleet_response_evidence ORDER BY received_at DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                detections = json.loads(item.pop("detection_types_json"))
            except (TypeError, ValueError, json.JSONDecodeError):
                detections = []
            item["schema"] = "cyberdefender.response-evidence.v1"
            item["detection_types"] = detections if isinstance(detections, list) else []
            item["receipt_integrity"] = item.get("receipt_integrity") == 1
            item["post_action_verification"] = item.get("post_action_verification") == 1
            result.append(item)
        return result

    def summary(self, *, online_after_seconds: float = 90.0) -> dict[str, Any]:
        cutoff = time.time() - max(1.0, float(online_after_seconds))
        with self._lock:
            row = self._conn.execute("""
                SELECT
                  COUNT(*) AS downloads_total,
                  SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) AS downloads_completed,
                  SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) AS downloads_failed
                FROM downloads
            """).fetchone()
            fleet = self._conn.execute("""
                SELECT
                  COUNT(*) AS endpoints_total,
                  SUM(CASE WHEN install_state='INSTALLED' THEN 1 ELSE 0 END) AS installed,
                  SUM(CASE WHEN install_state='PENDING' THEN 1 ELSE 0 END) AS pending,
                  SUM(CASE WHEN install_state='FAILED' THEN 1 ELSE 0 END) AS install_failed,
                  SUM(CASE WHEN install_state='REVOKED' THEN 1 ELSE 0 END) AS revoked,
                  SUM(CASE WHEN install_state='INSTALLED' AND last_seen>=? THEN 1 ELSE 0 END) AS online,
                  SUM(CASE WHEN install_state='INSTALLED' AND last_seen<? THEN 1 ELSE 0 END) AS offline,
                  SUM(CASE WHEN health_state='DEGRADED' THEN 1 ELSE 0 END) AS degraded,
                  SUM(CASE WHEN health_state='CRITICAL' THEN 1 ELSE 0 END) AS critical
                FROM fleet_endpoints
            """, (cutoff, cutoff)).fetchone()
            response = self._conn.execute(
                """
                SELECT COUNT(*) responses_total,
                  SUM(CASE WHEN action_state='QUARANTINED' THEN 1 ELSE 0 END) responses_quarantined,
                  SUM(CASE WHEN action_state='RESTORED' THEN 1 ELSE 0 END) responses_restored,
                  MAX(response_latency_ms) response_latency_ms_max
                FROM fleet_response_evidence
                """
            ).fetchone()
        result = {k: int((row[k] if row else 0) or 0) for k in ("downloads_total","downloads_completed","downloads_failed")}
        result.update({k: int((fleet[k] if fleet else 0) or 0) for k in ("endpoints_total","installed","pending","install_failed","revoked","online","offline","degraded","critical")})
        result.update({
            key: int((response[key] if response else 0) or 0)
            for key in ("responses_total", "responses_quarantined", "responses_restored")
        })
        result["response_latency_ms_max"] = (
            float(response["response_latency_ms_max"])
            if response and response["response_latency_ms_max"] is not None
            else None
        )
        result.update({"status":"HEALTHY", "version":self.VERSION, "authoritative":False, "exact_download_events":True,
                       "people_identity_counted":False, "online_after_seconds":float(online_after_seconds)})
        return result

    def recent_endpoints(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._conn.execute("SELECT * FROM fleet_endpoints ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            try: self._conn.close()
            finally: pass
