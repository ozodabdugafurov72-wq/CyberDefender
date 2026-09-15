from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from threading import RLock
from typing import Any

from .repository import DataRepository


class SQLiteDataRepository(DataRepository):
    """CyberDefender SQLite structured read model v1.0.

    Security boundary:
      * NOT an authorization source.
      * NOT a replacement for DurableEventSpool.
      * NOT a replacement for authenticated/replay admission.
      * NOT a replacement for append-oriented JSONL audit evidence.

    SQLite stores queryable endpoint, incident and decision state for the
    local controller/demo and for future repository-backed APIs.
    """

    VERSION = "1.1"
    SCHEMA_VERSION = 1
    DEFAULT_MAX_INCIDENTS = 5000
    DEFAULT_MAX_DECISIONS = 5000
    MAX_EVIDENCE_PER_INCIDENT = 50

    def __init__(
        self,
        db_path: str | Path,
        *,
        max_incidents: int = DEFAULT_MAX_INCIDENTS,
        max_decisions: int = DEFAULT_MAX_DECISIONS,
    ):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(max_incidents, bool) or not isinstance(max_incidents, int) or max_incidents <= 0:
            raise ValueError("max_incidents positive integer bo'lishi kerak")
        if isinstance(max_decisions, bool) or not isinstance(max_decisions, int) or max_decisions <= 0:
            raise ValueError("max_decisions positive integer bo'lishi kerak")
        self.max_incidents = max_incidents
        self.max_decisions = max_decisions

        self._lock = RLock()
        self._sync_count = 0
        self._failed_count = 0
        self._query_count = 0
        self._last_sync_at: float | None = None
        self._last_error: str | None = None
        self._last_result: dict[str, Any] | None = None
        self._closed = False

        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=2.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure_connection()
        self._migrate()

    # ------------------------------------------------------------------
    # Connection / schema
    # ------------------------------------------------------------------

    def _configure_connection(self) -> None:
        cursor = self._conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = FULL")
        cursor.execute("PRAGMA busy_timeout = 2000")
        cursor.execute("PRAGMA trusted_schema = OFF")
        cursor.execute("PRAGMA wal_autocheckpoint = 500")
        cursor.execute("PRAGMA journal_size_limit = 8388608")
        cursor.close()

    def _migrate(self) -> None:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at REAL NOT NULL
                    )
                    """
                )

                current = self._conn.execute(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
                ).fetchone()["version"]

                if int(current) < 1:
                    self._apply_schema_v1()
                    self._conn.execute(
                        "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                        (1, "p0_7_data_foundation", time.time()),
                    )

                final = self._conn.execute(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
                ).fetchone()["version"]
                if int(final) != self.SCHEMA_VERSION:
                    raise RuntimeError(
                        f"Unsupported schema version: {final}; expected {self.SCHEMA_VERSION}"
                    )

                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def _apply_schema_v1(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                endpoint_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                scope TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                runtime_version TEXT,
                mode TEXT,
                runtime_status TEXT,
                resource_state TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                available_memory_mb REAL,
                process_count INTEGER,
                last_cycle INTEGER,
                snapshot_json TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen DESC)",
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                correlation_key TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score REAL NOT NULL,
                event_count INTEGER NOT NULL,
                evidence_count INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                last_seen REAL NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, updated_at DESC)",
            """
            CREATE TABLE IF NOT EXISTS incident_evidence (
                incident_id TEXT NOT NULL,
                evidence_slot INTEGER NOT NULL,
                event_type TEXT,
                severity TEXT,
                source TEXT,
                observed_at REAL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (incident_id, evidence_slot),
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                    ON DELETE CASCADE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_incident_evidence_type ON incident_evidence(event_type, severity)",
            """
            CREATE TABLE IF NOT EXISTS decisions (
                fingerprint TEXT PRIMARY KEY,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                occurrence_count INTEGER NOT NULL,
                cycle INTEGER,
                risk_level TEXT,
                risk_score REAL,
                policy_outcome TEXT,
                recommendation TEXT,
                policy_authorization TEXT,
                verification_outcome TEXT,
                verified INTEGER,
                verification_authorization TEXT,
                payload_json TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_decisions_last_seen ON decisions(last_seen DESC)",
        )
        for statement in statements:
            self._conn.execute(statement)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

    @staticmethod
    def _float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _int(value: Any, default: int = 0) -> int:
        if isinstance(value, bool):
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @classmethod
    def _decision_payload(
        cls,
        *,
        endpoint: dict[str, Any],
        risk: dict[str, Any] | None,
        policy: dict[str, Any] | None,
        verification: dict[str, Any] | None,
    ) -> dict[str, Any]:
        risk = risk if isinstance(risk, dict) else {}
        policy = policy if isinstance(policy, dict) else {}
        verification = verification if isinstance(verification, dict) else {}

        return {
            "endpoint_id": endpoint.get("endpoint_id"),
            "risk_level": risk.get("overall_risk_level", risk.get("risk_level")),
            "risk_score": risk.get("overall_risk_score", risk.get("risk_score")),
            "policy_outcome": policy.get("policy_outcome", policy.get("outcome")),
            "recommendation": policy.get("recommendation"),
            "policy_authorization": policy.get("authorization"),
            "verification_outcome": verification.get(
                "verification_outcome", verification.get("outcome")
            ),
            "verified": bool(verification.get("verified", False)),
            "verification_authorization": verification.get("authorization"),
        }

    @classmethod
    def _decision_fingerprint(cls, payload: dict[str, Any]) -> str:
        canonical = cls._json(payload).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _assert_open(self) -> None:
        if self._closed:
            raise RuntimeError("SQLiteDataRepository is closed")

    # ------------------------------------------------------------------
    # Write model
    # ------------------------------------------------------------------

    def sync_cycle(
        self,
        *,
        endpoint: dict[str, Any],
        incidents: list[dict[str, Any]],
        risk: dict[str, Any] | None,
        policy: dict[str, Any] | None,
        verification: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if not isinstance(endpoint, dict):
            raise TypeError("endpoint dict bo'lishi kerak")
        endpoint_id = str(endpoint.get("endpoint_id") or "").strip()
        hostname = str(endpoint.get("hostname") or "").strip()
        if not endpoint_id or not hostname:
            raise ValueError("endpoint_id va hostname talab qilinadi")
        if not isinstance(incidents, list):
            raise TypeError("incidents list bo'lishi kerak")

        now = time.time()
        valid_incidents = [item for item in incidents if isinstance(item, dict)]
        decision = self._decision_payload(
            endpoint=endpoint,
            risk=risk,
            policy=policy,
            verification=verification,
        )
        fingerprint = self._decision_fingerprint(decision)

        with self._lock:
            self._assert_open()
            try:
                self._conn.execute("BEGIN IMMEDIATE")

                self._upsert_endpoint(endpoint, now)
                evidence_rows = 0
                for incident in valid_incidents:
                    evidence_rows += self._upsert_incident(incident, now)
                self._upsert_decision(
                    fingerprint=fingerprint,
                    payload=decision,
                    cycle=self._int(endpoint.get("last_cycle"), 0),
                    now=now,
                )
                self._enforce_retention()

                self._conn.execute("COMMIT")
                self._sync_count += 1
                self._last_sync_at = now
                self._last_error = None
                self._last_result = {
                    "accepted": True,
                    "endpoint_id": endpoint_id,
                    "incidents": len(valid_incidents),
                    "evidence_rows": evidence_rows,
                    "decision_fingerprint": fingerprint,
                }
                return dict(self._last_result)

            except Exception as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                self._failed_count += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
                raise

    def _upsert_endpoint(self, endpoint: dict[str, Any], now: float) -> None:
        endpoint_id = str(endpoint["endpoint_id"])
        self._conn.execute(
            """
            INSERT INTO endpoints(
                endpoint_id, hostname, scope, first_seen, last_seen,
                runtime_version, mode, runtime_status, resource_state,
                cpu_percent, memory_percent, available_memory_mb,
                process_count, last_cycle, snapshot_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id) DO UPDATE SET
                hostname=excluded.hostname,
                scope=excluded.scope,
                last_seen=excluded.last_seen,
                runtime_version=excluded.runtime_version,
                mode=excluded.mode,
                runtime_status=excluded.runtime_status,
                resource_state=excluded.resource_state,
                cpu_percent=excluded.cpu_percent,
                memory_percent=excluded.memory_percent,
                available_memory_mb=excluded.available_memory_mb,
                process_count=excluded.process_count,
                last_cycle=excluded.last_cycle,
                snapshot_json=excluded.snapshot_json
            """,
            (
                endpoint_id,
                str(endpoint.get("hostname") or endpoint_id),
                str(endpoint.get("scope") or "LOCAL_ENDPOINT"),
                now,
                now,
                endpoint.get("runtime_version"),
                endpoint.get("mode"),
                endpoint.get("runtime_status"),
                endpoint.get("resource_state"),
                endpoint.get("cpu_percent"),
                endpoint.get("memory_percent"),
                endpoint.get("available_memory_mb"),
                endpoint.get("process_count"),
                endpoint.get("last_cycle"),
                self._json(endpoint),
            ),
        )

    def _upsert_incident(self, incident: dict[str, Any], now: float) -> int:
        incident_id = str(incident.get("incident_id") or "").strip()
        if not incident_id:
            return 0

        correlation_key = str(incident.get("correlation_key") or "unknown")
        severity = str(incident.get("severity") or "INFO").upper()
        created_at = self._float(incident.get("created_at"), now)
        updated_at = self._float(incident.get("updated_at"), created_at)
        detections = incident.get("detections")
        if not isinstance(detections, list):
            detections = []
        retained_detections = [item for item in detections if isinstance(item, dict)][
            -self.MAX_EVIDENCE_PER_INCIDENT:
        ]

        self._conn.execute(
            """
            INSERT INTO incidents(
                incident_id, correlation_key, severity, risk_score,
                event_count, evidence_count, created_at, updated_at,
                last_seen, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                correlation_key=excluded.correlation_key,
                severity=excluded.severity,
                risk_score=excluded.risk_score,
                event_count=excluded.event_count,
                evidence_count=excluded.evidence_count,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen,
                payload_json=excluded.payload_json
            """,
            (
                incident_id,
                correlation_key,
                severity,
                self._float(incident.get("risk_score"), 0.0),
                max(0, self._int(incident.get("event_count"), len(detections))),
                len(retained_detections),
                created_at,
                updated_at,
                now,
                self._json(incident),
            ),
        )

        # Evidence is a bounded snapshot supplied by CorrelationEngine.
        # Replacing only this incident's slots keeps SQL consistent with the
        # current forensic window while event_count preserves total occurrence.
        self._conn.execute(
            "DELETE FROM incident_evidence WHERE incident_id = ?",
            (incident_id,),
        )
        count = 0
        for index, detection in enumerate(retained_detections):
            self._conn.execute(
                """
                INSERT INTO incident_evidence(
                    incident_id, evidence_slot, event_type, severity,
                    source, observed_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    index,
                    detection.get("type"),
                    detection.get("severity"),
                    detection.get("source"),
                    self._float(detection.get("timestamp"), updated_at),
                    self._json(detection),
                ),
            )
            count += 1
        return count

    def _upsert_decision(
        self,
        *,
        fingerprint: str,
        payload: dict[str, Any],
        cycle: int,
        now: float,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO decisions(
                fingerprint, first_seen, last_seen, occurrence_count, cycle,
                risk_level, risk_score, policy_outcome, recommendation,
                policy_authorization, verification_outcome, verified,
                verification_authorization, payload_json
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                last_seen=excluded.last_seen,
                occurrence_count=decisions.occurrence_count + 1,
                cycle=excluded.cycle,
                payload_json=excluded.payload_json
            """,
            (
                fingerprint,
                now,
                now,
                cycle,
                payload.get("risk_level"),
                payload.get("risk_score"),
                payload.get("policy_outcome"),
                payload.get("recommendation"),
                payload.get("policy_authorization"),
                payload.get("verification_outcome"),
                1 if payload.get("verified") else 0,
                payload.get("verification_authorization"),
                self._json(payload),
            ),
        )

    def _enforce_retention(self) -> None:
        # Foreign-key cascade removes evidence for pruned incidents.  Logical
        # row bounds keep the local read model finite; SQLite reuses freed
        # pages instead of growing per cycle forever.
        self._conn.execute(
            """
            DELETE FROM incidents
            WHERE incident_id IN (
                SELECT incident_id FROM incidents
                ORDER BY updated_at DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.max_incidents,),
        )
        self._conn.execute(
            """
            DELETE FROM decisions
            WHERE fingerprint IN (
                SELECT fingerprint FROM decisions
                ORDER BY last_seen DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.max_decisions,),
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_payload(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        raw = value.get("payload_json") or value.get("snapshot_json")
        if isinstance(raw, str):
            try:
                value["payload"] = json.loads(raw)
            except json.JSONDecodeError:
                value["payload"] = None
        value.pop("payload_json", None)
        value.pop("snapshot_json", None)
        return value

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._assert_open()
            self._query_count += 1
            row = self._conn.execute(
                "SELECT * FROM endpoints WHERE endpoint_id = ?",
                (str(endpoint_id),),
            ).fetchone()
            return self._decode_payload(row)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._assert_open()
            self._query_count += 1
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (str(incident_id),),
            ).fetchone()
            result = self._decode_payload(row)
            if result is None:
                return None
            evidence_rows = self._conn.execute(
                """
                SELECT evidence_slot, event_type, severity, source,
                       observed_at, payload_json
                FROM incident_evidence
                WHERE incident_id = ?
                ORDER BY evidence_slot ASC
                """,
                (str(incident_id),),
            ).fetchall()
            evidence: list[dict[str, Any]] = []
            for evidence_row in evidence_rows:
                item = dict(evidence_row)
                raw = item.pop("payload_json", None)
                if isinstance(raw, str):
                    try:
                        item["payload"] = json.loads(raw)
                    except json.JSONDecodeError:
                        item["payload"] = None
                evidence.append(item)
            result["evidence"] = evidence
            return result

    def recent_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit integer bo'lishi kerak")
        if limit <= 0:
            return []
        limit = min(limit, 500)
        with self._lock:
            self._assert_open()
            self._query_count += 1
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._decode_payload(row) or {} for row in rows]

    def recent_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit integer bo'lishi kerak")
        if limit <= 0:
            return []
        limit = min(limit, 500)
        with self._lock:
            self._assert_open()
            self._query_count += 1
            rows = self._conn.execute(
                "SELECT * FROM decisions ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._decode_payload(row) or {} for row in rows]

    # ------------------------------------------------------------------
    # Health / lifecycle
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            try:
                self._assert_open()
                row = self._conn.execute("SELECT 1 AS ok").fetchone()
                schema = self._conn.execute(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
                ).fetchone()["version"]
                status = "HEALTHY" if row and row["ok"] == 1 and int(schema) == self.SCHEMA_VERSION else "DEGRADED"
                self._last_error = None if status == "HEALTHY" else self._last_error
            except Exception as exc:
                status = "DEGRADED"
                schema = None
                self._last_error = f"{type(exc).__name__}: {exc}"

            try:
                size = self.db_path.stat().st_size if self.db_path.exists() else 0
            except OSError:
                size = 0

            return {
                "component": "SQLiteDataRepository",
                "status": status,
                "version": self.VERSION,
                "schema_version": schema,
                "authoritative": False,
                "db_path": str(self.db_path),
                "db_bytes": size,
                "max_incidents": self.max_incidents,
                "max_decisions": self.max_decisions,
                "max_evidence_per_incident": self.MAX_EVIDENCE_PER_INCIDENT,
                "sync_count": self._sync_count,
                "failed": self._failed_count,
                "queries": self._query_count,
                "last_sync_at": self._last_sync_at,
                "last_error": self._last_error,
                "last_result": dict(self._last_result) if isinstance(self._last_result, dict) else None,
            }

    def close(self) -> None:
        """Release SQLite resources deterministically.

        Windows keeps an open SQLite database file locked until every
        connection handle is closed.  Tests and short-lived controller
        instances therefore must not rely on garbage collection.  A final
        best-effort WAL checkpoint also keeps the local read-model tidy.
        """
        with self._lock:
            if self._closed:
                return

            conn = self._conn
            try:
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    # Closing the handle is the security/lifecycle invariant;
                    # checkpoint failure must never prevent resource release.
                    pass
            finally:
                conn.close()
                self._closed = True

    def __enter__(self) -> "SQLiteDataRepository":
        with self._lock:
            self._assert_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
