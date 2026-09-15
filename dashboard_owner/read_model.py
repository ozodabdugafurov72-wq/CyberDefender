from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote


class OwnerReadModel:
    """Read-only SQLite query surface for Owner Master Control.

    Security boundary:
      * opens the CyberDefender structured database in SQLite mode=ro
      * never migrates or writes schema/data
      * never participates in Policy/Safety authorization
      * every dynamic filter remains parameterized and bounded
    """

    VERSION = "1.1"
    MAX_LIMIT = 200
    MAX_QUERY_CHARS = 96
    VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    VALID_CLASSES = {"SECURITY", "RESOURCE"}

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()

    def _connect(self) -> sqlite3.Connection:
        if not self.db_path.is_file():
            raise FileNotFoundError(str(self.db_path))
        encoded_path = quote(self.db_path.as_posix(), safe="/:")
        uri = f"file:{encoded_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.execute("PRAGMA busy_timeout = 1000")
        return conn

    @staticmethod
    def _decode_json(raw: Any) -> Any:
        if not isinstance(raw, str):
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _bounded_limit(cls, value: Any, default: int = 50) -> int:
        try:
            limit = int(value)
        except (TypeError, ValueError):
            limit = default
        return max(1, min(limit, cls.MAX_LIMIT))

    @classmethod
    def _bounded_query(cls, value: Any) -> str:
        query = str(value or "").strip()
        return query[: cls.MAX_QUERY_CHARS]

    @staticmethod
    def _resource_text(value: Any) -> bool:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str).lower()
        except (TypeError, ValueError):
            text = str(value).lower()
        normalized = text.replace("-", "_")
        words = (
            "memory", "high_memory_usage", "low_available_memory",
            "available_memory", "memory_percent", "cpu", "cpu_percent",
            "disk", "disk_percent", "resource", "process_count",
            "systemobserver", "system_observer",
        )
        return any(word in normalized for word in words)

    def health_check(self) -> dict[str, Any]:
        try:
            conn = self._connect()
            try:
                schema_row = conn.execute(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
                ).fetchone()
                conn.execute("SELECT 1").fetchone()
            finally:
                conn.close()
            return {
                "component": "OwnerReadModel",
                "version": self.VERSION,
                "status": "HEALTHY",
                "authoritative": False,
                "read_only": True,
                "schema_version": int(schema_row["version"]) if schema_row else 0,
            }
        except (OSError, sqlite3.Error, ValueError) as exc:
            return {
                "component": "OwnerReadModel",
                "version": self.VERSION,
                "status": "UNAVAILABLE",
                "authoritative": False,
                "read_only": True,
                "schema_version": None,
                "error": type(exc).__name__,
            }

    def search_incidents(
        self,
        *,
        query: str = "",
        severity: str = "",
        incident_class: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = self._bounded_query(query)
        severity = str(severity or "").upper().strip()
        incident_class = str(incident_class or "").upper().strip()
        limit = self._bounded_limit(limit)

        if severity and severity not in self.VALID_SEVERITIES:
            severity = ""
        if incident_class and incident_class not in self.VALID_CLASSES:
            incident_class = ""

        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if query:
            clauses.append(
                "(incident_id LIKE ? ESCAPE '\\' OR correlation_key LIKE ? ESCAPE '\\' OR payload_json LIKE ? ESCAPE '\\')"
            )
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            params.extend((like, like, like))

        sql = (
            "SELECT incident_id, correlation_key, severity, risk_score, event_count, "
            "evidence_count, created_at, updated_at, last_seen, payload_json "
            "FROM incidents"
        )
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        query_limit = self.MAX_LIMIT if incident_class else limit
        params.append(query_limit)

        conn = self._connect()
        try:
            rows = conn.execute(sql, tuple(params)).fetchall()
        finally:
            conn.close()

        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            payload = self._decode_json(item.pop("payload_json", None))
            item["payload"] = payload if isinstance(payload, dict) else {}
            item["incident_class"] = "RESOURCE" if self._resource_text(item["payload"] or item) else "SECURITY"
            if incident_class and item["incident_class"] != incident_class:
                continue
            result.append(item)
        return result[:limit]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        incident_id = str(incident_id or "").strip()[:128]
        if not incident_id:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT incident_id, correlation_key, severity, risk_score,
                       event_count, evidence_count, created_at, updated_at,
                       last_seen, payload_json
                FROM incidents WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
            if row is None:
                return None
            evidence_rows = conn.execute(
                """
                SELECT evidence_slot, event_type, severity, source,
                       observed_at, payload_json
                FROM incident_evidence
                WHERE incident_id = ?
                ORDER BY observed_at ASC, evidence_slot ASC
                """,
                (incident_id,),
            ).fetchall()
        finally:
            conn.close()

        result = dict(row)
        payload = self._decode_json(result.pop("payload_json", None))
        result["payload"] = payload if isinstance(payload, dict) else {}
        result["incident_class"] = "RESOURCE" if self._resource_text(result["payload"] or result) else "SECURITY"
        timeline: list[dict[str, Any]] = []
        for evidence_row in evidence_rows:
            evidence = dict(evidence_row)
            evidence_payload = self._decode_json(evidence.pop("payload_json", None))
            evidence["payload"] = evidence_payload if isinstance(evidence_payload, dict) else {}
            timeline.append(evidence)
        result["evidence_timeline"] = timeline

        # Compact investigation facets for the drawer.  They are derived from
        # the retained read-only evidence and never influence authorization.
        sources: list[str] = []
        signal_types: list[str] = []
        for evidence in timeline:
            payload = evidence.get("payload") if isinstance(evidence.get("payload"), dict) else {}
            source = str(evidence.get("source") or payload.get("source") or "").strip()
            event_type = str(evidence.get("event_type") or payload.get("type") or "").strip()
            if source and source not in sources:
                sources.append(source)
            if event_type and event_type not in signal_types:
                signal_types.append(event_type)

        payload_sources = result["payload"].get("sources") if isinstance(result["payload"], dict) else None
        if isinstance(payload_sources, list):
            for source in payload_sources[:32]:
                source = str(source).strip()
                if source and source not in sources:
                    sources.append(source)

        payload_types = result["payload"].get("detection_types") if isinstance(result["payload"], dict) else None
        if isinstance(payload_types, list):
            for event_type in payload_types[:32]:
                event_type = str(event_type).strip()
                if event_type and event_type not in signal_types:
                    signal_types.append(event_type)

        result["sources"] = sources[:32]
        result["signal_types"] = signal_types[:32]
        result["incident_family"] = (
            result["payload"].get("incident_family")
            if isinstance(result["payload"], dict)
            else None
        )
        return result

    def endpoint_details(self, endpoint_id: str | None = None, *, decision_limit: int = 20) -> dict[str, Any] | None:
        decision_limit = self._bounded_limit(decision_limit, 20)
        conn = self._connect()
        try:
            if endpoint_id:
                row = conn.execute(
                    "SELECT * FROM endpoints WHERE endpoint_id = ?",
                    (str(endpoint_id)[:128],),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM endpoints ORDER BY last_seen DESC LIMIT 1"
                ).fetchone()
            if row is None:
                return None
            decision_rows = conn.execute(
                """
                SELECT fingerprint, first_seen, last_seen, occurrence_count,
                       cycle, risk_level, risk_score, policy_outcome,
                       recommendation, policy_authorization,
                       verification_outcome, verified,
                       verification_authorization, payload_json
                FROM decisions ORDER BY last_seen DESC LIMIT ?
                """,
                (decision_limit,),
            ).fetchall()
        finally:
            conn.close()

        endpoint = dict(row)
        raw_snapshot = endpoint.pop("snapshot_json", None)
        endpoint["snapshot"] = self._decode_json(raw_snapshot) or {}
        decisions: list[dict[str, Any]] = []
        for decision_row in decision_rows:
            item = dict(decision_row)
            raw = item.pop("payload_json", None)
            item["payload"] = self._decode_json(raw) or {}
            item["verified"] = bool(item.get("verified"))
            decisions.append(item)
        endpoint["recent_decisions"] = decisions
        return endpoint
