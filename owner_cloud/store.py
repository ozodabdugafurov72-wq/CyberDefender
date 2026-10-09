from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any


class OwnerStore:
    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=3.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute("PRAGMA trusted_schema=OFF")
        return conn

    def _migrate(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS owner_schema (
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS owner_sessions (
                    token_hash TEXT PRIMARY KEY,
                    csrf_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_owner_sessions_expiry
                    ON owner_sessions(expires_at, revoked_at);
                CREATE TABLE IF NOT EXISTS owner_login_failures (
                    subject_hash TEXT NOT NULL,
                    client_hash TEXT NOT NULL,
                    window_started REAL NOT NULL,
                    failure_count INTEGER NOT NULL,
                    locked_until REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY(subject_hash, client_hash)
                );
                CREATE TABLE IF NOT EXISTS owner_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at REAL NOT NULL,
                    request_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    client_hash TEXT NOT NULL,
                    subject TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_owner_audit_time
                    ON owner_audit(occurred_at DESC);
                COMMIT;
                """
            )
            row = conn.execute("SELECT COALESCE(MAX(version), 0) AS version FROM owner_schema").fetchone()
            if int(row["version"] or 0) < self.SCHEMA_VERSION:
                conn.execute(
                    "INSERT INTO owner_schema(version, applied_at) VALUES(?, ?)",
                    (self.SCHEMA_VERSION, time.time()),
                )
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def rotate_session_csrf(self, token_hash: str, csrf_hash: str) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE owner_sessions SET csrf_hash=? WHERE token_hash=? AND revoked_at IS NULL",
                (csrf_hash, token_hash),
            )
            return cursor.rowcount == 1
        finally:
            conn.close()

    def health(self) -> bool:
        conn = self._connect()
        try:
            conn.execute("SELECT 1").fetchone()
            return True
        finally:
            conn.close()

    def create_session(
        self,
        *,
        token_hash: str,
        csrf_hash: str,
        username: str,
        role: str,
        now: float,
        expires_at: float,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO owner_sessions(
                    token_hash, csrf_hash, username, role, created_at,
                    last_seen, expires_at, revoked_at
                ) VALUES(?,?,?,?,?,?,?,NULL)
                """,
                (token_hash, csrf_hash, username, role, now, now, expires_at),
            )
        finally:
            conn.close()

    def get_session(self, token_hash: str, *, now: float, idle_seconds: float) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM owner_sessions WHERE token_hash=? AND revoked_at IS NULL",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) <= now or float(row["last_seen"]) + idle_seconds <= now:
                conn.execute(
                    "UPDATE owner_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                    (now, token_hash),
                )
                return None
            if now - float(row["last_seen"]) >= 60:
                conn.execute("UPDATE owner_sessions SET last_seen=? WHERE token_hash=?", (now, token_hash))
            return dict(row)
        finally:
            conn.close()

    def revoke_session(self, token_hash: str, *, now: float) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE owner_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (now, token_hash),
            )
            return cursor.rowcount == 1
        finally:
            conn.close()

    def login_allowed(self, subject_hash: str, client_hash: str, *, now: float) -> tuple[bool, float]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT locked_until FROM owner_login_failures WHERE subject_hash=? AND client_hash=?",
                (subject_hash, client_hash),
            ).fetchone()
            locked_until = float(row["locked_until"] or 0) if row else 0.0
            return locked_until <= now, locked_until
        finally:
            conn.close()

    def record_login_failure(
        self,
        subject_hash: str,
        client_hash: str,
        *,
        now: float,
        window_seconds: float,
        failure_limit: int,
        lock_seconds: float,
    ) -> float:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM owner_login_failures WHERE subject_hash=? AND client_hash=?",
                (subject_hash, client_hash),
            ).fetchone()
            if row is None or float(row["window_started"]) + window_seconds <= now:
                failures, window_started = 1, now
            else:
                failures, window_started = int(row["failure_count"]) + 1, float(row["window_started"])
            locked_until = now + lock_seconds if failures >= failure_limit else 0.0
            conn.execute(
                """
                INSERT INTO owner_login_failures(
                    subject_hash, client_hash, window_started, failure_count, locked_until
                ) VALUES(?,?,?,?,?)
                ON CONFLICT(subject_hash, client_hash) DO UPDATE SET
                    window_started=excluded.window_started,
                    failure_count=excluded.failure_count,
                    locked_until=excluded.locked_until
                """,
                (subject_hash, client_hash, window_started, failures, locked_until),
            )
            conn.execute("COMMIT")
            return locked_until
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def clear_login_failures(self, subject_hash: str, client_hash: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM owner_login_failures WHERE subject_hash=? AND client_hash=?",
                (subject_hash, client_hash),
            )
        finally:
            conn.close()

    def audit(
        self,
        *,
        now: float,
        request_id: str,
        actor: str,
        role: str,
        action: str,
        outcome: str,
        client_hash: str,
        subject: str = "",
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO owner_audit(
                    occurred_at, request_id, actor, role, action,
                    outcome, client_hash, subject
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    now,
                    request_id[:64],
                    actor[:64],
                    role[:16],
                    action[:64],
                    outcome[:32],
                    client_hash[:64],
                    subject[:128],
                ),
            )
        finally:
            conn.close()

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT occurred_at, request_id, actor, role, action,
                       outcome, client_hash, subject
                FROM owner_audit ORDER BY occurred_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()
