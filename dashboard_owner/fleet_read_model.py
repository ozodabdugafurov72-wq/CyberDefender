from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote


class FleetReadModel:
    VERSION = "1.0"
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()

    def _connect(self):
        if not self.db_path.is_file():
            raise FileNotFoundError(str(self.db_path))
        uri = f"file:{quote(self.db_path.as_posix(), safe='/:')}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=1000")
        return conn

    def snapshot(self, *, limit: int = 100, online_after_seconds: float = 90.0) -> dict[str, Any]:
        cutoff = time.time() - max(1.0, float(online_after_seconds))
        conn = self._connect()
        try:
            d = conn.execute("""SELECT COUNT(*) downloads_total,
                SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) downloads_completed,
                SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) downloads_failed FROM downloads""").fetchone()
            f = conn.execute("""SELECT COUNT(*) endpoints_total,
                SUM(CASE WHEN install_state='INSTALLED' THEN 1 ELSE 0 END) installed,
                SUM(CASE WHEN install_state='PENDING' THEN 1 ELSE 0 END) pending,
                SUM(CASE WHEN install_state='FAILED' THEN 1 ELSE 0 END) install_failed,
                SUM(CASE WHEN install_state='REVOKED' THEN 1 ELSE 0 END) revoked,
                SUM(CASE WHEN install_state='INSTALLED' AND last_seen>=? THEN 1 ELSE 0 END) online,
                SUM(CASE WHEN install_state='INSTALLED' AND last_seen<? THEN 1 ELSE 0 END) offline,
                SUM(CASE WHEN health_state='DEGRADED' THEN 1 ELSE 0 END) degraded,
                SUM(CASE WHEN health_state='CRITICAL' THEN 1 ELSE 0 END) critical FROM fleet_endpoints""", (cutoff, cutoff)).fetchone()
            rows = conn.execute("SELECT endpoint_id,hostname,install_state,health_state,service_state,runtime_version,resource_state,first_seen,last_seen,last_error FROM fleet_endpoints ORDER BY last_seen DESC LIMIT ?", (max(1,min(int(limit),500)),)).fetchall()
        finally:
            conn.close()
        summary = {}
        for key in ("downloads_total","downloads_completed","downloads_failed"):
            summary[key] = int((d[key] if d else 0) or 0)
        for key in ("endpoints_total","installed","pending","install_failed","revoked","online","offline","degraded","critical"):
            summary[key] = int((f[key] if f else 0) or 0)
        return {"status":"HEALTHY","version":self.VERSION,"read_only":True,"authoritative":False,
                "exact_download_events":True,"people_identity_counted":False,"online_after_seconds":online_after_seconds,
                "summary":summary,"endpoints":[dict(r) for r in rows]}
