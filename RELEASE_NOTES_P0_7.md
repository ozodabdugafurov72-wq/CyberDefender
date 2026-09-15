# CyberDefender P0.7 / P0.7.1 Data Foundation

## P0.7.0
- Added non-authoritative `SQLiteDataRepository` structured read model.
- Added repository abstraction for endpoint, incident and decision queries.
- Preserved Crypto/Replay/Durable/Policy/Verification/Safety as authoritative security boundaries.
- Added bounded incident/decision/evidence retention and WAL settings.
- Added Data Store health and synchronization telemetry to Owner Master Control.

## P0.7.1 Windows lifecycle hotfix
- Fixed Windows `WinError 32` during release-gate temporary-directory cleanup.
- `CyberDefenderRuntime.close()` now deterministically relinquishes repository ownership and is idempotent.
- Runtime bootstrap exceptions automatically invoke cleanup, including fail-closed KeyManager startup rejection after SQLite has opened.
- `SQLiteDataRepository.close()` performs best-effort WAL checkpoint, closes the connection deterministically, and supports context-manager lifecycle.
- Temporary-runtime regression tests now close runtime-owned SQLite handles before deleting state directories.
- Added `test_sqlite_bootstrap_cleanup_v1.py` to prove fail-closed bootstrap still releases the SQLite resource.

Safety posture remains unchanged:
- SQLite is not an authorization source.
- Real privileged OS execution remains blocked / DRY-RUN only.
