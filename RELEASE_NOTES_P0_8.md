# CyberDefender P0.8.0 — Demo Operations

P0.8 turns the local Owner Master Control from a summary-only dashboard into a safe investigation/demo surface while preserving the P0.7.1 security boundaries.

## Demo Operations
- Incident drill-down backed by the local non-authoritative SQLite read model.
- Chronological bounded evidence timeline for retained incident evidence.
- Search and filters for incident ID/correlation key, severity and SECURITY/RESOURCE class.
- Endpoint details with current structured telemetry and recent Risk → Policy → Verification history.
- Owner Master Control schema upgraded to v3.3.
- Local API routes remain loopback-only and carry the existing security headers.

## Safe Critical-Threat Simulation
- Added `CriticalThreatDemoScenario v0.1`.
- Demonstrates a synthetic multi-stage zero-day-style behavior chain.
- Shows critical risk, policy recommendation, independent verification, response simulation and recovery plan.
- No malware payload is created.
- No system command is executed.
- No privileged action is performed.
- Authorization remains `NOT_GRANTED`; response stays `DRY_RUN_ONLY`.

## Read-model safety
- Added `OwnerReadModel v1.0` using SQLite `mode=ro` + `PRAGMA query_only=ON`.
- Dynamic search parameters remain parameterized and bounded.
- Dashboard read connections are deterministically closed to avoid Windows file-lock regressions.
- The dashboard query layer is not an authorization source and cannot replace Crypto/Replay, Durable Spool, Policy, Verification or Safety Core.

## UI
- Added investigation drawer for incident, endpoint and demo-scenario details.
- Added incident SQL history search/filter controls.
- Added evidence timeline and recent decision-history rendering.
- Updated Governance copy to reflect deployed dry-run post-action verification and plan-only recovery foundations.

## Deliberately unchanged
- Runtime privileged OS actions remain blocked.
- PowerShell launch/install workflow remains development-only until P0.8.5 Windows Service / installer foundation.
- Rust native sensor migration remains a later parallel track.
