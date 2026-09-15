# CyberDefender P0.8.1 — Operations Hardening

P0.8.1 closes the operator-facing inconsistencies observed during the live P0.8 dashboard run without weakening any runtime security boundary.

## Cross-source resource incident coalescing
- CorrelationEngine upgraded to v1.4.
- Host-wide resource signals are normalized into bounded incident families: MEMORY_PRESSURE, CPU_PRESSURE, PROCESS_PRESSURE and DISK_PRESSURE.
- SystemObserver, RuleEngine and EventState evidence for the same local memory-pressure episode now share one incident identity.
- Explicit host/asset/sensor scope is preserved so different endpoints can never merge.
- Unknown/security fallback remains source-isolated.
- Incident payload now exposes `incident_family`, contributing `sources`, and distinct `detection_types`.

## Owner control semantics v3.4
- Visible `ACTIVE · UNLOCKED` wording was removed.
- The UI now distinguishes operator/control-surface availability from privileged execution authority.
- Privileged execution remains `PROTECTED`; execution mode remains `DRY_RUN_ONLY`; real-world effect remains blocked.
- Backward-compatible `unlocked=true` is retained only with explicit `unlocked_semantics=CONTROL_SURFACE_ONLY`.

## Investigation polish
- OwnerReadModel upgraded to v1.1.
- Incident drill-down now shows retained-evidence count, normalized family, contributing sources and signal types.
- Evidence timeline is explicitly chronological and read-only.
- Critical-threat simulation and recovery visualization remain synthetic/plan-only and never grant authorization.

## Deliberately unchanged
- Runtime stays v2.4.
- Crypto/Replay, Durable Spool, EventBus, Policy, Independent Verification and Safety Core remain authoritative.
- SQLite remains a non-authoritative read model.
- Real privileged OS action remains blocked.
- Windows Service / installer work remains the next P0.8.5 milestone.
