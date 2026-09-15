# CyberDefender P0.6 Runtime State & Recovery Boundary Hardening

Current release versions:
- CyberDefenderRuntime: 2.3
- EventBus: 2.4
- EventState: 2.2
- Owner Master Control: 3.2

Hardening completed:
1. EventState follows `CYBERDEFENDER_STATE_DIR`.
2. EventLogger is isolated with the runtime state root (or explicit `CYBERDEFENDER_LOG_DIR`).
3. Recovery SecurityEvents cross the canonical crypto/replay/durable/EventBus boundary.
4. Rejected recovery admission restores the exact previous ACTIVE state.
5. Recovery events are dispatched in the same runtime cycle.
6. State/logger persistence failures force runtime `DEGRADED` health.
7. EventBus v2.4 adds bounded MEDIUM/LOW service while preserving bounded capacity and security reserve.
8. Owner Dashboard follows the configured runtime state/log root.
9. Owner governance reflects deployed dry-run post-action verification and plan-only recovery.
10. Legacy monitor no longer embeds a source-code password; password is process-local configuration.
11. Superseded regression tests are separated under `legacy_tests/`.
12. Runtime artifacts, virtualenvs, bytecode, backups and packaged secrets are excluded from the clean release.

Safety posture remains unchanged:
- No real autonomous privileged OS executor is enabled.
- Response path remains DRY-RUN / plan-only where applicable.

P0.6.2 dashboard/runtime-observability hardening:
13. Resource posture uses ResourceGuard pressure state while preserving operational health separately.
14. RuntimeStatePublisher is first-class in the component health matrix.
15. Available-memory telemetry aliases are normalized for live endpoint display.
16. Security-critical incident counts are separated from critical resource-pressure incidents.
17. Owner API evidence reading is single-pass and bounded by tail bytes/lines.
18. Legacy monitor evidence reading is also bounded.
19. Remaining backup/duplicate source debris and superseded owner_console files are removed from the production package.
20. Owner Master Control schema/server version is consistently v3.2.

P0.6.3 24/7 evidence-retention hardening:
21. EventLogger v1.2 rotates the local JSONL security log before unbounded growth and keeps a bounded backup set.
22. Default local audit retention is one 16 MiB active segment plus up to 6 rotated segments; both limits are configurable by environment.
23. CorrelationEngine v1.3 separates cumulative `event_count` from bounded in-memory `evidence_count` (50 retained observations per incident).
24. Incident evidence compaction retains the newest forensic observations without count-based severity escalation.
25. Owner and legacy dashboards read bounded live tails across rotated log segments.
26. Component Matrix header distinguishes operational health from resource-pressure nominal state (`OPERATIONAL` vs `NOMINAL`).
27. Obsolete duplicate resource-stress regression removed from the active production suite; current hysteresis-aware test remains.
