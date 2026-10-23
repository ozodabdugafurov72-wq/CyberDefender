# CyberDefender audited release evidence index

This branch is based on `origin/main` at `a33676c7e89e37c3d75918e7878186b023584897` and contains only reviewable source/tests. It has not been pushed.

## Included

- `agent/service_lifecycle.py`: bounded `stop_on_attempt_failure` behavior. A failed guarded attempt returns failure to the SCM host instead of leaving a dead runtime under a Running service state.
- `dashboard_owner/windows_service.py` and `control_plane/windows_service.py`: companion hosts opt into fail-closed termination and emit closed STOPPED/fatal behavior.
- `agent/diagnostics/trusted_event_path_probe.py` plus its test: isolated synthetic delivery/bridge/correlation/persistence/ACK markers with sanitized exception class and no live imports.
- `tests/test_ownerui_fatal_lifecycle_v1.py`: fail-first lifecycle regression; PASS after the change.

## Verification

- Focused lifecycle/diagnostic tests: `6/6 PASS`.
- Python compilation and `git diff --check`: PASS.
- Existing `tests.test_h1d_service_integration`: `5/6 PASS`; one unrelated fixture fails because `agent.windows_service` has no `servicemanager` attribute in the origin/main test environment. This is UNVERIFIED for release.
- Runtime/installer ZIPs are not rebuilt or asserted for this branch: `SOURCE_ZIP=UNVERIFIED`, `RUNTIME_ZIP=UNVERIFIED`, `INSTALLER=UNVERIFIED`. Existing invariant references from the prior audit were runtime `7368ccfc91f605b3f3aa96de804a950d1797699021a5236b66a607e643878bb2` and installer `6917043b433cc4eac884300ee301f230d54d436c4b4f500fcb9864c2b6a49d86`; they are not bound to this branch.

## Live boundary

No service, ProgramData, spool, CrashGuard, cleanup, PLAN/APPLY, probe, deployment, credential, or Railway operation was performed. Live OwnerUI refusal, Agent runtime health, SQLite backup/restore, MFA, PostgreSQL durability, HA/monitoring, tenant isolation, EICAR, and staging heartbeat remain outside this source-only branch and are not claimed PASS.

Excluded from the branch: protected runtime artifacts, credentials, raw logs, ProgramData evidence, private evidence, Downloads artifacts, temporary patch files, and reports containing local machine paths or unverified live claims.

## Release decision

`UNIVERSITY_GO=NO-GO`; `SAFE_TO_PUSH=NO` until the unrelated existing test failure is resolved or explicitly accepted and a fresh independent review, deterministic source ZIP/provenance, read-only PLAN, and live health evidence are complete.
