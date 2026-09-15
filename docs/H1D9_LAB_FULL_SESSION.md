# H1D9 two-hour session plan

Use the university runbook and machine-readable test_catalog.json. This is a time budget, not a promise that all variants fit. Preserve honest INCOMPLETE results when time expires.

0–20 min: staff identity/isolation/dependency/C0 checks, clean install and C1 baseline/ACL review.

20–35 min: C1/C2 checkpoints, canary baseline, source FixtureTests, short resource observation and baseline evidence.

35–65 min: controlled service crash/replacement checks and one bounded SCM storm branch. Each complete storm requires at least 5+15+60 seconds of recovery delays plus 180 seconds of terminal observation. Stop after any unsafe invariant.

65–90 min: preserve results, staff C2 restore, explicit verified ResumeCheckpoint; another selected service or Rust containment branch. Do not reset lifetime debits or manually bypass tickets.

90–105 min: selected protected-store variant or an explicitly approved reboot. Each destructive store variant needs its own restore/verification branch. Sleep only where supported and staff-approved. Hard power loss is not part of the default two-hour session.

105–120 min: operator receipt review, Report, preserve evidence externally, final C0 restore and rollback validation. Leave time for cleanup even when earlier tests fail.

Full three-service storms, seven store variants, latched/interrupted reboot variants, sleep and power-loss coverage may require additional scheduled sessions. Do not mark mixed cases PASS based on one supporting observation. At most 12 verified C2 continuations and 64 total fault debits are available in one ledger. If the bound is reached, stop and report; a separately authorized later run must retain the failed/incomplete prior report.
