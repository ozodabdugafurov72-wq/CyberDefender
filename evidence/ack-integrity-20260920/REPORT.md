# Consumer success / ACK propagation closure

Date: 2026-09-20. SOURCE ONLY. LIVE DEPLOY: NOT PERFORMED.

## Root cause and reconciliation

The runtime called CorrelationAdapter.handle_event() and then ACKed even when
the adapter had caught an engine exception or rejected incident publication.
The engine also committed duplicate suppression before publication; simply
returning False from the adapter would leave a retry mistaken for completed work.
Engine None previously conflated duplicates, malformed input and internal error.

Git was available for this task. Initial status was clean at
`fb1e563a4ab5b6a1d81e2018a8e270e7f4876015`. Runtime/network changes are committed
history (`18d7df4`, `db38cbb`, `3a52b73`, `f9dd70f`), rather than unexplained
working-tree edits. No reset, checkout, cleanup, commit or deployment was used.
All four pre-existing modified files were backed up before editing; normalized
backup contents match starting HEAD. Exact backup/current hashes are in
`source-manifest.json`. Historical freeze/package evidence was not overwritten.

## Design and changed files

- `agent/correlation/adapter.py`: explicit boolean consumption result; contain
  downstream errors; require strict engine processing and successful enqueue;
  propagate callback ACK failure rather than treating it as success.
- `agent/correlation/engine.py`: optional strict and publish keyword arguments.
  Default ingest(event) behavior remains compatible. Strict errors propagate to
  the adapter's bounded exception handler. Incident serialization/publication
  precede duplicate-state commit, allowing failed publication to retry normally.
- `agent/main.py`: ACK only after adapter returns exactly True; failed/exceptional
  ACK increments runtime component failure and never increments events_acked.
- `test_main_correlation_ownership_v1_5.py`: probe delegates to real engine with
  optional keyword forwarding; every existing ownership assertion retained.
- `tests/test_runtime_consumer_admission_ack.py`: 18 focused fixtures.
- `docs/CURRENT_IMPLEMENTATION_STATUS.md`, `docs/INTEGRATION_GAPS.md`: status and
  remaining boundaries.

DurableEventPipeline, spool, recovery scheduling, EventBus, response authorization,
Policy, Safety and verifier implementation were not modified. No added authority.

## Executed commands and final results

Working directory: `C:\Users\HP\Desktop\CyberDefender`.

```powershell
git status --short
git status --porcelain=v1
git log -3 --oneline -- agent/main.py agent/correlation/adapter.py
git log -5 --oneline
git log -1 --format=fuller -- agent/main.py
git diff HEAD -- agent/main.py agent/correlation/adapter.py agent/core/durable_event_pipeline.py
git show --stat 18d7df4 -- agent/main.py
git log --oneline -- agent/correlation/adapter.py agent/correlation/engine.py agent/core/durable_event_pipeline.py
git rev-parse HEAD
.\.venv\Scripts\python.exe -B tests/test_runtime_consumer_admission_ack.py
.\.venv\Scripts\python.exe -B test_main_correlation_ownership_v1_5.py
.\.venv\Scripts\python.exe -B evidence/ack-integrity-20260920/verify.py
git diff --check
git diff --numstat
git status --short
```

The focused command and verification runner were executed again after diagnosing
fixture failures. Each runner result directory contains exact child command
arrays, working directories, exit codes and durations in `results.json`, plus
individual stdout/stderr logs. It compiles all five changed Python files in memory
using compile(..., 'exec'), avoiding source bytecode writes. The final run is the
timestamp-suffixed `verification-*` directory; `verification/` retains the initial
run, including its failure.

| Final gate | PASS | FAIL | SKIPPED |
|---|---:|---:|---:|
| Established regression scripts | 92 | 0 | 0 |
| Additional ACK-related scripts | 9 | 0 | 0 |
| Total scripts | 101 | 0 | 0 |
| Focused ACK cases (included above) | 18 | 0 | 0 |
| Ownership assertions (included above) | 15 | 0 | 0 |
| Changed Python compile | 5 | 0 | 0 |

git diff --check exited 0. A line-ending conversion warning is informational.

Additional regressions include bridge/correlation, crash/ACK atomicity, failure
resilience, failure/recovery, adversarial admission, duplicate/replay, canonical
runtime traversal and risk integration. The established suite covers bounded
spool/resource behavior, EventBus pressure/shutdown races, recovery, H1D9, response
and NDR fixtures. Existing lifecycle fixtures ran through their owned-child guard;
no installed service actuator was invoked.

## Original fixtures and failure accounting

Successful correlation ACKs once per delivery. Correlation failure and rejected
incident publication do not ACK. All three original fixtures now behave correctly.
Additional cases verify internal engine errors, malformed/unknown results,
publication exceptions, serialization errors, duplicate delivery, callback/ACK
errors, real queue saturation, 100 rejected deliveries without accumulating
incident state or internal retries, and reopening a durable spool after failure.

Initial attempts are not erased or counted as PASS:

1. First focused run: 13 successful cases, one temporary-directory access error
   in the sandbox. Also corrected the fixture's recovery method name to the
   inspected existing replay_pending() API before rerunning outside the sandbox.
2. Expanded queue fixture initially failed because a one-slot queue reserved its
   slot for security traffic. A HIGH-priority filler corrected the fixture; the
   queue implementation was not weakened.
3. Initial 101-script run: 100 PASS, 1 FAIL. The ownership diagnostic used an old
   probe signature. Its probe now delegates to the real engine; all 15 original
   assertions pass. The entire 101-script run was repeated successfully.

## Remaining risks and source status

ACK-integrity source gates: PASS. Production readiness is not claimed.

The transport remains at-least-once. Incident publication means acceptance into
the existing bounded in-memory EventBus, not durable downstream consumption.
Existing duplicate suppression is bounded and in-memory; a crash between
publication and durable ACK has no new cross-process exactly-once guarantee.
This patch adds no retry worker or loop; existing bounded replay determines retry
frequency. A persistently malformed event can remain pending and observable under
the existing bounded spool policy rather than being falsely marked completed.

Direct EventBus admission binding remains an acknowledged separate issue and was
not repaired. Custom adapter engine substitutes must support the strict delivery
arguments; unsupported substitutes fail closed. Legacy direct engine callers keep
the unchanged default interface. No production installation, ProgramData, service,
Registry, Firewall, or production process mutation was performed.

Git summary: four tracked files modified and three source/docs files added;
task evidence resides in the repository's ignored evidence directory. No commit.

LIVE DEPLOY: NOT PERFORMED.
