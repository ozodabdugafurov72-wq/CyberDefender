# H1D source lifecycle containment

This implementation is for disposable-machine integration before any production rollout. No source test configures the installed services. Policy numbers below are explicit staging defaults, not calibrated production SLOs.

## Boundaries

Python ProcessSensor remains the only graph authority. The compiled Rust-primary lock, Policy, SafetyCore, independent verifier, and dry-run action authorization are unchanged. Child termination is deterministic ownership cleanup of a process this supervisor created, not a response to AI output or a risk score. The service installer is the only caller that changes SCM recovery policy. Neither dashboards nor runtime policy decisions can clear crash accounting or grant repair rights.

## Native child

All launch paths enter one admission gate, with one initial attempt and an explicit debit before every retry. Failed creation and HELLO attempts consume capacity. Exhaustion latches for that supervisor instance; repeated calls do not launch another generation. A still-running sensor can replenish retry capacity only through validated snapshots spanning the configured stability window. Cumulative failures, retries, and launch attempts remain observable. Exhausted instances are not automatically reconstructed by the sampling loop.

The Windows native wrapper uses `PROC_THREAD_ATTRIBUTE_JOB_LIST` at process creation and a noninheritable kill-on-close Job Object. There is no uncontained or create-then-assign fallback. Only explicit pipe handles are inherited. Retained process handles verify exit before replacement. A failed kill/wait or unfinished reader retains ownership and blocks replacement. Reader stop events and queues are generation-local. The canary and runtime retain failed-cleanup ownership rather than silently discarding it.

The child environment contains only SYSTEMROOT/WINDIR obtained through Windows and the generated IPC nonce/supervisor PID. A read handle denying file write/delete remains open while the expected SHA-256 is verified and the process is created. The pin is checked on every admitted launch. A deployment pin is not signed authority evidence and cannot promote Rust.

## Service state machine

Each service owns one exclusive crash-store lock for its host lifetime. The host opens protected accounting and records its boot/session before application imports. Every application attempt is committed before initialization begins. An interrupted active attempt is recorded on the next attach, including across boots. Graceful stops preserve attempts and historical failures.

| State | Behavior |
|---|---|
| READY | Eligible for a debited initial/retry attempt after the required cooldown |
| STARTING | Attempt is persisted; useful healthy work has not yet established stability |
| RUNNING | Repeated validated healthy work established stability; current retry capacity replenished, history retained |
| LATCHED | Application initialization held; responsive host waits for eligible bounded probe or administrator repair |
| PROBE | One recovery attempt, with optional Rust collection disabled |
| UNAVAILABLE | Integrity/store/cleanup prerequisites cannot be established; no replacement attempt; explicit repair required |

Staging policy: three attempts since validated stability, 60 awake seconds between failed attempts, at least three successful health checks spanning 60 awake seconds for stability, and one automatic recovery probe after cooldown. This is a conservative budget since validated stability, not failure expiration based on a wall-clock sliding window. Failed probes do not replenish themselves. There is no second restart scheduler.

After a failure, a successful Agent recovery attempt uses the existing fail-closed managed factory with optional Rust sensors suppressed. It never bypasses key/spool/admission/pipeline health prerequisites. A healthy clean restart after validated stability can restore optional sensors. Failed telemetry-client construction is isolated from core construction. SafetyCore instances remain sticky; there is no new clear-safe-mode API.

A minimal SCM host is not endpoint protection. It reports UNAVAILABLE/LATCHED through structured diagnostics and fixed EventLog messages; SCM RUNNING alone does not mean healthy protection. Existing dashboard freshness handling remains necessary when no new runtime snapshot is published.

## Protected persistence

The installer source provisions `%ProgramData%/CyberDefenderCrashGuard`, separate from normal state/log directories. It rejects reparse ancestry and adoption of a non-SYSTEM/non-Administrators owner, then sets an explicit protected DACL for SYSTEM/Administrators only. Runtime validation rejects untrusted owners, null/unexpected ACLs, reparse paths, missing provisioning markers, and missing or malformed keys/state. Runtime startup never provisions an empty replacement for a damaged store.

Records have exact bounded schemas, service binding, finite counters, up to 32 structured failure records, and a 32 KiB file bound. A purpose-specific random key authenticates records and commit anchors. Two alternating slots plus an authenticated revision/digest anchor form the commit protocol: flush the candidate slot, atomically replace it, then flush/replace the anchor. A crash before the anchor commits preserves the previous transaction; risky initialization happens only after the debit transaction returns successfully. Incomplete pending writes are never trusted. In-process high-water revision checks and the anchor reject stale slot replay. Exclusive OS locks and per-object thread locks prevent competing writers.

The protection boundary excludes a fully privileged administrator. An administrator capable of restoring the complete protected directory, key and anchor together can roll back it; this implementation does not claim TPM-backed anti-rollback. Disk faults and denied writes result in unavailable accounting rather than reset counters. Recovery of a missing/corrupt store requires administrator forensic repair/restoration; there is no automatic re-key/reset command.

`python -m agent.service_crash_store status --service NAME` reads sanitized state while acquiring the exclusive lock; a running host therefore prevents this offline command. Live diagnostics are available in the protected per-service log files. After stopping the affected service and repairing the cause, an authenticated administrator can run `python -m agent.service_crash_store authorize-probe --service NAME`, then explicitly start the service. The command grants one further probe, records a repair count, and accounts for any interrupted active attempt. It does not erase cumulative history, previous attempts, or SafetyCore denial. Access requires the protected directory rights and an unowned service lock.

## Progress watchdog

A separate observer tracks completed validated work, not PID existence. Windows QueryUnbiasedInterruptTime excludes verified kernel sleep/hibernation intervals and wall-clock corrections. The 60-awake-second deadline is a staging value. Healthy Agent cycles earn progress; optional canary errors do not override independent core health. HTTP services verify actual responses with one outstanding self-probe at most. Failed probes earn no progress and do not accumulate request handlers; probing resumes only after the prior handler finishes.

The observer reports DEGRADED/STALLED/UNAVAILABLE and never kills a Python thread or the core process. Arbitrarily hung Python core work cannot be safely recovered automatically by this in-process design. Automatic recovery from such hangs requires a separately reviewed worker-process boundary and finite ownership/restart protocol; it is not implemented here. No availability claim is made for a core stuck forever or unavailable security prerequisites. A blocked OS storage call also remains an integration failure case, not a reason to bypass persistence or terminate arbitrary threads.

## SCM and diagnostics

Installer source sets three restarts at 5/15/60 seconds followed by SC_ACTION_NONE, with the existing 86400-second reset period and noncrash-failure flag. The helper uses typed Win32 APIs and reads the configuration back. The C# definition and expected action array are compiled/tested without invoking Configure on this machine. Actual SCM application, exhaustion, and administrator repair must be exercised on a disposable Windows machine. The existing full installer retains app.previous but is not transactional rollback; deployment must have a separately rehearsed rollback procedure.

Diagnostics emit only allowlisted events and exception categories, never raw exception messages, tracebacks, command lines, tokens, keys, or environment values. Each service has its own protected JSONL stream with OS-locked rotation (2 MiB plus two backups). Record size is at most 512 bytes. Logging failure is nonfatal, and rotation failure does not authorize unbounded append. Fixed EventLog state messages provide a secondary signal when the protected store cannot open. Collection scripts no longer print legacy raw bootstrap logs or full SCM event messages.

## Required disposable-machine validation

Provisioning ACLs under elevated installer and LocalSystem tokens; all three host startup/stop/shutdown paths; finite SCM terminal behavior and repair; early import failures; repeated genuine process crashes; Job Object behavior under installed/nested job policies; reboot/sleep/wake; disk faults and power loss during commits; prolonged CPU/memory/handle/diagnostic retention measurements; genuine repaired-service recovery; continued Python-only authority and offline protection where prerequisites hold. Source tests exercise deterministic fault models, local kernel child containment, local HTTP stalls and existing security regressions; they do not substitute for these machine tests.

References: [atomic job-list process attribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute), [awake interrupt time](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime), [SCM repeats the final action](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw).
