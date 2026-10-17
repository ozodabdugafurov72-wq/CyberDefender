# CrashGuard v2 staged specification

Status: design plus M1 pure core. The v2 feature flag defaults to off and no
service imports this package. Store, authorization, migration and service-host
integration described below remain staged work until their batches pass.

## Lifecycle model

Health is separate from lifecycle. Lifecycle values are `INIT`, `READY`,
`STARTING`, `RUNNING`, `STOPPING`, `STOPPED`, `LATCHED`, `SAFE_HOLD`,
`RECOVERY_AUTHORIZED`, and `RECOVERY_PROBING`. Health values are `UNKNOWN`,
`UNHEALTHY`, `DEGRADED`, `HEALTHY`, and `STABLE`.

The executable transition table is `agent/crashguard_v2/state_machine.py`.
Undefined state/event pairs fail with `CG2_TRANSITION_UNDEFINED`.

| Current state | Event | Next state | Required effects |
|---|---|---|---|
| INIT | INITIALIZE | READY | persist initial state; publish status |
| READY or STOPPED | START_REQUESTED | STARTING | reserve attempt; publish status |
| STARTING | START_CONFIRMED | RUNNING | bind runtime identity; publish status |
| READY, STARTING, RUNNING, LATCHED, SAFE_HOLD, RECOVERY_AUTHORIZED, or RECOVERY_PROBING | STOP_REQUESTED | STOPPING | request stop; retain any recovery debit |
| STOPPING | STOP_CONFIRMED | STOPPED | persist stop; publish status |
| STARTING or RUNNING | ATTEMPT_FAILED | LATCHED | record failure; publish status; host exits non-zero |
| STARTING or RUNNING | RUNTIME_EXITED | LATCHED | record fatal runtime exit; publish status; host exits non-zero |
| READY, STARTING, RUNNING, or STOPPED | LATCH_REQUIRED | LATCHED | persist latch; publish status |
| LATCHED or SAFE_HOLD | BOOT_OBSERVED | SAFE_HOLD | no budget debit; no privileged runtime; signal truthfully latched |
| READY or STOPPED | BOOT_OBSERVED | READY | no budget debit; publish status |
| LATCHED or SAFE_HOLD | RECOVERY_AUTHORIZED | RECOVERY_AUTHORIZED | verify authorization; publish status |
| RECOVERY_AUTHORIZED | RECOVERY_STARTED | RECOVERY_PROBING | atomically reserve budget and nonce; publish status |
| RECOVERY_PROBING | RECOVERY_VERIFIED | RUNNING | preserve history; begin health verification; publish status |
| RECOVERY_PROBING | RECOVERY_FAILED or ATTEMPT_FAILED | LATCHED | record failure; preserve debit; publish status |
| STARTING, RUNNING, or RECOVERY_PROBING | HEALTH_OBSERVED | unchanged | evaluate health sample |

`STABLE` cannot be set by a lifecycle transition. The pure health verifier
requires three fresh, strictly sequenced, progressing, invariant-clean samples
whose accepted timestamps are each at least 60 seconds apart. Stability is
earned only by a further progressing sample at least 15 minutes after the third
accepted sample. A stale, replayed, non-progressing or failed-invariant sample
cannot earn stability and clears accumulated healthy evidence.

## Store v2 schema (B2 contract)

The single service-host writer owns a versioned authenticated record. Bounded
fields include schema version, service, lifecycle, health, revision,
generation, boot identifier, monotonic and wall-clock observations, permanent
cumulative failures, attempts since stable, recovery budget, consumed nonces,
bounded failure history and last verified runtime identity. Two authenticated
slots commit through an authenticated anchor outside the state directory.
Every successful commit publishes a separate bounded authenticated read-only
status snapshot, so inspection never requires the writer lock.

Commits use write-through replacement and flushed handles. Slot, anchor,
snapshot, path, ACL, reparse, size, schema, numeric and monotonic-revision
checks fail closed. Sharing violations receive bounded backoff. The existing
protected software key is reused. Recovery-key rotation and revocation are
explicit transactions; no implicit key regeneration is allowed.

Within one boot, the monotonic observation cannot decrease. Across a changed
boot identifier, revision and generation remain monotonic while the monotonic
clock may reset. A wall-clock regression greater than five minutes is marked
`ROLLBACK_SUSPECTED`; smaller clock corrections earn no recovery credit by
themselves.

B2 implements this store in `agent/crashguard_v2/store.py`, still unwired.
Its writer lock is separate from the authenticated status snapshot. The
snapshot exposes only service, revision, generation, lifecycle, health,
failure code and update time. It excludes boot identifiers, nonces and runtime
identity.

## Failure-code contract (B2 contract)

Guard, store, diagnostics and installer consume one closed vocabulary. It
includes store authentication, owner lock, schema, rollback suspicion, unsafe
spool terminal state, runtime import/fatal/stale-heartbeat, bootstrap failure,
recovery budget, authorization and verification failures. A bounded sanitized
diagnostic record remains writable independently of a rejected store commit.

## Recovery protocol (B3 contract)

Recovery authorization is an Ed25519 detached signature by a distinct offline
operator recovery key over canonical JSON containing `action`, `service`,
`release_sha256`, `state_generation`, `state_revision`, `nonce`, `issued_at`,
and `expires_at`. The protected provisioned public key is not secret.

Verification binds freshness, service, exact release and current record. Budget
reservation and nonce consumption occur in one atomic commit before probing.
Inspection and PLAN debit zero budget. Reboot and clean stop never replenish
budget. Cumulative failure history never resets; only verified `STABLE` resets
`attempts_since_stable`. A failed probe preserves its debit and evidence.

B3 implements canonical request parsing, Ed25519 verification, current
revision/generation and release binding, expiry checks, nonce replay rejection,
zero-debit planning, and atomic recovery reservation in
`agent/crashguard_v2/recovery.py`. The implementation remains unwired. A
32-byte Ed25519 public key is selected from protected provisioned state by a
bounded key identifier. Rotation must be authorized by the currently active
recovery key; revocation is monotonic and a revoked key cannot authorize its
own restoration. Recovery and release-signing keys are separate roles.

## Boot and health semantics

A boot start of a latched Agent moves to `SAFE_HOLD`, consumes no recovery
budget, starts no privileged runtime, and publishes truthful latched status.
SCM state alone never proves health. Runtime heartbeats must advance sequence,
match process identity, pass critical-component checks and follow an independent
spool-validator PASS. A verifier inside the managed runtime is supporting
evidence and is not independent verification.

The contents of a minimal protective degraded mode remain an operator design
decision and are not implemented by this specification.

## v1 to v2 migration contract (B4 contract)

| v1 state | v2 import | Counter treatment |
|---|---|---|
| READY | READY with UNKNOWN health | preserve revision, generation and all counters |
| STARTING | LATCHED | archive active attempt; add no recovery budget |
| RUNNING | READY with UNKNOWN health | preserve history; require fresh v2 health proof |
| LATCHED | LATCHED | preserve history and exhausted probe state; no budget gain |
| PROBE | LATCHED | archive in-flight probe as consumed; no budget gain |
| UNAVAILABLE | SAFE_HOLD | preserve raw authenticated evidence; no privileged runtime |

Migration is offline, one-shot, signed through the recovery protocol and runs
only while the Agent is stopped. Fixtures are generated by v1 code. The staged
v2 record is authenticated and reread before commit; the v1 files remain
read-only. V2 records refuse downgrade. Interruption at every step must produce
either the authenticated old state or an explicitly incomplete migration,
never a clean state or additional budget.

