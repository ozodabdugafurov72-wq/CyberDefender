# CyberDefender Process Sensor Authority Architecture v1

## Status

Repository baseline: CyberDefender P0.8.5.2 + ProcessGraph 1.6 coverage-aware patch.
Runtime version remains 2.4.

This release adds the **Process Sensor Authority Plane** but deliberately does **not** enable Rust as production primary.

Current production authority:

`ProcessSensor (Python) -> ProcessGraph 1.6`

Rust remains a separately bounded native evidence source.

---

## 1. Why an Authority Plane exists

A mature endpoint security agent must never let "which sensor happened to return data" decide the source of truth.
Authority is a security decision.

The authority plane separates five concerns:

1. sensor collection;
2. sensor trust;
3. snapshot coverage/completeness;
4. source-of-truth selection;
5. ProcessGraph lifecycle mutation.

This prevents an accidental configuration change, transient crash, stale comparison, unsigned/replaced native binary, or partial snapshot from silently becoming authoritative.

---

## 2. Stable modes

### PYTHON_ONLY

Python ProcessSensor is authoritative. Rust is not required or executed.

### RUST_SHADOW

Python remains authoritative. Rust is executed only for bounded parity/coverage evidence.
Rust cannot enter ProcessGraph.

### RUST_CANARY

Python remains authoritative. Rust is evaluated against all future authority gates.
The controller may emit a `would_select_sensor=RustProcessSensor` decision, but `may_ingest=false` and no authority switch occurs.

This is the recommended next pre-seed rollout mode.

### RUST_PRIMARY_WITH_FALLBACK

Reserved future mode.
In this release it is protected by a **compiled primary lock**.
Environment variables alone cannot enable Rust authority.

---

## 3. Authority is gated, not configured

Requesting a mode is not equivalent to receiving authority.

A future Rust authority transition requires all of the following:

- reviewed release with compiled-primary support;
- explicit operator unlock;
- pinned Rust binary SHA-256 match;
- bounded Rust process startup/transport;
- exact v0.4 snapshot validation;
- HEALTHY native probe;
- lifecycle-safe ProcessGraph coverage metadata;
- only auto-approved coverage gaps;
- recent Python/Rust alignment lease;
- zero identity disagreement;
- zero parent disagreement;
- exact common ProcessGraph identity match;
- minimum healthy Rust streak;
- confirmed consecutive Python primary failure.

Any failed gate returns no Rust authority.

---

## 4. Supply-chain boundary

The native v0.4 process sensor is pinned to:

`ada90a9ee632b225196348213ef05970828c38ceb0c69eb3776c7e8cb9bedd2d`

The runtime hashes the binary **before execution**.
A mismatch prevents the Rust probe from starting.

Future production evolution should replace the static development pin with signed release metadata rooted in CyberDefender's secure update / attestation trust chain, not with a freely mutable environment-only hash override.

---

## 5. Validated-transport boundary

A Rust dictionary that merely claims:

- `schema=cd.process.v4`
- `sensor=RustProcessSensor`
- `version=0.4.0`

is not authority evidence.

The authority controller requires explicit proof that the snapshot came through the existing `RustProcessShadowProbe`, which already provides:

- `shell=False` process execution;
- bounded timeout;
- bounded stdout;
- non-zero exit rejection;
- malformed JSON rejection;
- duplicate key rejection;
- exact field contract;
- process count bounds;
- PID uniqueness;
- exact FILETIME canonicalization;
- timestamp freshness;
- skip diagnostics validation.

This is defense-in-depth against format spoofing.

---

## 6. Coverage policy

ProcessGraph 1.6 separates positive evidence from negative inference.

### Complete snapshot

A missing RUNNING identity may immediately transition to EXITED.

### Valid partial snapshot

Only explicitly skipped PIDs are protected from absence-based exit.
Unrelated missing PIDs remain valid exit candidates.

### Invalid/ambiguous coverage

Absence-based lifecycle inference fails closed.
The previous graph state is preserved.

### Automatic Rust failover policy

Authority eligibility is intentionally stricter than ProcessGraph acceptance.
For v0.4, automatic promotion currently accepts only the already verified Windows PID 0 limitation:

`SYSTEM_IDLE_UNQUERYABLE / PID 0 / Win32 error 87`

An `OPEN_ACCESS_DENIED` or broader coverage loss can still be useful canary evidence but is not auto-authority eligible.

---

## 7. Alignment lease

Python/Rust parity evidence is not timeless.

A successful comparison establishes a monotonic alignment lease.
The current default maximum age is 30 seconds.

If Python temporarily disappears, a fresh Rust snapshot may reuse the recent alignment lease only while it remains within the bounded age.
A stale lease fails closed.

This avoids trusting a Rust sensor indefinitely based on an old comparison.

---

## 8. Anti-flapping hysteresis

Future transition defaults:

- Python failure threshold: 2 consecutive failures;
- Python recovery threshold: 2 consecutive healthy samples;
- Rust healthy threshold: 2 consecutive healthy evidence cycles.

Therefore:

`1x Python failure -> HOLD_LAST_GRAPH_STATE`

not:

`1x Python failure -> instant source switch`

Likewise a single Python recovery sample cannot immediately steal authority back from a future Rust failover state.

---

## 9. No snapshot blending

The controller selects one authoritative source per decision generation.
It never merges Python and Rust process lists into one authoritative snapshot.

Merging two sequential, non-atomic enumerations could create impossible process states and ambiguous lifecycle ownership.

Cross-sensor data fusion belongs in analytics/evidence layers, not in the authoritative process lifecycle snapshot.

---

## 10. Authority epochs and telemetry

Every decision has a monotonically increasing controller generation and explicit reason code.
Health telemetry exposes:

- requested/effective mode;
- controller state;
- authoritative sensor;
- compiled primary lock;
- operator unlock presence;
- failure/recovery/health streaks;
- alignment age;
- Rust eligibility reason;
- failover/failback counts;
- hold/fail-closed counts;
- canary would-failover count;
- last decision.

This allows the Owner dashboard and future SOC integrations to distinguish:

- operational sensor health;
- authority state;
- coverage quality;
- failover readiness.

---

## 11. Current release safety invariant

Even if an operator sets:

`CYBERDEFENDER_PROCESS_SENSOR_MODE=RUST_PRIMARY_WITH_FALLBACK`

and also provides the operator unlock token, this release still reports:

`RUST_PRIMARY_COMPILED_LOCKED`

Rust cannot become ProcessGraph authority.

This prevents configuration from silently enabling code paths that have not passed the final release gates.

---

## 12. Environment configuration

Primary mode selector:

`CYBERDEFENDER_PROCESS_SENSOR_MODE`

Supported values:

- `PYTHON_ONLY`
- `RUST_SHADOW`
- `RUST_CANARY`
- `RUST_PRIMARY_WITH_FALLBACK`

Backward compatibility:

If the new mode is not explicitly set, legacy
`CYBERDEFENDER_RUST_PROCESS_SHADOW=1`
maps to `RUST_SHADOW`.
Otherwise the safe baseline is `PYTHON_ONLY`.

Optional bounded tuning:

- `CYBERDEFENDER_PROCESS_PYTHON_FAILURE_THRESHOLD`
- `CYBERDEFENDER_PROCESS_PYTHON_RECOVERY_THRESHOLD`
- `CYBERDEFENDER_PROCESS_RUST_HEALTHY_THRESHOLD`
- `CYBERDEFENDER_PROCESS_ALIGNMENT_MAX_AGE_SECONDS`

Values are bounded in runtime code.

---

## 13. Recommended pre-seed endpoint architecture

```text
Windows Service / Agent Supervisor
        |
        +-------------------------------+
        |                               |
        v                               v
Python ProcessSensor              Rust Native Sensors
(authoritative today)             (shadow/canary today)
        |                               |
        +---------------+---------------+
                        |
                        v
           ProcessSensorAuthorityController
                        |
                 one source only
                        |
                        v
                 ProcessGraph 1.6
                        |
                        v
Detection / Correlation / AttackGraph / Risk
                        |
                        v
Policy -> Independent Verification -> SafetyCore
                        |
                        v
              Action Gateway (protected)
```

AI remains outside privileged authority:

`AI -> recommendation/context -> Policy -> Verifier -> SafetyCore`

Never:

`AI -> direct privileged OS action`

---

## 14. Professional expansion roadmap

### Phase A — Authority Foundation (this release)

- explicit modes;
- hash pinning;
- authority controller;
- canary readiness;
- alignment lease;
- anti-flap state machine;
- health telemetry;
- compiled primary lock;
- release regression tests.

### Phase B — Process Enrichment Parity

Rust must gain or safely source the fields needed by downstream detection:

- executable path;
- command line;
- username/SID;
- token/session/integrity information;
- executable signer/trust metadata;
- file identity/hash where justified;
- provenance and confidence per enrichment field.

No primary promotion should reduce detection context silently.

### Phase C — Native Sensor Supervisor

Move Rust collection behind a dedicated local supervisor/IPC contract:

- bounded framed messages;
- sequence number;
- monotonic sensor epoch;
- anti-replay;
- version negotiation;
- watchdog;
- crash-only restart;
- rate/size limits;
- explicit privilege separation.

### Phase D — RUST_CANARY release ring

Enable canary mode on controlled endpoints only.
Collect:

- parity rate;
- coverage reasons;
- failover readiness;
- CPU/RAM overhead;
- sensor latency;
- crash/restart rate;
- graph lifecycle disagreement;
- enrichment disagreement.

No authority switch yet.

### Phase E — Adversarial Primary Candidate

Inject:

- Python crash/timeout;
- Rust crash/timeout;
- stale Rust snapshot;
- hash mismatch;
- binary replacement;
- malformed/oversized IPC;
- PID reuse;
- process churn;
- temporary AccessDenied;
- parent changes;
- partial/complete transitions;
- service restart;
- sleep/resume;
- clock adjustments;
- upgrade/rollback.

### Phase F — Controlled Primary Unlock

Only after all gates pass:

- compile-enable Rust failover in a reviewed release;
- keep explicit operator/release policy;
- deploy to a small canary ring;
- Python remains emergency fallback;
- runtime should report controlled DEGRADED state during failover even if protection continues.

### Phase G — Broader Rust Endpoint Data Plane

Migrate security-critical native collection incrementally:

- process;
- service;
- registry;
- filesystem;
- network/NDR;
- device/driver telemetry;
- local self-protection primitives.

Do not perform a blind full-language rewrite.

### Phase H — Python Intelligence Plane

Keep Python where it provides leverage:

- detection experimentation;
- correlation analytics;
- attack-graph analytics;
- ML/AI;
- cloud orchestration;
- SOC integrations;
- research pipelines.

The boundary is capability-based, not language ideology.

---

## 15. Pre-seed readiness definition

A credible pre-seed build does not need every module to be Rust.
It should demonstrate:

1. a memory-safe native endpoint direction;
2. explicit trust and authority boundaries;
3. safe degradation and rollback;
4. full trusted runtime traversal;
5. no AI-to-privileged-action bypass;
6. signed/pinned native artifacts;
7. bounded resource behavior;
8. reproducible release gates;
9. real Windows canary evidence;
10. a clear path from shadow -> canary -> controlled primary.

That story is stronger than claiming a 100% Rust rewrite before the system contracts are mature.
