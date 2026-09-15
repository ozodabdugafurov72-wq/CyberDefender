# CyberDefender Rust Canary 24/7 + Admin/Owner Observability Architecture v1

## Release intent

This release places the validated Rust ProcessSensor v0.5.1 inside the managed
24/7 endpoint lifecycle as a **non-authoritative canary**.  Python
`ProcessSensor` remains the only source permitted to mutate `ProcessGraph`.
The release also adds a loopback-only technical Admin Operations surface and
expands Owner Master Control with native sensor authority/reliability telemetry.

## Authority invariant

```text
Python ProcessSensor --------------------------> ProcessGraph 1.6
        |                                             |
        | authoritative                               v
        |                                   Detection / Correlation / Risk
        |
        +--> after successful graph ingest --> Rust v0.5.1 Canary
                                                |
                                                +-- persistent bounded IPC
                                                +-- parity/enrichment evidence
                                                +-- health/restart telemetry
                                                X-- NO ProcessGraph edge
                                                X-- NO EventBus edge
                                                X-- NO Policy/Safety/Action edge
```

`RUST_CANARY` is a monitoring mode, not an authority grant.  The existing
compiled Rust-primary lock remains closed.

## Persistent native supervisor

The Rust child uses `cd.sensor.ipc.v1` with:

- one direct native child process;
- 256-bit per-launch nonce binding;
- supervisor PID + direct child PID binding;
- monotonically increasing request sequence;
- sensor epoch binding per child generation;
- bounded 12 MiB response frames;
- strict JSON/duplicate-key rejection;
- bounded request timeout;
- bounded crash-only restart budget;
- new epoch required after restart.

The Rust binary is SHA-256 pinned by machine-local deployment configuration
before the supervisor may start.  This pin protects canary deployment
integrity; it is intentionally **not** sufficient to unlock future primary
authority, which requires a separately reviewed signed/attested release path.

## Enrichment parity

Canary comparisons cover authoritative identity/lifecycle compatibility and
security context:

- PID + creation time identity;
- parent PID relationship;
- canonical process name semantics;
- executable path;
- username;
- command line;
- native-only SID coverage;
- native-only session ID coverage;
- native-only integrity-level coverage.

Known Windows pseudo-process aliases are narrowly classified and remain
observable. Unknown executable/name disagreements stay review-required.

## Machine runtime configuration

`C:\ProgramData\CyberDefender\config\process_sensor_runtime.json`

The file is strict-schema, duplicate-key rejecting, size bounded, and contains:

- mode (`RUST_CANARY` for this deployment);
- exact Rust executable path;
- exact Rust SHA-256;
- sample cadence;
- IPC timeout;
- restart budget/window;
- minimum enrichment coverage threshold.

Malformed configuration fails closed to Python authority.

## Dashboard surfaces

### Owner Master Control

`http://127.0.0.1:8775/owner`

Adds a Process Sensor Plane section showing:

- current authority mode/source;
- ProcessGraph health;
- primary compiled lock;
- Rust canary health/readiness;
- persistent IPC state/restarts;
- identity/parent/name parity;
- executable/user/cmdline parity;
- SID/session/integrity coverage;
- explicit no-bypass safety invariant.

Owner schema remains `cyberdefender.owner-master-control.v3.5` for API
compatibility while the UI revision becomes `owner-v3.6-sensor-plane`.

### Admin Operations

`http://127.0.0.1:8775/admin`

A new read-only technical monitoring surface served by the existing
`CyberDefenderOwnerUI` Windows Service.  No fourth service or PowerShell-hosted
web server is introduced.  `/admin/api/state` is observational and has no OS
action endpoint.

## Failure semantics

Rust canary failure:

- increments canary-specific failure telemetry;
- does not increment core component failures;
- does not mark ProcessGraph failed;
- does not switch authority;
- does not stop the 24/7 Python protection loop.

Core Python/ProcessGraph failure continues to use existing fail-safe runtime
semantics. Canary data is never substituted implicitly.

## Deployment discipline

The release transaction:

1. verifies exact canonical + installed baselines;
2. backs up source, installed runtime, config and native artifact;
3. patches canonical source first;
4. runs the full release gate;
5. compiles/tests Rust v0.5.1 in an isolated build target;
6. runs a real Windows canary/crash-recovery candidate gate;
7. stops only Agent + OwnerUI; ControlPlane remains online;
8. deploys exact hashed files, native EXE and pinned config;
9. preflights Agent/OwnerUI;
10. restarts services and verifies Owner/Admin/API canary invariants;
11. automatically rolls back on any failed gate.

## Current non-goals

- Rust is not primary.
- No Rust process snapshot is admitted to ProcessGraph.
- No native canary event is published to EventBus.
- No dashboard path directly executes privileged OS actions.
- Signer/hash enrichment remains a future bounded Tier-2 worker rather than a
  synchronous process-enumeration hot-path dependency.
