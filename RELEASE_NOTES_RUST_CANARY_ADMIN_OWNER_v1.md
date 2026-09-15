# CyberDefender Rust Canary 24/7 + Admin/Owner v1

- Adds persistent Rust ProcessSensor v0.5.1 as `RUST_CANARY` inside the managed
  24/7 Agent lifecycle.
- Python ProcessSensor remains the sole ProcessGraph authority.
- Adds strict machine-local process-sensor runtime configuration and binary pin.
- Adds persistent bounded IPC supervisor with nonce/PID/sequence/epoch binding
  and bounded crash recovery.
- Adds enrichment parity telemetry and native SID/session/integrity coverage.
- Adds `/admin` and `/admin/api/state` to the existing loopback OwnerUI service.
- Expands `/owner` with Process Sensor Plane observability.
- Keeps compiled Rust-primary lock closed and preserves all Policy/Safety/Action
  boundaries.
- Adds new release regressions for config, wire contract, enrichment semantics,
  supervisor adversarial behavior, canary failure isolation, and dashboards.
