# Process Sensor Authority Foundation v1 — Release Notes

Adds an explicit process-sensor authority plane on top of the verified
P0.8.5.2 + ProcessGraph 1.6 baseline.

## Added

- `agent/sensors/process_authority.py`
- explicit process sensor modes
- safe invalid-mode fallback
- backward-compatible legacy shadow flag mapping
- pinned Rust v0.4 SHA-256 verification before execution
- validated-transport requirement for Rust authority evidence
- alignment lease with bounded age
- native health streak
- Python failure/recovery hysteresis
- canary would-failover telemetry
- compiled Rust-primary release lock
- process authority health surface
- two permanent release-gate tests
- one live Windows canary test

## Unchanged security boundaries

- Runtime version remains 2.4.
- Python `ProcessSensor` remains ProcessGraph authority.
- Rust remains non-authoritative.
- ProcessGraph remains v1.6.
- No Rust event enters EventBus directly.
- No authority decision grants OS action permission.
- Policy, Independent Verification and SafetyCore boundaries are unchanged.

## Release-gate result in build environment

37/37 tests PASS.
