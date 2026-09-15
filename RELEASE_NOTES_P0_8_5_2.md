# CyberDefender P0.8.5.2 — Managed Runtime Service Hotfix

## Fixed from Windows validation
- Agent Windows Service no longer passes `CyberDefenderRuntime` directly as a zero-argument factory.
- Added canonical `build_managed_runtime()` bootstrap using `SafetyCore`, validated config, and critical component health gates.
- Windows service preflight now constructs and closes a real managed runtime before SCM registration.
- `ServiceRunner` marks externally-managed runtime lifecycle as active and uses authoritative `health_snapshot()` telemetry.
- Fleet/distribution telemetry failures are explicitly non-authoritative and cannot terminate the local protection service.
- Added managed-runtime integration and telemetry-resilience regression tests.

## Validation boundary
Linux build validation cannot execute Windows SCM. P0.8.5.2 is only CLOSED after the user's Windows machine reports all three services RUNNING and fresh Agent runtime state is published.
