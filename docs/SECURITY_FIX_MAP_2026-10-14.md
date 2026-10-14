# Security fix map — 2026-10-14

| Requirement | Implementation | Automated evidence |
|---|---|---|
| Real-time autonomous quarantine boundary | `agent/quarantine/production_gate.py`, `agent/quarantine/autonomous_pipeline.py`, production mode in `executor.py` | `tests/test_production_quarantine_gate.py` |
| TOCTOU-resistant source identity | `ImmutableFileCapture` in `agent/quarantine/crypto_vault.py` | `tests/test_quarantine_immutable_capture.py`, target mutation test in `test_quarantine_v2.py` |
| Encrypted vault and transactional restore | AES-256-GCM object/evidence envelopes in `crypto_vault.py`, `vault.py`, `v2_vault.py`; single-use restore remains fail-closed | `test_quarantine_v2.py`, `test_quarantine_v2_restore_and_latency.py` |
| SCM CrashGuard recovery | One shared allowlist for runtime/store failure codes | `test_h1d_crash_guard.py`, `test_h1d_crash_store.py` |
| 16,384/16,385 ACK crash window | Explicit restart repair after pending compaction in `durable_spool.py` | `test_durable_spool_crash_window_repair.py` |
| Local-first restart persistence | Durable spool replay and terminal reconciliation | `test_runtime_consumer_admission_ack.py`, `test_trusted_consumer_admission_binding.py` |
| ACL hardening | SID-native verifier plus installer gate | `test_windows_acl_verifier.py` and live read-only ACL audit |
| Token isolation and log leakage | Separate local/remote token paths; AST sensitive-log-sink scan | `test_secret_log_static_analysis.py`, `scan_repository_secrets.py` |
| Three-cycle cloud health admission | `ServiceRunner._observe_runtime_health_gate` | `test_service_runner_production_health_gate.py` |
| Signed heartbeat/evidence replay | Durable nonce rejection with HTTP 409 | `test_fleet_protocol_security.py` |
| Owner evidence attribution | production policy ID in signed response schema, repository schema v4, Owner read model | production gate and fleet protocol tests |

The production path is compiled and tested but remains inert until a caller
constructs it with a pinned public key, an explicit approved root, and a valid
signed policy. This is the intended default-deny deployment state.
