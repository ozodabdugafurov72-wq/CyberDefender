# CyberDefender production response Go / No-Go gate

Date: 2026-10-14  
Scope: Endpoint Agent autonomous quarantine and signed XDR evidence  
Current decision: **NO-GO for broad production activation; GO for staged pilot validation**

The code now contains a production authorization boundary, encrypted quarantine
storage, immutable source capture, a three-cycle health admission gate, durable
spool crash-window repair, SID-native ACL verification, and signed-ingest replay
tests. Broad production activation remains blocked until the installed Agent and
Owner evidence path pass the host and staging checks below.

## Mandatory code gates

- [x] Default deny: production mode requires an offline Ed25519-signed policy.
- [x] Policy is bounded by ID, issue/expiry times, approved roots, risk,
  detection count, confidence, and executable authorization.
- [x] A production response requires risk >= policy threshold, at least two
  distinct detections, independent verifier `VERIFIED`, and policy outcome
  `AUTHORIZED_AUTONOMOUS_QUARANTINE`.
- [x] `HEALTHY/RUNNING` fleet state requires three consecutive completed cycles
  with `running=true`, `component_failures=0`, and resource state `NORMAL`.
- [x] Quarantine objects and evidence use AES-256-GCM; SHA-256 links plaintext
  identity while ciphertext SHA-256 and the AEAD tag detect disk tampering.
- [x] Windows source capture holds a no-write/no-delete-share handle and deletes
  the opened object by handle. POSIX uses descriptor identity before unlink.
- [x] Restore uses exclusive create, exact SHA-256 verification, a one-time
  capability, a durable receipt, and refuses overwrite or replay.
- [x] CrashGuard PROBE/LATCHED state accepts every allowlisted service exit code
  in its authenticated store; history remains bounded and is never reset by a
  repair probe.
- [x] Durable spool repairs the exact 16,385 tombstone crash window only after
  pending evidence is compacted; larger states remain fail-closed.
- [x] ACL verification consumes Windows SID objects directly, rejects broad
  write/delete/owner/DACL control, rejects unsupported ACE types, and requires a
  privileged owner.
- [x] Local and remote fleet tokens remain separate files. Static analysis fails
  on token/secret/password/private-key variables passed to print or log sinks.
- [x] Exact signed request replay returns HTTP 409 for registration, heartbeat,
  and response-evidence endpoints.
- [x] Production response evidence carries `authorization_policy_id` and the
  consumed production capability state into the Owner read model.

## Staged host gates before production authorization

- [ ] Install the pinned candidate Agent and obtain a committed release receipt.
- [ ] Confirm Windows SCM reports `Running`, `Automatic`, `LocalSystem`, expected
  binary path, and unchanged recovery actions.
- [ ] Confirm ControlPlane and OwnerUI PIDs/configuration remain unchanged.
- [ ] Capture three fresh runtime snapshots with advancing cycle count,
  `component_failures=0`, `running=true`, resource `NORMAL`, crypto/replay/spool
  `HEALTHY`, and no unbounded deferred growth.
- [ ] Simulate network loss and restart; prove every pre-outage pending event is
  recovered or terminally ACKed without duplication or loss.
- [ ] Run the fixed-root harmless lab canary: detect, quarantine, independently
  verify, publish signed evidence, restore once, and reject restore replay.
- [ ] Confirm encrypted object/evidence bytes do not contain fixture plaintext;
  tampering must fail AEAD/SHA verification.
- [ ] Confirm Owner protected API shows the matching endpoint, incident, policy
  ID, SHA-256, latency, `QUARANTINED_VERIFIED`, and later `RESTORED_VERIFIED`.
- [ ] Run the SID-native ACL verifier on product, release, state, vault, receipt,
  identity, and both secret directories.
- [ ] Run repository secret and sensitive-log-sink scan with zero findings.

## Limited production pilot gates

- [ ] Use a newly generated offline signing key. Keep the private key outside
  endpoints; deploy only the public key to the Agent.
- [ ] Sign a short-lived policy for one pilot endpoint and explicit user-writable
  roots. Do not authorize Windows, Program Files, ProgramData, boot, recovery,
  or CyberDefender paths.
- [ ] Use harmless executable fixtures only. Prove low confidence, one-signal,
  stale policy, bad signature, out-of-root, reparse, hash mismatch, unhealthy
  runtime, and capability replay all produce zero filesystem effect.
- [ ] Prove an authorized fixture is removed by exact file identity, stored only
  as authenticated ciphertext, and visible through signed Owner evidence.
- [ ] Complete a controlled restore and rollback drill.
- [ ] Complete a 24-hour soak with no Agent crash loop, no spool loss, no ACL
  regression, bounded CPU/RAM/disk, and stable signed heartbeats.

Broad production activation is **GO** only when every unchecked item has linked
evidence and an explicit change record. A failed or missing item keeps the
decision **NO-GO** and does not weaken local observation or signed telemetry.
