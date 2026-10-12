# Pilot Critical Audit

Date: 2026-10-12

## Decision-driving finding

The detection and bounded quarantine path was real, but the sale demonstration was incomplete: recovery was fail-closed and the Railway Owner Dashboard could not receive or display response evidence. A local UI result alone did not prove the cloud product path.

## Implemented vertical path

1. A real detector, correlation engine, risk engine, policy engine, independent verifier, and SafetyCore process one harmless temporary canary.
2. A single-use HMAC capability authorizes one exact lab file under a marker-protected temporary root.
3. The executor quarantines the file, verifies object/evidence/receipt integrity, and persists measured latency.
4. A separate, single-use restore capability restores the same hash without overwriting an existing destination.
5. The endpoint client can send a bounded `cyberdefender.response-evidence.v1` record through the signed, replay-protected fleet channel.
6. Distribution validates the contract again, stores immutable evidence in SQLite, and exposes it only through the private authenticated Owner read endpoint.
7. Railway Owner Cloud validates the upstream response again and renders reason, risk, SHA-256, verification state, and latency using text-only DOM writes.

## Security review result

- Production action authorization remains `NOT_GRANTED`.
- Quarantine and restore remain restricted to a marker-protected lab root and one non-executable file.
- Capabilities are exact-scope, short-lived, integrity protected, and single-use.
- Restore never overwrites an existing destination.
- A pre-effect restore failure preserves the truthful `QUARANTINED` state.
- A post-effect uncertainty requires recovery and is not shown as success.
- Response evidence rejects extra fields, forged authorization, invalid hashes, unverified receipts, invalid state/outcome pairs, and unbounded values.
- Owner Cloud remains authenticated, server-side RBAC protected, CSRF protected for state-changing routes, rate limited, audited, and read-only.

## Audit conclusion

The restricted lab response demonstration is ready for staging. Production autonomous response is outside this pilot gate and remains disabled.
