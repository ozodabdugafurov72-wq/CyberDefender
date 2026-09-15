# CyberDefender v6 Phase 1 - Device + Workload Identity Foundation v1.1

Status: VALIDATED CONTRACT FOUNDATION after deployment gates pass  
Runtime authority: NONE  
Privileged execution: NOT ENABLED  
Persistent v6 identity: NOT IMPLEMENTED YET  
Attestation: NOT IMPLEMENTED YET  
Workload cryptographic authentication: NOT IMPLEMENTED YET

## Security rule

`IDENTIFIER != AUTHENTICATED IDENTITY != TRUST != AUTHORIZATION`

An identifier or valid binding never grants permission to execute an OS action.

## Current legacy reality

The current Agent service loads `CYBERDEFENDER_ENDPOINT_ID` from the machine-local `ProgramData/CyberDefender/identity/endpoint_id.txt`. Fleet telemetry uses this ID with a bootstrap bearer token. That mechanism is operational identity/telemetry, not enterprise device authentication or attestation.

Phase 1 deliberately does not pretend otherwise and does not replace that runtime path.

## Device identity contract

A device identity explicitly records schema version, independent device identity ID, existing endpoint ID, local/tenant scope, tenant/enrollment binding when applicable, provenance, assurance, trust state, generation and `authority=NONE`.

Phase 1 rejects self-declared `ATTESTED` and `TRUSTED` state. Attestation IDs are forbidden until an attestation authority exists.

## Workload identity contract

Current workload roles:

- CyberDefenderAgent -> DATA_PLANE / ENDPOINT_TCB
- CyberDefenderControlPlane -> CONTROL_PLANE / DISTRIBUTED_CONTROL_RECOVERY
- CyberDefenderOwnerUI -> MANAGEMENT_PLANE / DISTRIBUTED_CONTROL_RECOVERY
- RustProcessCanary -> DATA_PLANE / ENDPOINT_TCB

Each workload binds to exact device identity ID, **device generation**, endpoint ID, scope, tenant and enrollment. Role-to-plane mapping is fixed by code. A workload cannot self-declare `EXECUTION_PLANE` or `CRYPTO_AUTHENTICATED` in Phase 1.

## Fail-closed rules

Rejected conditions include authority smuggling, role/plane mismatch, stale device-generation binding, cross-device/endpoint/tenant/enrollment substitution, revoked identities, local identity claiming tenant membership, tenant identity without enrollment binding, self-declared attestation/trust/crypto authentication, non-canonical UUIDs, malformed identifiers, coercive generation types, and unknown serialized fields.

## Content digest caveat

The SHA-256 content digest is only deterministic evidence/corruption support. It is **not a signature** and must never be interpreted as authenticity.

## Trust transition caveat

Phase 1 has no trust-state transition authority. No state transition is permitted except a no-op transition. Revocation, promotion, re-attestation and trust restoration require a future auditable authority.

## Next gate

Phase 2: protected persistent identity storage, enrollment ownership, per-purpose key separation, cryptographic workload authentication, attestation evidence verification and explicit trust-transition authority. Real privileged OS execution remains blocked.
