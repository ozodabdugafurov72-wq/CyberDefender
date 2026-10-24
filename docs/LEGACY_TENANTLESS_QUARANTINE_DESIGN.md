# Legacy tenantless record quarantine

**Status:** DESIGN ONLY. This document does not authorize or perform a live
spool, ProgramData, service, or CrashGuard operation.

## Scope and trigger

Legacy pending records whose authenticated tenant context is absent are not
replayed as valid events. The runtime records the bounded reason code
`TENANT_IDENTITY_REQUIRED`, increments `tenant_binding_pending`, leaves the
record pending, and sends no ACK. A future quarantine operation must be an
explicit, authenticated product operation; direct JSONL editing and deletion
are prohibited.

## Evidence-preserving record

The operation must read a pending record through the `DurableEventSpool` API
and preserve the exact canonical record bytes before any state transition.
The quarantine vault record must contain only bounded metadata: schema version,
quarantine id, event id when present, reason, failure type, source, UTC
timestamp, raw byte count, SHA-256 of the original bytes, evidence filename,
and `QUARANTINED` status. The raw canonical bytes are stored as protected
evidence and must verify against the recorded digest after writing. No tenant
identity may be invented or inferred from payload data.

## Atomic transition and idempotency

The implementation must use the existing authenticated vault interface
(`quarantine(raw_record=..., reason=..., source=..., event_id=...,
failure_type=...)`) and then persist the spool terminal quarantine state using
its atomic state writer. ACK remains impossible for a quarantined event.
Repeated reconciliation is idempotent by the original raw SHA-256 and event
identity; a vault record already present is treated as the same terminal
record, never duplicated. If the vault write or terminal-state commit cannot
be authenticated and verified, the record remains pending and the operation
fails closed.

## Reconciliation invariant

Before and after the bounded operation, compute sanitized counts and digest
sets from the API: `P_before = P_after + Q_added + A_added + R_explicit`.
For every moved record, the original raw digest must occur exactly once in the
protected vault and the terminal spool state must reference the same event
identity and digest. The operation is invalid if a digest disappears, appears
more than once, an ACK is created for a tenantless record, or any unrelated
pending record changes. The audit result contains counts, reason codes, and
digests only; it must not contain credentials, raw payloads, host identifiers,
or environment values.

## Review, rollback, and limits

The operation must be bounded by a fixed record count, byte budget, and stage
timeout. It must take an authenticated pre-operation snapshot and retain the
protected evidence manifest. Rollback is an authenticated vault restore or
product transaction that re-establishes the prior terminal snapshot and
pending visibility after digest verification; copying or editing spool files
by hand is not rollback. `SecureQuarantineVault.restore` remains denied unless
the separate authorization, policy, and clean-verification gates all pass.

## Required implementation tests

Before any live consideration, add isolated fail-first tests for: exact raw
byte/digest preservation; missing-tenant records receive no ACK; duplicate
reconciliation is idempotent; vault-write failure leaves the record pending;
terminal-state failure leaves the record pending; ACK/quarantine exclusivity;
and the reconciliation equation above across restart. Existing tenant,
replay, persistence-before-ACK, and compaction tests must remain passing.

**Implementation status:** not implemented, not executed, and not applied to
the installed agent.
