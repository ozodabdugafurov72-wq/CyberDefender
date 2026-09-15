# CyberDefender v6 - Canonical Architecture Baseline

**Canonical target:** Security-First Distributed XDR Control System  
**Current product reality:** Security-First Endpoint XDR MVP  
**Rule:** architecture is not implementation evidence.

## 1. Security Constitution

The v6 constitution is code-backed in `agent/architecture/constitution.py` and has 16 stable invariants: zero implicit trust; risk is not authorization; AI is not authority; management is not execution; cloud cannot bypass local safety; fail-closed privileged action; local continuity; bounded capabilities; attributable actions; independent outcome verification; tenant isolation; no self-promotion; signed supply-chain trust; recovery requires re-attestation; evidence preservation; and no direct learning-to-production promotion.

## 2. Six Security Planes

1. **Trust Foundation** - identity, keys, attestation, crypto/replay, update trust.
2. **Endpoint Trusted Computing Base** - native sensors, resource guard, self-protection, local Safety Core.
3. **Trusted Telemetry & Evidence** - canonical event, provenance, durable event/evidence fabric.
4. **XDR Intelligence** - cross-domain adapters, detection, correlation, ProcessGraph/AttackGraph/EvidenceGraph, risk/confidence/uncertainty, advisory AI.
5. **Decision & Response** - policy, pre-action independent verification, blast-radius guard, local safety, scoped capability, privilege-separated executor, post-action verification.
6. **Distributed Control & Recovery** - control plane, recovery, re-attestation, trust restoration, tenant/mesh governance.

## 3. Runtime Plane Separation

- **Data Plane:** sensors, admission, events, spool, detection/correlation evidence.
- **Control Plane:** policy/orchestration/distribution; no direct OS execution.
- **Management Plane:** Owner/Admin/SOC/UI/API; no direct OS execution.
- **Execution Plane:** local Safety Core, capability verification, future privilege-separated executor.

Management-to-execution direct routing is forbidden.

## 4. Canonical Decision / Response Flow

```text
TRUSTED EVIDENCE
  -> RISK
  -> AI RECOMMENDATION (optional/advisory)
  -> POLICY
  -> PRE-ACTION INDEPENDENT VERIFIER
  -> BLAST-RADIUS GUARD
  -> LOCAL SAFETY CORE
  -> SHORT-LIVED, SINGLE-USE, TARGET-BOUND CAPABILITY
  -> PRIVILEGE-SEPARATED EXECUTOR
  -> POST-ACTION INDEPENDENT VERIFIER
  -> EVIDENCE PRESERVATION
  -> RECOVERY
  -> RE-ATTESTATION
  -> TRUST RESTORATION
```

No risk score, AI result, dashboard action, cloud command, or mesh peer may skip these gates.

## 5. Current Reality - after Phase 1

Phase 0 is validated: Security Constitution, Authority Matrix and plane-boundary contracts are code-backed and tested.

Phase 1 establishes a **source-only Device + Workload Identity contract foundation**. It defines canonical local/tenant scope, device/workload binding, generation binding, enrollment binding, workload role-to-plane mapping, provenance, assurance/trust vocabulary, and strict fail-closed parsing. It does not integrate identity into the running Agent or services and it grants no runtime authority.

Current legacy machine identity still comes from `ProgramData/CyberDefender/identity/endpoint_id.txt`; fleet telemetry still uses the bootstrap bearer token path. That remains operational telemetry identity, not enterprise attestation.

The current runtime remains observe-first and dry-run for privileged response. Existing `SafetyAuthorizationGate` issues only `DRY_RUN_ONLY` capability and `ActionGateway` is a no-op dry-run executor.

CyberDefender v6 does **not** claim real privileged execution, persistent v6 identity, enterprise enrollment ownership, device attestation, cryptographic workload authentication, enterprise PKI, distributed HA, production Family Mesh, or complete cross-domain XDR today.

## 6. Phase 1 Identity Invariant

```text
IDENTIFIER != AUTHENTICATED IDENTITY != TRUST != AUTHORIZATION
```

Phase 1 intentionally stops at the contract boundary. `TRUSTED`, `ATTESTED`, and `CRYPTO_AUTHENTICATED` may not be self-declared in the Phase 1 schema. Device/workload identity records carry `authority=NONE`. Valid binding is evidence of consistency only, never permission to execute an OS action.

A workload is bound to the exact device identity **and device generation**, endpoint, scope, tenant and enrollment. This prevents a stale workload record from silently surviving a future device-identity rotation.

## 7. Promotion Rule

A v6 capability can move from PLANNED/PARTIAL to CURRENT/VALIDATED only after repository evidence: code + compile + focused tests + integration + regression + security/adversarial/failure tests as applicable + observability + rollback/recovery evidence.

## 8. Next Engineering Phase

**Phase 2 - Persistent Identity + Enrollment Ownership + Attestation Authority.**

Phase 2 must introduce protected persistent machine/workload identity, explicit enrollment ownership, key separation/rotation, cryptographic workload authentication, attestation evidence verification and a single auditable trust-state transition authority. Real OS execution remains disabled until a separate reviewed Rust-first enforcement milestone.
