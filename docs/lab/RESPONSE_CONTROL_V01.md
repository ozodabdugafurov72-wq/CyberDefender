# Response Control Plane v0.1: synthetic contract

The `response_control` package is opt-in and is not imported by the frozen Agent runtime. It adds no HTTP endpoint, EventBus subscriber, sensor, privileged executor or production persistence. Capability status is **UNIT_TESTED**, scoped to the fixture tests identified in the sprint report. Real quarantine and real rollback are not implemented.

## Existing boundaries reused

`FixtureContext` accepts trusted synthetic `SecurityEvent` objects and incident/target inventories supplied by the test assembly. It verifies event integrity, original evidence hashes, incident membership and tenant identity. It is not an external authenticated ingress service. The actual EventBus exposes `publish(event)` and `subscribe(callback)`; CorrelationEngine accepts a normalized detection dictionary through `ingest(event)`. No duplicate bus, correlation engine, or ProcessGraph is introduced. Future production ingress must pass existing authenticated/replay admission and correlation before supplying trusted context.

`prepare(intent, principal)` validates the complete intent and principal, persists PROPOSED, checks complete evidence and protected-target metadata, and invokes the existing RiskEngine with a synthetic AttackGraph, PolicyEngine, IndependentVerifier, SafetyCore, BlastRadiusGuard and SafetyAuthorizationGate. The gate grants only its existing DRY_RUN capability. Risk, policy, safety evaluation and AI advice cannot independently authorize anything.

`simulate(ticket, intent, principal)` rechecks all scope, evidence, target, policy, expiry and safety conditions. It commits consumed=True and SIMULATING before invoking the existing ActionGateway.execute_dry_run. The gateway is a no-op and consumes its own single-use gate capability. The new ticket never enables EXECUTE. Both OBSERVE and SIMULATE produce only an audited no-op analysis; neither changes target state.

The post-action boundary combines the existing PostActionVerifier receipt checks with a fresh, separate fixture inventory observation. A receipt alone is insufficient. Missing/stale/wrong-target/conflicting observations cannot become VERIFIED. RecoveryPlanner must explicitly report no recovery required, no execution support, no effect and NOT_GRANTED. Any ambiguous execution/verification/recovery outcome is terminal REVIEW_REQUIRED / DEGRADED_SAFE; no rollback is automatically attempted.

## Identity, lifecycle and auditing

ActionIntent strictly binds intent/incident/tenant/target/type/action, requester and source, evidence, risk snapshot, policy version/recovery contract, timestamps, mode and idempotency key. It is not an authorization object. Principal is a trusted assembly input, not authentication middleware. AI Principal requests are denied even with may_simulate=True. `advisory()` returns only UNTRUSTED_ADVISORY_INPUT, NOT_GRANTED and a digest; an authorized operator must independently create any subsequent intent through normal admission.

The ticket contains a random nonce, intent/tenant/session, mode, short expiry and a digest binding the complete intent, evidence, target, policy and safety decisions. Its HMAC uses a purpose-separated prefix. It is useless without the ledger's pending record and the existing gate capability held only in that process. Copying or renaming a ticket does not change its identity. Cancellation is one-way and cannot resume or renew it.

Success states: PROPOSED → ADMITTED → POLICY_EVALUATED → SAFETY_EVALUATED → AUTHORIZED_FOR_SIMULATION → SIMULATING → SIMULATED → VERIFYING → VERIFIED. Terminal states also include DENIED, EXPIRED, CANCELLED, FAILED, REVIEW_REQUIRED and DEGRADED_SAFE. Explicit transition validation rejects skipping or repeating a step. Process replacement converts every nonterminal record to REVIEW_REQUIRED and never reissues a capability. There is no resume actuator.

The ledger is deliberately separate from SQLiteDataRepository: that existing class explicitly forbids using its read model as an authorization/replay source. This synthetic journal uses SQLite atomic transactions, FULL synchronization, DELETE journaling and HMAC-authenticated canonical state. Consumption precedes the no-op gateway; interruption preserves consumption and requires review. Missing state, a corrupt marker/MAC, stale in-process revision, invalid history or ambiguous write denies progress. Only explicit trusted create=True provisioning creates an empty journal; ordinary reload never recreates missing state.

Audit records include validated intent identity and evidence hashes, risk/policy/safety decisions, timestamps, history, plan and independent verification digests. Raw evidence payloads, private/guard keys and gate/ticket MACs are not persisted. Rejected inputs are represented by a digest and validated principal identity, fixed reason and terminal status. The bounded rejection ring retains the most recent 64 with a monotonic aggregate count; old rejected-input detail is deliberately evicted, while admitted-intent tombstones remain. A storage failure is reported as degraded, never successful durable auditing.

## Bounds and limitations

| Collection/resource | Bound | Expiry/retention/restart |
|---|---|---|
| Intent records and tombstones | 64 per journal | No automatic eviction/reset; full journal denies new work |
| Intent input | 16 KiB, 8 unique evidence refs | Maximum 300-second lifetime |
| Tickets / in-memory gate capabilities | At most 64 | At most 30 seconds and intent expiry; new process invalidates all |
| Per-intent history | 20 entries | Durable; terminal state cannot transition |
| Rejected request history | 64 entries | Oldest detail evicted, count retained; 1,000,000 attempts stops admission |
| Events / incidents / targets | 128 / 64 / 64 | Trusted fixture lifetime; byte caps 16 / 16 / 4 KiB per entry |
| Journal payload / SQLite pages | 1 MiB / 1024 pages | Default SQLite page size gives about 4 MiB; persistent full journal fails closed |
| Verification / recovery | One attempt | No retries; interruption requires review |

The fixture clock catches backward time relative to persisted progress, while forward movement expires tickets. The existing gate also enforces its own actual-time TTL. No administrator-resistant clock or external monotonic anchor is claimed. HMAC requires a trusted caller-supplied 32-byte key; production key provisioning, ACLs, authenticated client admission and external anti-rollback anchoring are not implemented. An administrator able to replace an entire old journal and its trusted environment is outside this local integrity boundary. Session invalidation prevents old-ticket reuse after reload, but this is not a claim of global exactly-once execution under arbitrary whole-directory rollback.

Protected-target decisions use trusted classification metadata, not process names alone. Critical OS, security, boot/recovery, identity infrastructure and protected business targets are denied. Real system classification and independent OS verification adapters remain absent. A synthetic target observation cannot establish that a real process/file/network is contained.

No production runtime/security file is changed. Python ProcessSensor remains the sole ProcessGraph authority; Rust canary remains non-authoritative and primary compile-locked. This sprint does not deploy anything.
