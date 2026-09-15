# CyberDefender Polyglot Language & Data Strategy

Status: accepted target architecture after P0.7.

## Security principle
CyberDefender does not choose one programming language for the whole system.
Each trust boundary uses the language/runtime that best fits its safety,
performance, portability and operational requirements. A language migration
must never silently change an authorization or fail-safe contract.

## Current / target allocation

### Python — current orchestration and analysis plane
Keep for:
- runtime orchestration
- Detection / Rule Engine
- Correlation / Attack Graph / Risk
- Policy Engine
- Independent Verification
- response simulation / safety orchestration
- rapid adversarial testing

Python is not planned as the final privileged endpoint execution plane.

### Rust — next native endpoint/security plane
Preferred for new memory-safe native components:
- Process/File/Network sensor core
- self-protection helpers
- signed native telemetry producer
- secure update verification helpers
- future bounded privileged enforcement components after separate approval gates

Migration rule: native Rust sensors must feed the existing canonical trusted
boundary; they may not publish directly into correlation or privileged action.

### Go — future backend/control-plane services
Preferred for:
- concurrent cloud ingest
- agent-to-backend transport gateways
- fleet/service APIs
- multi-tenant control-plane services

### C# — Windows-specific integration only when it materially helps
Candidate areas:
- ETW / Windows Event Log / Service Control integration
- Windows enterprise API adapters
- native management surfaces where .NET is the safest practical interface

### C / C++ — constrained interoperability/driver use
Use only where required by kernel/driver/legacy SDK boundaries. New security
logic should prefer Rust where technically viable. Any C/C++ boundary requires
strict fuzzing, bounds checks and a minimal API surface.

## Data strategy

### SQLite — P0.7 local structured read model
Use for:
- local endpoint inventory/state
- incident history and bounded evidence snapshots
- Risk/Policy/Verification decision history
- local demo/query operations

SQLite is explicitly non-authoritative. It does not replace:
- Crypto/Replay admission
- DurableEventSpool
- append-oriented JSONL audit evidence
- Policy/Independent Verification/Safety authorization boundaries

### PostgreSQL — future enterprise system of record
Planned for:
- tenants
- endpoints
- policies
- incidents/cases
- users/roles/governance metadata

### ClickHouse / TimescaleDB — future high-volume telemetry
Evaluate only when real scale measurements justify it. It should not become an
authorization source.

## Migration order
1. P0.7: SQLite repository abstraction and structured read model.
2. P0.8: demo operations (incident drill-down, evidence timeline, endpoint details).
3. Parallel native track: Rust ProcessSensor proof-of-contract, initially optional.
4. P0.9: controlled synthetic demo scenario engine.
5. Demo RC1: stable installer + one-click demo + scripted scenario.
6. P1.x: controlled response foundation only after Safety/Policy/Verification gates are independently proven.
