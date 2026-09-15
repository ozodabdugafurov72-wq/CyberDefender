# CyberDefender Polyglot Security Architecture v1

## Goal

CyberDefender must not have a single-language failure mode. Language choice is a security and operational decision, not a branding decision. We use a language only where its runtime, memory-safety, ecosystem, operating-system access, performance or verification model materially improves the component.

## Non-negotiable principles

- Detection != Authorization.
- Probability != Truth.
- Confidence != Risk.
- Risk != Authorization.
- AI recommendation != Authorization.
- AI/LLM is outside the Trusted Computing Base for privileged actions.
- Unknown/unverified never becomes PASS.
- Every privileged future action must be Policy -> Safety -> narrow capability -> deterministic executor -> Independent Verification -> Recovery/Audit.
- A failure of Python, an AI model or a cloud service must not reduce endpoint protection to zero.

## Language ownership target

| Language | Target ownership | Must NOT own alone |
|---|---|---|
| **Rust** | endpoint/native sensors, local security kernel, crypto/replay admission, deterministic probability fusion, durable local safety state, self-protection-sensitive components | UI, exploratory ML research |
| **Go** | NDR edge collectors, concurrent flow aggregation, fleet/control-plane services, service-to-service transport, distributed ingestion | kernel/driver code, final AI decision authority |
| **C#** | Windows ETW/EventLog/WMI/SCM integration, enterprise Windows adapters, Windows management surfaces | cross-platform security kernel, AI authority |
| **C++** | isolated high-performance native integrations, packet/telemetry libraries, vendor SDK/ONNX/native inference bridges where benchmarks justify it | broad business logic or default privileged control plane |
| **C** | very small audited ABI/kernel/firmware/eBPF/vendor boundaries where C is unavoidable | general application logic, large parsers, policy engine |
| **Python** | AI/ML research, calibration, offline analytics, threat-research notebooks, orchestration/tests, prototype correlation | sole always-on enforcement path, sole policy/safety/authorization implementation |
| **TypeScript** | dashboard/UI, visualization, operator workflows | security authority |
| **PowerShell** | Windows deployment, diagnostics, lab orchestration | long-lived privileged runtime logic |

## Migration rule

The current prototype contains important Python control-plane logic. Do **not** rewrite it blindly. Freeze its contracts and golden tests, then migrate security-critical deterministic boundaries incrementally.

### Migration order

1. Keep current Python runtime behavior stable and contract-tested.
2. Build a Rust deterministic `Security Intelligence Core` for probability fusion and safety-critical local scoring with no AI authority.
3. Build Go NDR Edge Collector in OBSERVE mode and feed existing admission/correlation contracts.
4. Build C# Windows telemetry adapter for ETW/EventLog/device/USB metadata where Rust APIs are not the best fit.
5. Add C/C++ only behind narrow audited ABI boundaries when a real dependency/performance/driver requirement exists.
6. Move distributed orchestration from Python only after behavior equivalence and failure-mode tests exist.
7. Python AI service becomes replaceable: if unavailable, Rust/Go deterministic detection, correlation and policy continue.

## Cross-language trust boundary

Every producer must have:

- component identity and version
- tenant identity
- event identity
- timestamp/epoch
- trust level
- payload digest
- provenance/evidence references
- bounded payload size
- replay identity

Cross-language messages do not grant authority. The new Go evidence-envelope package in this milestone enforces `authorization = NOT_GRANTED`.

## Interface strategy

Near term: preserve the existing `SecurityEvent` and admission contracts and use golden conformance fixtures.

Medium term: introduce a versioned language-neutral wire IDL after benchmark and compatibility review. Candidate: Protocol Buffers for Rust/Go/C++/C#/Python services; C remains behind a minimal ABI wrapper. Do not introduce an IDL merely to increase language count.

## Build/verification target

- Rust: `cargo fmt --check`, `cargo check`, `cargo test`, Clippy when available.
- Go: `gofmt`, `go vet`, `go test`.
- C/C++: Clang/MSVC compile, warnings-as-errors for project-owned code, sanitizers in disposable CI/lab where supported.
- C#: `dotnet build`, analyzers, `dotnet test`.
- Python: compile + deterministic unit/adversarial tests.
- PowerShell: AST/parser validation.
- TypeScript: typecheck/lint/test for UI contracts.

Third-party `.venv`, `target`, generated code and vendor code must not pollute project-owned source diagnostics.
