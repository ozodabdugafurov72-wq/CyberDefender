# PSI v0.2 implementation notes

CyberDefender PSI v0.2 is additive beside the frozen v0.1/v0.1.1 implementation. It does not overwrite the existing runtime/security core.

The v0.2 focus is adversarial probabilistic intelligence:

1. fixed multi-window evidence fusion;
2. low-and-slow persistence across long windows;
3. dependency-group discounting;
4. source-concentration discounting;
5. trusted caller-owned source caps so evidence producers cannot self-promote reliability;
6. explicit counter-evidence;
7. `UNKNOWN` and `ABSTAIN` semantics;
8. bounded state and fail-closed validation.

The Go NDR edge remains synthetic-only. The Rust PSI core remains non-authoritative. AI is not part of the trusted computing base.

Verification statuses are four-state where platform capability matters: `PASS`, `FAIL`, `UNSUPPORTED`, or `UNVERIFIED_PREREQUISITE`. A missing Windows Go race prerequisite is never mislabeled as a code failure.
