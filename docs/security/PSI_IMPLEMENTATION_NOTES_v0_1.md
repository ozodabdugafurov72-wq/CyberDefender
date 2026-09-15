# PSI v0.1 Implementation Notes

CyberDefender now begins moving numerical security intelligence out of the Python-only path.

## Language ownership in this milestone

- **Rust**: bounded deterministic evidence fusion, dependency discounting, uncertainty and calibration metadata.
- **Go**: bounded synthetic NDR edge feature aggregation. No live ingress yet.
- **Python**: conformance oracle and existing regression suites only; it is not the privileged authority and is not required to implement the Rust fusion formula.
- **C/C++/C#**: toolchains are prepared for later native/Windows-specific adapters; they are intentionally not added merely to increase language count.

## Why the Rust core is not an AI model

The PSI core must remain deterministic, auditable and independent from language-model output. AI may consume PSI results and explain them, but AI cannot alter the authorization boundary, mint a ticket or mark independent verification as PASS.

## Security model against AI manipulation

Any future AI analyst output must enter as `UNTRUSTED_ADVISORY_INPUT`. The deterministic admission/risk/policy/safety path remains authoritative. If AI is unavailable or compromised, PSI/NDR/correlation must remain usable without it.

## Current claim boundary

- deterministic conformance: testable
- synthetic edge behavior: testable
- real-world probability calibration: **UNVERIFIED**
- lab calibration: **UNVERIFIED**
- production calibration: **UNVERIFIED**
- live NDR capture: **NOT ENABLED**
- response authority: **NOT GRANTED**
