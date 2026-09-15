# CyberDefender Probabilistic Security Intelligence Core v0.2

Status: **engineering/conformance implementation**. It is not production-calibrated threat probability and cannot authorize response.

## Non-negotiable invariants

- `Probability != Truth`
- `Confidence != Risk`
- `Risk != Authorization`
- `AI recommendation != Authorization`
- `Missing telemetry != benign evidence`
- `Correlated evidence != independent evidence`
- every output has `Authorization = NOT_GRANTED`
- calibration is `UNVERIFIED`

## Multi-window model

The core emits separate assessments for fixed windows:

- 5 seconds
- 30 seconds
- 5 minutes
- 1 hour
- 6 hours
- 24 hours

There is intentionally no single privileged aggregate score. A short-window absence cannot erase long-horizon evidence. Evidence older than the 24-hour analysis horizon contributes to no window and therefore increases uncertainty through missing-evidence semantics rather than becoming benign evidence.

## Evidence fusion

For prior probability `p`:

`L = ln(p / (1-p))`

For each eligible item in a window:

`delta = signed_log_lr * effective_reliability * effective_independence * source_repeat_weight * freshness`

Where:

- `signed_log_lr` is finite and in `[-8, 8]`.
- `effective_reliability` is bounded by a trusted caller-owned source cap, then multiplied by bounded sensor integrity and telemetry quality.
- an unknown source cannot self-assert full trust; default caps are reliability `0.35` and integrity `0.50`.
- repeated dependency-group evidence is discounted; repeats are capped by `0.25 / sqrt(previous_count)` with floor `0.05`.
- repeated evidence from one source is discounted by `1/sqrt(source_occurrence)` with floor `0.25`.
- freshness is deterministic: `1 / (1 + age/window)`.
- log odds are clamped to `[-20, 20]`.
- max evidence count is 128.
- max trusted source records is 64.
- duplicate evidence IDs and duplicate trusted-source IDs fail closed.

## Poisoning resistance

The core reports non-authoritative poisoning indicators for:

- source concentration,
- dependency-group concentration,
- unknown-source dominance,
- degraded telemetry quality.

These indicators do not authorize containment. They reduce confidence and/or increase uncertainty.

## Hypothesis disposition

Each window is classified as one of:

- `SUPPORT`
- `COUNTER`
- `UNKNOWN`
- `ABSTAIN`

`ABSTAIN` is mandatory when effective data quality is too low or epistemic uncertainty is too high. Missing telemetry returns `UNKNOWN`, not benign.

## Security boundary

This crate has no network I/O, filesystem mutation, process control, registry/service/firewall access, endpoint isolation, quarantine, or authorization issuance. AI is outside this trust boundary and can only provide `UNTRUSTED_ADVISORY_INPUT` downstream.
