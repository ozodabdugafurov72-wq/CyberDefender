# CyberDefender Probabilistic Security Intelligence Core v0.1

Status: **engineering/conformance implementation**, not production-calibrated threat probability.

## Non-negotiable invariants

- `Probability != Truth`
- `Confidence != Risk`
- `Risk != Authorization`
- `AI recommendation != Authorization`
- `Missing telemetry != benign evidence`
- `Correlated evidence != independent evidence`
- `Authorization = NOT_GRANTED` for every PSI v0.1 output

## Rust ownership

The Rust PSI core owns deterministic bounded evidence fusion and numeric validation. It performs no network I/O, process control, registry/service/firewall mutation, isolation, quarantine, or privileged response.

### Fusion

For prior probability `p`:

`L = ln(p / (1-p))`

Each evidence contribution is:

`signed_log_lr * reliability * effective_independence * freshness_weight * sensor_integrity`

Then:

- `L` is clamped to `[-20, 20]`
- posterior is `sigmoid(L)`
- `signed_log_lr` must be finite and in `[-8, 8]`
- every weight must be finite and in `[0,1]`
- max evidence count is 64
- duplicate evidence IDs fail closed
- IDs are bounded and restricted to `[A-Za-z0-9_.:-]`

## Dependency-group defense

The first item in a dependency group may use its requested independence weight. Every additional item in the same group is capped to `0.25`, even if a producer attempts to self-assert full independence.

This is deliberately conservative. Production dependency modelling may become more sophisticated later, but v0.1 must not multiply repeated telemetry as independent proof.

## Uncertainty / abstention

PSI tracks `data_quality` and `epistemic_uncertainty` separately from posterior probability.

- data quality `< 0.35` or uncertainty `> 0.75` => `ABSTAIN`
- data quality `< 0.60` or uncertainty `> 0.45` => `REVIEW_REQUIRED`
- otherwise => `EVALUATE`

These states do not grant response authority.

## Calibration status

One of:

- `UNVERIFIED`
- `SYNTHETIC_CALIBRATED`
- `LAB_CALIBRATED`
- `PRODUCTION_CALIBRATED`

This package does not promote calibration beyond `UNVERIFIED` merely because deterministic conformance tests pass.
