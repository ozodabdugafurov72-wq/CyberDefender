# Probabilistic Security Intelligence Contract v1

This contract is architecture-level in this milestone. It does **not** claim calibrated production probabilities yet.

## Core invariants

- `Probability != Truth`. A posterior is conditional on the current model, priors and evidence quality.
- `Confidence != Risk`. Confidence describes belief in a hypothesis; risk includes impact and asset context.
- `Risk != Authorization`. No numeric score grants execution authority.
- `Correlated evidence != independent evidence`. Dependency groups must prevent confidence multiplication.
- `Missing telemetry != benign`. Absence of evidence is not evidence of absence.
- `AI recommendation != Authorization`. AI may explain or recommend only.

## Separation

- `posterior_probability`: likelihood of a specific hypothesis under the current model/evidence assumptions.
- `data_quality`: reliability/completeness of telemetry.
- `evidence_independence`: how independent the evidence classes are.
- `epistemic_uncertainty`: uncertainty due to missing/unknown model knowledge.
- `risk`: impact-aware business/security risk if the hypothesis is true.
- `authorization`: a separate policy/safety decision; probability and risk never grant it.

## Required hypothesis examples

Network recon:
- benign_application
- approved_scanner
- unknown_recon
- malicious_internal_recon
- distributed_stealth_recon

USB/device:
- approved_device_use
- benign_transfer
- sensitive_data_exfiltration
- removable_media_execution_chain
- HID_injection_like_behavior
- rogue_network_device

## Evidence fusion rules

1. Start from explicit prior; never hide the prior.
2. Each signal has likelihood contribution, sensor reliability, freshness and dependency group.
3. Evidence from the same dependency group is discounted; duplicate logs do not become independent proof.
4. Counter-evidence must be represented, not discarded.
5. Invalid/NaN/infinite scores are rejected.
6. No single unverified model output may drive posterior directly.
7. Calibration status must be explicit: `UNVERIFIED`, `SYNTHETIC_CALIBRATED`, `LAB_CALIBRATED`, `PRODUCTION_CALIBRATED`.
8. Until lab/real datasets exist, probabilities are engineering scores, not claims of real-world accuracy.
9. Low data quality/high uncertainty should allow `ABSTAIN` and `REVIEW_REQUIRED`.
10. High posterior does not bypass Policy/Safety/Independent Verification.

## Time windows

The design must support bounded multi-window analysis such as 5s, 30s, 5m, 1h, 6h and 24h. The exact production windows require telemetry-volume benchmarks; they are not hard-coded claims.

## Low-and-slow/distributed scan principle

Do not rely solely on `N ports in N seconds`. Accumulate bounded evidence across time and graph dimensions: source, target set, service/port, subnet, ordering, timing, source reputation/context and independent endpoint/process context.
