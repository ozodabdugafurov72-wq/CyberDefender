# Probability Fusion Conformance v1

This is a language-neutral **reference contract**, not a production-calibrated model. Long-term owner target is Rust; Python may be used only as an offline oracle/test harness.

For a hypothesis prior `p`, compute log-odds `L = ln(p/(1-p))`. For each evidence item add:

`signed_log_likelihood_ratio * reliability * independence_weight * freshness_weight`

Then clamp `L` to [-20, 20] and map through sigmoid.

Rules:

- prior must be finite and strictly between 0 and 1
- each weight must be finite and in [0,1]
- signed log-likelihood ratio must be finite and bounded to [-8,8]
- dependency groups are explicit; correlated evidence must be discounted before fusion
- counter-evidence uses a negative signed log-likelihood ratio
- no posterior grants authorization
- invalid values fail closed
- production calibration requires real/lab data and calibration metrics; synthetic fixtures are conformance only
