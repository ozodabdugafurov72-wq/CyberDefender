//! CyberDefender Probabilistic Security Intelligence Core v0.1
//!
//! Security scope:
//! - deterministic, bounded evidence fusion only;
//! - no network I/O, filesystem mutation, process control, registry/service/firewall access;
//! - no privileged action and no authorization issuance;
//! - probabilities are engineering outputs until calibration status says otherwise;
//! - correlated evidence is dependency-group aware and automatically capped;
//! - invalid numeric inputs fail closed.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

pub const MAX_EVIDENCE: usize = 64;
pub const MAX_ID_LEN: usize = 100;
pub const LOG_ODDS_CLAMP: f64 = 20.0;
pub const SIGNED_LOG_LR_LIMIT: f64 = 8.0;
pub const CORRELATED_INDEPENDENCE_CAP: f64 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    NotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationStatus {
    Unverified,
    SyntheticCalibrated,
    LabCalibrated,
    ProductionCalibrated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssessmentState {
    Evaluate,
    ReviewRequired,
    Abstain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusionError {
    InvalidPrior,
    EvidenceBound,
    InvalidEvidenceId,
    InvalidDependencyGroup,
    DuplicateEvidenceId,
    InvalidSignedLogLr,
    InvalidWeight,
    InvalidQuality,
}

impl fmt::Display for FusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::InvalidPrior => "INVALID_PRIOR",
            Self::EvidenceBound => "EVIDENCE_BOUND",
            Self::InvalidEvidenceId => "INVALID_EVIDENCE_ID",
            Self::InvalidDependencyGroup => "INVALID_DEPENDENCY_GROUP",
            Self::DuplicateEvidenceId => "DUPLICATE_EVIDENCE_ID",
            Self::InvalidSignedLogLr => "INVALID_SIGNED_LOG_LR",
            Self::InvalidWeight => "INVALID_WEIGHT",
            Self::InvalidQuality => "INVALID_QUALITY",
        };
        f.write_str(value)
    }
}

impl std::error::Error for FusionError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub evidence_id: String,
    pub dependency_group: String,
    pub signed_log_lr: f64,
    pub reliability: f64,
    pub independence_weight: f64,
    pub freshness_weight: f64,
    pub sensor_integrity: f64,
}

impl Evidence {
    pub fn new(
        evidence_id: impl Into<String>,
        dependency_group: impl Into<String>,
        signed_log_lr: f64,
        reliability: f64,
        independence_weight: f64,
        freshness_weight: f64,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            dependency_group: dependency_group.into(),
            signed_log_lr,
            reliability,
            independence_weight,
            freshness_weight,
            sensor_integrity: 1.0,
        }
    }

    pub fn with_sensor_integrity(mut self, value: f64) -> Self {
        self.sensor_integrity = value;
        self
    }

    fn validate(&self) -> Result<(), FusionError> {
        if !valid_identifier(&self.evidence_id) {
            return Err(FusionError::InvalidEvidenceId);
        }
        if !valid_identifier(&self.dependency_group) {
            return Err(FusionError::InvalidDependencyGroup);
        }
        if !self.signed_log_lr.is_finite()
            || self.signed_log_lr < -SIGNED_LOG_LR_LIMIT
            || self.signed_log_lr > SIGNED_LOG_LR_LIMIT
        {
            return Err(FusionError::InvalidSignedLogLr);
        }
        for value in [
            self.reliability,
            self.independence_weight,
            self.freshness_weight,
            self.sensor_integrity,
        ] {
            if !unit_interval(value) {
                return Err(FusionError::InvalidWeight);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FusionInput {
    pub prior_probability: f64,
    pub evidence: Vec<Evidence>,
    pub data_quality: f64,
    pub epistemic_uncertainty: f64,
    pub calibration_status: CalibrationStatus,
}

impl FusionInput {
    pub fn new(prior_probability: f64, evidence: Vec<Evidence>) -> Self {
        Self {
            prior_probability,
            evidence,
            data_quality: 1.0,
            epistemic_uncertainty: 0.0,
            calibration_status: CalibrationStatus::Unverified,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceContribution {
    pub evidence_id: String,
    pub dependency_group: String,
    pub signed_log_lr: f64,
    pub requested_independence: f64,
    pub effective_independence: f64,
    pub effective_log_odds_delta: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FusionResult {
    pub posterior_probability: f64,
    pub model_confidence: f64,
    pub data_quality: f64,
    pub evidence_independence: f64,
    pub epistemic_uncertainty: f64,
    pub calibration_status: CalibrationStatus,
    pub assessment_state: AssessmentState,
    pub authorization: Authorization,
    pub dependency_group_count: usize,
    pub supporting_evidence_count: usize,
    pub counter_evidence_count: usize,
    pub contributions: Vec<EvidenceContribution>,
}

pub fn fuse(input: &FusionInput) -> Result<FusionResult, FusionError> {
    validate_input(input)?;

    let mut log_odds = logit(input.prior_probability);
    let mut group_counts: HashMap<&str, usize> = HashMap::new();
    let mut contributions = Vec::with_capacity(input.evidence.len());
    let mut supporting = 0usize;
    let mut counter = 0usize;
    let mut independence_sum = 0.0;

    for evidence in &input.evidence {
        let seen = group_counts
            .entry(evidence.dependency_group.as_str())
            .or_insert(0usize);

        let effective_independence = if *seen == 0 {
            evidence.independence_weight
        } else {
            evidence
                .independence_weight
                .min(CORRELATED_INDEPENDENCE_CAP)
        };
        *seen += 1;

        let delta = evidence.signed_log_lr
            * evidence.reliability
            * effective_independence
            * evidence.freshness_weight
            * evidence.sensor_integrity;

        log_odds += delta;
        independence_sum += effective_independence;

        if evidence.signed_log_lr > 0.0 {
            supporting += 1;
        } else if evidence.signed_log_lr < 0.0 {
            counter += 1;
        }

        contributions.push(EvidenceContribution {
            evidence_id: evidence.evidence_id.clone(),
            dependency_group: evidence.dependency_group.clone(),
            signed_log_lr: evidence.signed_log_lr,
            requested_independence: evidence.independence_weight,
            effective_independence,
            effective_log_odds_delta: delta,
        });
    }

    log_odds = log_odds.clamp(-LOG_ODDS_CLAMP, LOG_ODDS_CLAMP);
    let posterior_probability = sigmoid(log_odds);

    let evidence_independence = if input.evidence.is_empty() {
        1.0
    } else {
        independence_sum / input.evidence.len() as f64
    };

    let evidence_coverage = (input.evidence.len() as f64 / 3.0).min(1.0);
    let model_confidence =
        (input.data_quality * (1.0 - input.epistemic_uncertainty) * evidence_coverage)
            .sqrt()
            .clamp(0.0, 1.0);

    let assessment_state = assessment_state(input.data_quality, input.epistemic_uncertainty);

    Ok(FusionResult {
        posterior_probability,
        model_confidence,
        data_quality: input.data_quality,
        evidence_independence,
        epistemic_uncertainty: input.epistemic_uncertainty,
        calibration_status: input.calibration_status,
        assessment_state,
        authorization: Authorization::NotGranted,
        dependency_group_count: group_counts.len(),
        supporting_evidence_count: supporting,
        counter_evidence_count: counter,
        contributions,
    })
}

fn validate_input(input: &FusionInput) -> Result<(), FusionError> {
    if !input.prior_probability.is_finite()
        || input.prior_probability <= 0.0
        || input.prior_probability >= 1.0
    {
        return Err(FusionError::InvalidPrior);
    }
    if input.evidence.len() > MAX_EVIDENCE {
        return Err(FusionError::EvidenceBound);
    }
    if !unit_interval(input.data_quality) || !unit_interval(input.epistemic_uncertainty) {
        return Err(FusionError::InvalidQuality);
    }

    let mut ids = HashSet::with_capacity(input.evidence.len());
    for evidence in &input.evidence {
        evidence.validate()?;
        if !ids.insert(evidence.evidence_id.as_str()) {
            return Err(FusionError::DuplicateEvidenceId);
        }
    }
    Ok(())
}

fn assessment_state(data_quality: f64, uncertainty: f64) -> AssessmentState {
    if data_quality < 0.35 || uncertainty > 0.75 {
        AssessmentState::Abstain
    } else if data_quality < 0.60 || uncertainty > 0.45 {
        AssessmentState::ReviewRequired
    } else {
        AssessmentState::Evaluate
    }
}

fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ID_LEN {
        return false;
    }
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

fn unit_interval(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn logit(p: f64) -> f64 {
    (p / (1.0 - p)).ln()
}

fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-12;

    fn close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= EPS,
            "actual={actual:.15} expected={expected:.15}"
        );
    }

    fn ev(
        id: &str,
        group: &str,
        signed_log_lr: f64,
        reliability: f64,
        independence: f64,
        freshness: f64,
    ) -> Evidence {
        Evidence::new(
            id,
            group,
            signed_log_lr,
            reliability,
            independence,
            freshness,
        )
    }

    #[test]
    fn prior_only_fixture() {
        let result = fuse(&FusionInput::new(0.1, vec![])).unwrap();
        close(result.posterior_probability, 0.1);
        assert_eq!(result.authorization, Authorization::NotGranted);
    }

    #[test]
    fn independent_supporting_fixture() {
        let result = fuse(&FusionInput::new(
            0.1,
            vec![
                ev("ev-1", "netflow", 2.0, 0.9, 1.0, 1.0),
                ev("ev-2", "endpoint", 1.4, 0.8, 1.0, 0.9),
            ],
        ))
        .unwrap();
        close(result.posterior_probability, 0.6481176661751409);
        assert_eq!(result.dependency_group_count, 2);
        assert_eq!(result.authorization, Authorization::NotGranted);
    }

    #[test]
    fn supporting_with_counterevidence_fixture() {
        let result = fuse(&FusionInput::new(
            0.1,
            vec![
                ev("ev-1", "netflow", 2.0, 0.9, 1.0, 1.0),
                ev("ev-2", "asset_context", -1.2, 0.95, 1.0, 1.0),
            ],
        ))
        .unwrap();
        close(result.posterior_probability, 0.17693910183506345);
        assert_eq!(result.counter_evidence_count, 1);
    }

    #[test]
    fn correlated_duplicate_fixture() {
        let result = fuse(&FusionInput::new(
            0.1,
            vec![
                ev("ev-1", "same_packet_stream", 2.0, 0.9, 1.0, 1.0),
                ev("ev-2", "same_packet_stream", 2.0, 0.9, 0.15, 1.0),
            ],
        ))
        .unwrap();
        close(result.posterior_probability, 0.4682366877732213);
        close(result.contributions[1].effective_independence, 0.15);
    }

    #[test]
    fn repeated_group_cannot_self_assert_full_independence() {
        let result = fuse(&FusionInput::new(
            0.1,
            vec![
                ev("ev-1", "same_packet_stream", 2.0, 0.9, 1.0, 1.0),
                ev("ev-2", "same_packet_stream", 2.0, 0.9, 1.0, 1.0),
            ],
        ))
        .unwrap();
        close(
            result.contributions[1].effective_independence,
            CORRELATED_INDEPENDENCE_CAP,
        );
        assert!(result.posterior_probability < 0.7);
    }

    #[test]
    fn stale_signal_fixture() {
        let result = fuse(&FusionInput::new(
            0.1,
            vec![ev("ev-1", "netflow", 2.0, 0.9, 1.0, 0.2)],
        ))
        .unwrap();
        close(result.posterior_probability, 0.13737986769209481);
    }

    #[test]
    fn sensor_integrity_discounts_signal() {
        let full = fuse(&FusionInput::new(
            0.1,
            vec![ev("a", "endpoint", 3.0, 1.0, 1.0, 1.0)],
        ))
        .unwrap();
        let degraded = fuse(&FusionInput::new(
            0.1,
            vec![ev("b", "endpoint", 3.0, 1.0, 1.0, 1.0).with_sensor_integrity(0.2)],
        ))
        .unwrap();
        assert!(degraded.posterior_probability < full.posterior_probability);
    }

    #[test]
    fn low_quality_abstains_without_changing_authority() {
        let mut input = FusionInput::new(0.1, vec![ev("ev-1", "endpoint", 6.0, 1.0, 1.0, 1.0)]);
        input.data_quality = 0.2;
        let result = fuse(&input).unwrap();
        assert_eq!(result.assessment_state, AssessmentState::Abstain);
        assert_eq!(result.authorization, Authorization::NotGranted);
    }

    #[test]
    fn high_uncertainty_abstains() {
        let mut input = FusionInput::new(0.1, vec![]);
        input.epistemic_uncertainty = 0.9;
        assert_eq!(
            fuse(&input).unwrap().assessment_state,
            AssessmentState::Abstain
        );
    }

    #[test]
    fn invalid_prior_fails_closed() {
        for prior in [0.0, 1.0, -0.1, f64::NAN, f64::INFINITY] {
            assert_eq!(
                fuse(&FusionInput::new(prior, vec![])),
                Err(FusionError::InvalidPrior)
            );
        }
    }

    #[test]
    fn invalid_numeric_evidence_fails_closed() {
        let bad = ev("ev-1", "netflow", f64::NAN, 1.0, 1.0, 1.0);
        assert_eq!(
            fuse(&FusionInput::new(0.1, vec![bad])),
            Err(FusionError::InvalidSignedLogLr)
        );

        let bad_weight = ev("ev-1", "netflow", 1.0, 1.1, 1.0, 1.0);
        assert_eq!(
            fuse(&FusionInput::new(0.1, vec![bad_weight])),
            Err(FusionError::InvalidWeight)
        );
    }

    #[test]
    fn duplicate_evidence_id_fails_closed() {
        let a = ev("same", "netflow", 1.0, 1.0, 1.0, 1.0);
        let b = ev("same", "endpoint", 1.0, 1.0, 1.0, 1.0);
        assert_eq!(
            fuse(&FusionInput::new(0.1, vec![a, b])),
            Err(FusionError::DuplicateEvidenceId)
        );
    }

    #[test]
    fn evidence_count_is_bounded() {
        let items: Vec<_> = (0..=MAX_EVIDENCE)
            .map(|i| ev(&format!("ev-{i}"), "netflow", 0.1, 1.0, 1.0, 1.0))
            .collect();
        assert_eq!(
            fuse(&FusionInput::new(0.1, items)),
            Err(FusionError::EvidenceBound)
        );
    }

    #[test]
    fn model_confidence_is_not_posterior() {
        let mut input = FusionInput::new(0.1, vec![ev("ev-1", "endpoint", 6.0, 1.0, 1.0, 1.0)]);
        input.data_quality = 0.5;
        input.epistemic_uncertainty = 0.4;
        let result = fuse(&input).unwrap();
        assert_ne!(result.posterior_probability, result.model_confidence);
        assert_eq!(result.authorization, Authorization::NotGranted);
    }
}
