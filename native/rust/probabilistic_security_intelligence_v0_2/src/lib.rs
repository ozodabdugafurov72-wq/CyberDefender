//! CyberDefender Probabilistic Security Intelligence Core v0.2
//!
//! Security scope:
//! - deterministic, bounded, multi-window evidence fusion only;
//! - no network I/O, filesystem mutation, process control, registry/service/firewall access;
//! - no privileged action and no authorization issuance;
//! - source trust caps come from a trusted caller boundary, never from evidence producers;
//! - correlated/repeated evidence is discounted by dependency group and source concentration;
//! - missing telemetry increases uncertainty and never becomes benign evidence;
//! - invalid numeric inputs fail closed.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

pub const WINDOWS_SECONDS: [u64; 6] = [5, 30, 300, 3_600, 21_600, 86_400];
pub const MAX_EVIDENCE: usize = 128;
pub const MAX_TRUSTED_SOURCES: usize = 64;
pub const MAX_ID_LEN: usize = 100;
pub const LOG_ODDS_CLAMP: f64 = 20.0;
pub const SIGNED_LOG_LR_LIMIT: f64 = 8.0;
pub const CORRELATED_INDEPENDENCE_CAP: f64 = 0.25;
pub const CORRELATED_INDEPENDENCE_FLOOR: f64 = 0.05;
pub const SOURCE_REPEAT_WEIGHT_FLOOR: f64 = 0.25;
pub const UNKNOWN_SOURCE_RELIABILITY_CAP: f64 = 0.35;
pub const UNKNOWN_SOURCE_INTEGRITY_CAP: f64 = 0.50;
pub const MAX_AGE_SECONDS: f64 = 604_800.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    NotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationStatus {
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypothesisDisposition {
    Support,
    Counter,
    Unknown,
    Abstain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoisoningSignal {
    SourceConcentration,
    DependencyConcentration,
    UnknownSourceDominance,
    TelemetryQualityDegraded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusionError {
    InvalidPrior,
    EvidenceBound,
    TrustedSourceBound,
    InvalidEvidenceId,
    InvalidDependencyGroup,
    InvalidSourceId,
    DuplicateEvidenceId,
    DuplicateTrustedSource,
    InvalidSignedLogLr,
    InvalidWeight,
    InvalidQuality,
    InvalidAge,
}

impl fmt::Display for FusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::InvalidPrior => "INVALID_PRIOR",
            Self::EvidenceBound => "EVIDENCE_BOUND",
            Self::TrustedSourceBound => "TRUSTED_SOURCE_BOUND",
            Self::InvalidEvidenceId => "INVALID_EVIDENCE_ID",
            Self::InvalidDependencyGroup => "INVALID_DEPENDENCY_GROUP",
            Self::InvalidSourceId => "INVALID_SOURCE_ID",
            Self::DuplicateEvidenceId => "DUPLICATE_EVIDENCE_ID",
            Self::DuplicateTrustedSource => "DUPLICATE_TRUSTED_SOURCE",
            Self::InvalidSignedLogLr => "INVALID_SIGNED_LOG_LR",
            Self::InvalidWeight => "INVALID_WEIGHT",
            Self::InvalidQuality => "INVALID_QUALITY",
            Self::InvalidAge => "INVALID_AGE",
        };
        f.write_str(value)
    }
}

impl std::error::Error for FusionError {}

#[derive(Debug, Clone, PartialEq)]
pub struct TrustedSource {
    pub source_id: String,
    pub reliability_cap: f64,
    pub integrity_cap: f64,
}

impl TrustedSource {
    pub fn new(source_id: impl Into<String>, reliability_cap: f64, integrity_cap: f64) -> Self {
        Self {
            source_id: source_id.into(),
            reliability_cap,
            integrity_cap,
        }
    }

    fn validate(&self) -> Result<(), FusionError> {
        if !valid_identifier(&self.source_id) {
            return Err(FusionError::InvalidSourceId);
        }
        if !unit_interval(self.reliability_cap) || !unit_interval(self.integrity_cap) {
            return Err(FusionError::InvalidWeight);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub evidence_id: String,
    pub dependency_group: String,
    pub source_id: String,
    pub signed_log_lr: f64,
    pub claimed_reliability: f64,
    pub independence_weight: f64,
    pub sensor_integrity: f64,
    pub telemetry_quality: f64,
    pub observed_age_seconds: f64,
}

impl Evidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: impl Into<String>,
        dependency_group: impl Into<String>,
        source_id: impl Into<String>,
        signed_log_lr: f64,
        claimed_reliability: f64,
        independence_weight: f64,
        sensor_integrity: f64,
        telemetry_quality: f64,
        observed_age_seconds: f64,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            dependency_group: dependency_group.into(),
            source_id: source_id.into(),
            signed_log_lr,
            claimed_reliability,
            independence_weight,
            sensor_integrity,
            telemetry_quality,
            observed_age_seconds,
        }
    }

    fn validate(&self) -> Result<(), FusionError> {
        if !valid_identifier(&self.evidence_id) {
            return Err(FusionError::InvalidEvidenceId);
        }
        if !valid_identifier(&self.dependency_group) {
            return Err(FusionError::InvalidDependencyGroup);
        }
        if !valid_identifier(&self.source_id) {
            return Err(FusionError::InvalidSourceId);
        }
        if !self.signed_log_lr.is_finite()
            || self.signed_log_lr < -SIGNED_LOG_LR_LIMIT
            || self.signed_log_lr > SIGNED_LOG_LR_LIMIT
        {
            return Err(FusionError::InvalidSignedLogLr);
        }
        for value in [
            self.claimed_reliability,
            self.independence_weight,
            self.sensor_integrity,
            self.telemetry_quality,
        ] {
            if !unit_interval(value) {
                return Err(FusionError::InvalidWeight);
            }
        }
        if !self.observed_age_seconds.is_finite()
            || self.observed_age_seconds < 0.0
            || self.observed_age_seconds > MAX_AGE_SECONDS
        {
            return Err(FusionError::InvalidAge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FusionInput {
    pub prior_probability: f64,
    pub evidence: Vec<Evidence>,
    pub trusted_sources: Vec<TrustedSource>,
    pub data_quality: f64,
    pub epistemic_uncertainty: f64,
}

impl FusionInput {
    pub fn new(
        prior_probability: f64,
        evidence: Vec<Evidence>,
        trusted_sources: Vec<TrustedSource>,
    ) -> Self {
        Self {
            prior_probability,
            evidence,
            trusted_sources,
            data_quality: 1.0,
            epistemic_uncertainty: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WindowAssessment {
    pub window_seconds: u64,
    pub posterior_probability: f64,
    pub model_confidence: f64,
    pub effective_data_quality: f64,
    pub evidence_independence: f64,
    pub epistemic_uncertainty: f64,
    pub evidence_count: usize,
    pub unique_source_count: usize,
    pub dependency_group_count: usize,
    pub supporting_evidence_count: usize,
    pub counter_evidence_count: usize,
    pub unknown_source_count: usize,
    pub source_concentration: f64,
    pub dependency_concentration: f64,
    pub disposition: HypothesisDisposition,
    pub poisoning_signals: Vec<PoisoningSignal>,
    pub authorization: Authorization,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FusionResult {
    pub prior_probability: f64,
    pub windows: Vec<WindowAssessment>,
    pub calibration_status: CalibrationStatus,
    pub authorization: Authorization,
}

pub fn fuse_multi_window(input: &FusionInput) -> Result<FusionResult, FusionError> {
    validate_input(input)?;

    let trusted: HashMap<&str, &TrustedSource> = input
        .trusted_sources
        .iter()
        .map(|source| (source.source_id.as_str(), source))
        .collect();

    let mut windows = Vec::with_capacity(WINDOWS_SECONDS.len());
    for window_seconds in WINDOWS_SECONDS {
        windows.push(assess_window(input, &trusted, window_seconds));
    }

    Ok(FusionResult {
        prior_probability: input.prior_probability,
        windows,
        calibration_status: CalibrationStatus::Unverified,
        authorization: Authorization::NotGranted,
    })
}

fn assess_window(
    input: &FusionInput,
    trusted: &HashMap<&str, &TrustedSource>,
    window_seconds: u64,
) -> WindowAssessment {
    let window = window_seconds as f64;
    let eligible: Vec<&Evidence> = input
        .evidence
        .iter()
        .filter(|evidence| evidence.observed_age_seconds <= window)
        .collect();

    if eligible.is_empty() {
        return WindowAssessment {
            window_seconds,
            posterior_probability: input.prior_probability,
            model_confidence: 0.0,
            effective_data_quality: input.data_quality,
            evidence_independence: 1.0,
            epistemic_uncertainty: (input.epistemic_uncertainty + 0.25).clamp(0.0, 1.0),
            evidence_count: 0,
            unique_source_count: 0,
            dependency_group_count: 0,
            supporting_evidence_count: 0,
            counter_evidence_count: 0,
            unknown_source_count: 0,
            source_concentration: 0.0,
            dependency_concentration: 0.0,
            disposition: HypothesisDisposition::Unknown,
            poisoning_signals: Vec::new(),
            authorization: Authorization::NotGranted,
        };
    }

    let mut log_odds = logit(input.prior_probability);
    let mut group_counts: HashMap<&str, usize> = HashMap::new();
    let mut source_counts: HashMap<&str, usize> = HashMap::new();
    let mut supporting = 0usize;
    let mut counter = 0usize;
    let mut unknown_sources = 0usize;
    let mut independence_sum = 0.0;
    let mut telemetry_quality_sum = 0.0;

    for evidence in &eligible {
        let group_seen = group_counts
            .entry(evidence.dependency_group.as_str())
            .or_insert(0usize);
        let effective_independence = if *group_seen == 0 {
            evidence.independence_weight
        } else {
            let cap = (CORRELATED_INDEPENDENCE_CAP / (*group_seen as f64).sqrt())
                .max(CORRELATED_INDEPENDENCE_FLOOR);
            evidence.independence_weight.min(cap)
        };
        *group_seen += 1;

        let source_seen = source_counts
            .entry(evidence.source_id.as_str())
            .or_insert(0usize);
        let source_repeat_weight = if *source_seen == 0 {
            1.0
        } else {
            (1.0 / ((*source_seen + 1) as f64).sqrt()).max(SOURCE_REPEAT_WEIGHT_FLOOR)
        };
        *source_seen += 1;

        let (reliability_cap, integrity_cap) = match trusted.get(evidence.source_id.as_str()) {
            Some(source) => (source.reliability_cap, source.integrity_cap),
            None => {
                unknown_sources += 1;
                (UNKNOWN_SOURCE_RELIABILITY_CAP, UNKNOWN_SOURCE_INTEGRITY_CAP)
            }
        };

        let effective_reliability = evidence.claimed_reliability.min(reliability_cap)
            * evidence.sensor_integrity.min(integrity_cap)
            * evidence.telemetry_quality;
        let freshness = 1.0 / (1.0 + evidence.observed_age_seconds / window);
        let delta = evidence.signed_log_lr
            * effective_reliability
            * effective_independence
            * source_repeat_weight
            * freshness;

        log_odds += delta;
        independence_sum += effective_independence * source_repeat_weight;
        telemetry_quality_sum += evidence.telemetry_quality;

        if evidence.signed_log_lr > 0.0 {
            supporting += 1;
        } else if evidence.signed_log_lr < 0.0 {
            counter += 1;
        }
    }

    log_odds = log_odds.clamp(-LOG_ODDS_CLAMP, LOG_ODDS_CLAMP);
    let posterior_probability = sigmoid(log_odds);
    let evidence_count = eligible.len();
    let source_concentration = max_count_ratio(&source_counts, evidence_count);
    let dependency_concentration = max_count_ratio(&group_counts, evidence_count);
    let unknown_source_ratio = unknown_sources as f64 / evidence_count as f64;
    let average_telemetry_quality = telemetry_quality_sum / evidence_count as f64;

    let effective_data_quality =
        (input.data_quality * average_telemetry_quality * (1.0 - 0.25 * unknown_source_ratio))
            .clamp(0.0, 1.0);

    let concentration_uncertainty = if evidence_count >= 2 {
        0.15 * source_concentration + 0.15 * dependency_concentration
    } else {
        0.0
    };
    let epistemic_uncertainty =
        (input.epistemic_uncertainty + 0.20 * unknown_source_ratio + concentration_uncertainty)
            .clamp(0.0, 1.0);

    let evidence_independence = independence_sum / evidence_count as f64;
    let evidence_coverage = (evidence_count as f64 / 4.0).min(1.0);
    let source_diversity = if evidence_count <= 1 {
        1.0
    } else {
        (source_counts.len() as f64 / evidence_count as f64).clamp(0.0, 1.0)
    };
    let model_confidence = (effective_data_quality
        * (1.0 - epistemic_uncertainty)
        * evidence_coverage
        * source_diversity)
        .sqrt()
        .clamp(0.0, 1.0);

    let mut poisoning_signals = Vec::new();
    if evidence_count >= 4 && source_concentration >= 0.75 {
        poisoning_signals.push(PoisoningSignal::SourceConcentration);
    }
    if evidence_count >= 4 && dependency_concentration >= 0.75 {
        poisoning_signals.push(PoisoningSignal::DependencyConcentration);
    }
    if evidence_count >= 2 && unknown_source_ratio >= 0.50 {
        poisoning_signals.push(PoisoningSignal::UnknownSourceDominance);
    }
    if average_telemetry_quality < 0.50 {
        poisoning_signals.push(PoisoningSignal::TelemetryQualityDegraded);
    }

    let disposition = hypothesis_disposition(
        posterior_probability,
        supporting,
        counter,
        effective_data_quality,
        epistemic_uncertainty,
    );

    WindowAssessment {
        window_seconds,
        posterior_probability,
        model_confidence,
        effective_data_quality,
        evidence_independence,
        epistemic_uncertainty,
        evidence_count,
        unique_source_count: source_counts.len(),
        dependency_group_count: group_counts.len(),
        supporting_evidence_count: supporting,
        counter_evidence_count: counter,
        unknown_source_count: unknown_sources,
        source_concentration,
        dependency_concentration,
        disposition,
        poisoning_signals,
        authorization: Authorization::NotGranted,
    }
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
    if input.trusted_sources.len() > MAX_TRUSTED_SOURCES {
        return Err(FusionError::TrustedSourceBound);
    }
    if !unit_interval(input.data_quality) || !unit_interval(input.epistemic_uncertainty) {
        return Err(FusionError::InvalidQuality);
    }

    let mut evidence_ids = HashSet::with_capacity(input.evidence.len());
    for evidence in &input.evidence {
        evidence.validate()?;
        if !evidence_ids.insert(evidence.evidence_id.as_str()) {
            return Err(FusionError::DuplicateEvidenceId);
        }
    }

    let mut trusted_ids = HashSet::with_capacity(input.trusted_sources.len());
    for source in &input.trusted_sources {
        source.validate()?;
        if !trusted_ids.insert(source.source_id.as_str()) {
            return Err(FusionError::DuplicateTrustedSource);
        }
    }
    Ok(())
}

fn hypothesis_disposition(
    posterior: f64,
    supporting: usize,
    counter: usize,
    data_quality: f64,
    uncertainty: f64,
) -> HypothesisDisposition {
    if data_quality < 0.35 || uncertainty > 0.75 {
        return HypothesisDisposition::Abstain;
    }
    if posterior >= 0.65 && supporting > counter {
        HypothesisDisposition::Support
    } else if posterior <= 0.35 && counter > supporting {
        HypothesisDisposition::Counter
    } else {
        HypothesisDisposition::Unknown
    }
}

fn max_count_ratio<K>(counts: &HashMap<K, usize>, total: usize) -> f64
where
    K: std::cmp::Eq + std::hash::Hash,
{
    if total == 0 {
        return 0.0;
    }
    let max_count = counts.values().copied().max().unwrap_or(0);
    max_count as f64 / total as f64
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

    fn trust(source: &str) -> TrustedSource {
        TrustedSource::new(source, 0.95, 0.95)
    }

    #[allow(clippy::too_many_arguments)]
    fn ev(
        id: &str,
        group: &str,
        source: &str,
        signed_log_lr: f64,
        reliability: f64,
        independence: f64,
        integrity: f64,
        quality: f64,
        age: f64,
    ) -> Evidence {
        Evidence::new(
            id,
            group,
            source,
            signed_log_lr,
            reliability,
            independence,
            integrity,
            quality,
            age,
        )
    }

    fn window(result: &FusionResult, seconds: u64) -> &WindowAssessment {
        result
            .windows
            .iter()
            .find(|item| item.window_seconds == seconds)
            .unwrap()
    }

    #[test]
    fn fixed_windows_and_authority() {
        let result = fuse_multi_window(&FusionInput::new(0.1, vec![], vec![])).unwrap();
        assert_eq!(result.windows.len(), WINDOWS_SECONDS.len());
        assert_eq!(result.authorization, Authorization::NotGranted);
        assert_eq!(result.calibration_status, CalibrationStatus::Unverified);
        assert_eq!(
            window(&result, 5).disposition,
            HypothesisDisposition::Unknown
        );
        assert_eq!(
            window(&result, 86_400).authorization,
            Authorization::NotGranted
        );
    }

    #[test]
    fn low_and_slow_survives_long_window() {
        let evidence = vec![
            ev("a", "net", "s1", 3.0, 0.95, 1.0, 0.95, 1.0, 900.0),
            ev("b", "endpoint", "s2", 3.0, 0.95, 1.0, 0.95, 1.0, 1_800.0),
            ev("c", "identity", "s3", 3.0, 0.95, 1.0, 0.95, 1.0, 2_400.0),
        ];
        let input = FusionInput::new(0.1, evidence, vec![trust("s1"), trust("s2"), trust("s3")]);
        let result = fuse_multi_window(&input).unwrap();
        assert_eq!(window(&result, 300).evidence_count, 0);
        assert_eq!(
            window(&result, 300).disposition,
            HypothesisDisposition::Unknown
        );
        assert_eq!(window(&result, 3_600).evidence_count, 3);
        assert_eq!(
            window(&result, 3_600).disposition,
            HypothesisDisposition::Support
        );
        assert!(window(&result, 3_600).posterior_probability > 0.65);
    }

    #[test]
    fn repeated_dependency_group_is_discounted() {
        let evidence = vec![
            ev("a", "same", "s1", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("b", "same", "s2", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("c", "same", "s3", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("d", "same", "s4", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
        ];
        let input = FusionInput::new(
            0.1,
            evidence,
            vec![trust("s1"), trust("s2"), trust("s3"), trust("s4")],
        );
        let result = fuse_multi_window(&input).unwrap();
        let w = window(&result, 5);
        assert!(w.evidence_independence < 0.50);
        assert!(w
            .poisoning_signals
            .contains(&PoisoningSignal::DependencyConcentration));
        assert_eq!(w.authorization, Authorization::NotGranted);
    }

    #[test]
    fn repeated_source_consensus_is_discounted_and_flagged() {
        let evidence = vec![
            ev("a", "g1", "s1", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("b", "g2", "s1", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("c", "g3", "s1", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("d", "g4", "s1", 4.0, 1.0, 1.0, 1.0, 1.0, 1.0),
        ];
        let input = FusionInput::new(0.1, evidence, vec![trust("s1")]);
        let result = fuse_multi_window(&input).unwrap();
        let w = window(&result, 5);
        assert_eq!(w.unique_source_count, 1);
        assert_eq!(w.source_concentration, 1.0);
        assert!(w
            .poisoning_signals
            .contains(&PoisoningSignal::SourceConcentration));
        assert!(w.model_confidence < 0.50);
    }

    #[test]
    fn unknown_source_cannot_self_assert_full_trust() {
        let unknown = FusionInput::new(
            0.1,
            vec![ev("a", "g1", "unknown", 6.0, 1.0, 1.0, 1.0, 1.0, 1.0)],
            vec![],
        );
        let trusted = FusionInput::new(
            0.1,
            vec![ev("b", "g1", "known", 6.0, 1.0, 1.0, 1.0, 1.0, 1.0)],
            vec![trust("known")],
        );
        let unknown_result = fuse_multi_window(&unknown).unwrap();
        let trusted_result = fuse_multi_window(&trusted).unwrap();
        assert!(
            window(&unknown_result, 5).posterior_probability
                < window(&trusted_result, 5).posterior_probability
        );
        assert_eq!(window(&unknown_result, 5).unknown_source_count, 1);
    }

    #[test]
    fn counterevidence_can_drive_counter_disposition() {
        let evidence = vec![
            ev("a", "endpoint", "s1", -4.0, 0.95, 1.0, 0.95, 1.0, 1.0),
            ev("b", "identity", "s2", -4.0, 0.95, 1.0, 0.95, 1.0, 2.0),
        ];
        let input = FusionInput::new(0.5, evidence, vec![trust("s1"), trust("s2")]);
        let result = fuse_multi_window(&input).unwrap();
        assert_eq!(
            window(&result, 5).disposition,
            HypothesisDisposition::Counter
        );
        assert!(window(&result, 5).posterior_probability <= 0.35);
    }

    #[test]
    fn low_quality_abstains() {
        let mut input = FusionInput::new(
            0.1,
            vec![ev("a", "endpoint", "s1", 6.0, 1.0, 1.0, 1.0, 0.2, 1.0)],
            vec![trust("s1")],
        );
        input.data_quality = 0.4;
        let result = fuse_multi_window(&input).unwrap();
        assert_eq!(
            window(&result, 5).disposition,
            HypothesisDisposition::Abstain
        );
        assert_eq!(window(&result, 5).authorization, Authorization::NotGranted);
    }

    #[test]
    fn duplicate_evidence_id_fails_closed() {
        let evidence = vec![
            ev("same", "g1", "s1", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0),
            ev("same", "g2", "s2", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0),
        ];
        assert_eq!(
            fuse_multi_window(&FusionInput::new(0.1, evidence, vec![])),
            Err(FusionError::DuplicateEvidenceId)
        );
    }

    #[test]
    fn duplicate_trusted_source_fails_closed() {
        let input = FusionInput::new(0.1, vec![], vec![trust("s1"), trust("s1")]);
        assert_eq!(
            fuse_multi_window(&input),
            Err(FusionError::DuplicateTrustedSource)
        );
    }

    #[test]
    fn invalid_numeric_input_fails_closed() {
        let evidence = vec![ev("a", "g1", "s1", f64::NAN, 1.0, 1.0, 1.0, 1.0, 1.0)];
        assert_eq!(
            fuse_multi_window(&FusionInput::new(0.1, evidence, vec![])),
            Err(FusionError::InvalidSignedLogLr)
        );
    }

    #[test]
    fn stale_beyond_24h_does_not_become_benign() {
        let input = FusionInput::new(
            0.1,
            vec![ev("old", "g1", "s1", 6.0, 1.0, 1.0, 1.0, 1.0, 90_000.0)],
            vec![trust("s1")],
        );
        let result = fuse_multi_window(&input).unwrap();
        let w = window(&result, 86_400);
        assert_eq!(w.evidence_count, 0);
        assert_eq!(w.disposition, HypothesisDisposition::Unknown);
        assert!(w.epistemic_uncertainty >= 0.25);
    }

    #[test]
    fn bounds_are_enforced() {
        let evidence: Vec<_> = (0..=MAX_EVIDENCE)
            .map(|i| ev(&format!("e{i}"), "g", "s", 0.1, 1.0, 1.0, 1.0, 1.0, 1.0))
            .collect();
        assert_eq!(
            fuse_multi_window(&FusionInput::new(0.1, evidence, vec![])),
            Err(FusionError::EvidenceBound)
        );
    }

    #[test]
    fn trusted_source_cap_limits_claimed_reliability() {
        let weak = FusionInput::new(
            0.1,
            vec![ev("a", "g", "s", 6.0, 1.0, 1.0, 1.0, 1.0, 1.0)],
            vec![TrustedSource::new("s", 0.2, 0.2)],
        );
        let strong = FusionInput::new(
            0.1,
            vec![ev("b", "g", "s", 6.0, 1.0, 1.0, 1.0, 1.0, 1.0)],
            vec![TrustedSource::new("s", 0.95, 0.95)],
        );
        assert!(
            window(&fuse_multi_window(&weak).unwrap(), 5).posterior_probability
                < window(&fuse_multi_window(&strong).unwrap(), 5).posterior_probability
        );
    }

    #[test]
    fn numeric_fixture_independent_sources() {
        let input = FusionInput::new(
            0.1,
            vec![
                ev("a", "net", "s1", 2.0, 0.9, 1.0, 0.9, 1.0, 1.0),
                ev("b", "endpoint", "s2", 1.4, 0.8, 1.0, 0.9, 0.9, 2.0),
            ],
            vec![trust("s1"), trust("s2")],
        );
        let result = fuse_multi_window(&input).unwrap();
        close(
            window(&result, 5).posterior_probability,
            0.45035794005496954,
        );
        close(
            window(&result, 30).posterior_probability,
            0.5550305077666905,
        );
    }
}
