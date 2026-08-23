//! Calculates the versioned, explainable Surface Exposure Score.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{ScanReport, ScanStatus, Severity};

// Rust guideline compliant 2026-02-21

/// Current deterministic exposure-score model identifier.
pub const EXPOSURE_MODEL_VERSION: &str = "1.0";

/// One explicit score deduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreDeduction {
    /// Stable deduction identity.
    pub id: String,
    /// Deducted points.
    pub points: u8,
    /// Human-readable rationale.
    pub reason: String,
    /// Stable finding IDs supporting this deduction.
    pub finding_ids: Vec<String>,
    /// Affected target when available.
    pub target: Option<String>,
}

/// Classification of a Surface Exposure Score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreClassification {
    /// Few detected exposure concerns.
    Favorable,
    /// Detected concerns merit review.
    Review,
    /// Material detected exposure concerns.
    Elevated,
    /// Severe detected exposure concerns.
    Critical,
}

/// Versioned score derived only from report observations and findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureScore {
    /// Score model version.
    pub model_version: String,
    /// Score from zero to one hundred; higher means fewer detected concerns.
    pub value: u8,
    /// Coarse presentation classification.
    pub classification: ScoreClassification,
    /// Sorted, explicit deductions.
    pub deductions: Vec<ScoreDeduction>,
    /// Whether scan incompleteness limits interpretation.
    pub incomplete: bool,
    /// Stable limitations applying to this score.
    pub limitations: Vec<String>,
}

/// Calculates the deterministic Surface Exposure Score.
#[must_use]
pub fn calculate_exposure(report: &ScanReport) -> ExposureScore {
    let mut seen = BTreeSet::new();
    let mut deductions = report
        .findings
        .iter()
        .filter_map(|finding| {
            let key = (finding.id.clone(), finding.target.clone());
            if !seen.insert(key) {
                return None;
            }
            let points = severity_points(finding.severity);
            (points > 0).then(|| ScoreDeduction {
                id: format!("finding:{}:{}", finding.id, finding.target),
                points,
                reason: finding.title.clone(),
                finding_ids: vec![finding.id.clone()],
                target: Some(finding.target.clone()),
            })
        })
        .collect::<Vec<_>>();
    deductions.sort_by(|left, right| left.id.cmp(&right.id));
    let total = deductions
        .iter()
        .fold(0_u16, |sum, deduction| {
            sum.saturating_add(u16::from(deduction.points))
        })
        .min(100);
    let value = 100_u8.saturating_sub(u8::try_from(total).unwrap_or(100));
    let incomplete = report.status != ScanStatus::Completed;
    let mut limitations =
        vec!["This configuration and exposure score is not proof of security.".to_owned()];
    if incomplete {
        limitations.push(
            "The scan was incomplete; absent observations were not treated as safe.".to_owned(),
        );
    }
    ExposureScore {
        model_version: EXPOSURE_MODEL_VERSION.to_owned(),
        value,
        classification: classification(value),
        deductions,
        incomplete,
        limitations,
    }
}

const fn severity_points(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 2,
        Severity::Medium => 7,
        Severity::High => 20,
        Severity::Critical => 35,
    }
}

const fn classification(value: u8) -> ScoreClassification {
    match value {
        85..=100 => ScoreClassification::Favorable,
        65..=84 => ScoreClassification::Review,
        35..=64 => ScoreClassification::Elevated,
        _ => ScoreClassification::Critical,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        normalize_target, Finding, FindingCategory, FindingConfidence, ScanConfiguration,
        ScanReport, ScanStatus, Severity,
    };

    use super::calculate_exposure;

    fn report() -> ScanReport {
        ScanReport::not_started(
            normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![443],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        )
    }

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding {
            id: id.to_owned(),
            title: id.to_owned(),
            severity,
            category: FindingCategory::Network,
            target: "example.com".to_owned(),
            description: String::new(),
            evidence: Vec::new(),
            remediation: None,
            references: Vec::new(),
            confidence: FindingConfidence::High,
        }
    }

    #[test]
    fn score_is_stable_deduplicated_and_incomplete() {
        let mut report = report();
        report.status = ScanStatus::Partial;
        report.findings = vec![
            finding("SURFACE-X", Severity::High),
            finding("SURFACE-X", Severity::High),
            finding("SURFACE-Y", Severity::Low),
        ];

        let score = calculate_exposure(&report);
        assert_eq!(score.value, 78);
        assert_eq!(score.deductions.len(), 2);
        assert!(score.incomplete);
        assert_eq!(score, calculate_exposure(&report));
    }

    #[test]
    fn score_clamps_at_zero() {
        let mut report = report();
        report.status = ScanStatus::Completed;
        report.findings = (0..4)
            .map(|index| finding(&format!("SURFACE-C-{index}"), Severity::Critical))
            .collect();

        assert_eq!(calculate_exposure(&report).value, 0);
    }
}
