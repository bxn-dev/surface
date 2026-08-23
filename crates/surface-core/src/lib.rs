//! Core models and input parsing for Surface scans.

mod dns;
mod engine;
mod exposure;
mod findings;
mod http;
mod ports;
mod scanner;
mod service;
mod target;
mod tls;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[doc(inline)]
pub use dns::{
    AddressSource, DmarcObservation, DnsObservation, DnsRecord, MailObservation, ResolvedHost,
    SpfObservation, analyze_dns, interpret_mail,
};
#[doc(inline)]
pub use engine::run_scan;
#[doc(inline)]
pub use exposure::{
    EXPOSURE_MODEL_VERSION, ExposureScore, ScoreClassification, ScoreDeduction, calculate_exposure,
};
#[doc(inline)]
pub use findings::{
    Evidence, Finding, FindingCategory, FindingConfidence, Severity, generate_findings,
};
#[doc(inline)]
pub use http::{CookieObservation, HttpObservation, RedirectObservation, analyze_http};
#[doc(inline)]
pub use ports::{PortSelection, PortSpecError, parse_ports};
#[doc(inline)]
pub use scanner::{HostObservation, PortObservation, PortState, scan_ports};
#[doc(inline)]
pub use service::{
    DetectionConfidence, ServiceKind, ServiceObservation, detect_services, sanitize_banner,
};
#[doc(inline)]
pub use target::{NormalizedTarget, TargetError, normalize_target};
#[doc(inline)]
pub use tls::{TlsObservation, analyze_tls};

// Rust guideline compliant 2026-02-21

/// Describes whether meaningful scanning work occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// No scanning stage has started.
    NotStarted,
    /// All scheduled stages completed.
    Completed,
    /// Some stages failed while useful observations remain.
    Partial,
    /// The operator interrupted the scan.
    Interrupted,
    /// No meaningful report could be produced.
    Failed,
}

/// Identifies a planned scanner stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStage {
    /// Passive DNS collection.
    Dns,
    /// TCP connect scanning.
    Ports,
    /// Safe service identification.
    Services,
    /// HTTP endpoint analysis.
    Http,
    /// TLS endpoint analysis.
    Tls,
    /// Finding generation.
    Findings,
}

/// Categorizes a reportable scanner error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanErrorKind {
    /// DNS query failure.
    Dns,
    /// Operation deadline exceeded.
    Timeout,
    /// Network operation failure.
    Network,
    /// HTTP protocol failure.
    Http,
    /// TLS handshake or validation failure.
    Tls,
    /// Operator cancellation.
    Cancelled,
    /// Required authorization acknowledgement was absent.
    Authorization,
    /// Output or internal orchestration failure.
    Other,
}

/// A bounded, serializable stage error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanError {
    /// Stage that produced the error.
    pub stage: ScanStage,
    /// Affected target when available.
    pub target: Option<String>,
    /// Stable error category.
    pub kind: ScanErrorKind,
    /// Concise diagnostic without debug traces.
    pub message: String,
    /// Whether other scan work may continue.
    pub recoverable: bool,
}

impl ScanError {
    /// Creates a reportable scanner error.
    #[must_use]
    pub fn new(
        stage: ScanStage,
        target: Option<String>,
        kind: ScanErrorKind,
        message: impl Into<String>,
        recoverable: bool,
    ) -> Self {
        Self {
            stage,
            target,
            kind,
            message: message.into(),
            recoverable,
        }
    }
}

/// Records implementation state without fabricating observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageState {
    /// Planned stage.
    pub stage: ScanStage,
    /// Whether this release implements the stage.
    pub implemented: bool,
}

/// Captures effective Phase 1 scan settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfiguration {
    /// Sorted TCP ports selected by the user.
    pub ports: Vec<u16>,
    /// Maximum simultaneous TCP connections.
    pub concurrency: usize,
    /// Per-connection timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Per-request timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// Whole-scan timeout in milliseconds.
    pub global_timeout_ms: u64,
    /// Whether only IPv4 results should later be used.
    pub ipv4_only: bool,
    /// Whether only IPv6 results should later be used.
    pub ipv6_only: bool,
    /// Whether authorization was explicitly acknowledged.
    pub authorization_acknowledged: bool,
}

/// Contains versioned output shared by all report renderers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Report schema version.
    pub schema_version: String,
    /// Surface package version.
    pub scanner_version: String,
    /// Unique scan identifier.
    pub scan_id: Uuid,
    /// Scan construction timestamp.
    pub started_at: OffsetDateTime,
    /// Completion timestamp when execution ended.
    pub completed_at: Option<OffsetDateTime>,
    /// Normalized target metadata.
    pub target: NormalizedTarget,
    /// Effective scan settings.
    pub configuration: ScanConfiguration,
    /// Current scan lifecycle state.
    pub status: ScanStatus,
    /// Explicit state for each future stage.
    pub stages: Vec<StageState>,
    /// Passive DNS observations when that stage ran.
    pub dns: Option<DnsObservation>,
    /// Deterministic TCP observations by address.
    pub hosts: Vec<HostObservation>,
    /// Bounded protocol-identification observations.
    pub services: Vec<ServiceObservation>,
    /// Bounded HTTP endpoint observations.
    pub http: Vec<HttpObservation>,
    /// Validating TLS handshake observations.
    pub tls: Vec<TlsObservation>,
    /// Evidence-backed interpreted findings.
    pub findings: Vec<Finding>,
    /// Versioned explainable exposure score when findings were generated.
    #[serde(default)]
    pub exposure_score: Option<ExposureScore>,
    /// Partial errors retained across stages.
    pub errors: Vec<ScanError>,
    /// Human-readable explanation of the lifecycle state.
    pub message: String,
}

impl ScanReport {
    /// Creates a report that explicitly records no scanning activity.
    #[must_use]
    pub fn not_started(target: NormalizedTarget, configuration: ScanConfiguration) -> Self {
        const STAGES: [ScanStage; 6] = [
            ScanStage::Dns,
            ScanStage::Ports,
            ScanStage::Services,
            ScanStage::Http,
            ScanStage::Tls,
            ScanStage::Findings,
        ];

        Self {
            schema_version: "0.1.1".to_owned(),
            scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
            scan_id: Uuid::new_v4(),
            started_at: OffsetDateTime::now_utc(),
            completed_at: None,
            target,
            configuration,
            status: ScanStatus::NotStarted,
            stages: STAGES
                .into_iter()
                .map(|stage| StageState {
                    stage,
                    implemented: true,
                })
                .collect(),
            dns: None,
            hosts: Vec::new(),
            services: Vec::new(),
            http: Vec::new(),
            tls: Vec::new(),
            findings: Vec::new(),
            exposure_score: None,
            errors: Vec::new(),
            message:
                "Surface repository initialized. Scanning functionality is not implemented yet."
                    .to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanConfiguration, ScanReport, ScanStatus, normalize_target};

    #[test]
    fn placeholder_report_cannot_imply_scan_completion() {
        let target = normalize_target("example.com").unwrap_or_else(|error| panic!("{error}"));
        let report = ScanReport::not_started(
            target,
            ScanConfiguration {
                ports: vec![80, 443],
                concurrency: 64,
                connect_timeout_ms: 1_500,
                request_timeout_ms: 5_000,
                global_timeout_ms: 300_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        );

        assert_eq!(report.status, ScanStatus::NotStarted);
        assert!(report.stages.iter().any(|stage| stage.implemented));
        assert!(report.dns.is_none());
        assert!(report.message.contains("not implemented"));
    }
}
