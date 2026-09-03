//! Core models and input parsing for Surface scans.

mod dns;
mod engine;
mod exposure;
mod findings;
mod http;
mod intelligence;
mod passive_http;
mod ports;
mod scanner;
mod service;
mod ssh;
mod target;
mod tls;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[doc(inline)]
pub use dns::{
    AddressSource, AuthoritativeAxfrObservation, AxfrAttempt, AxfrLimits, AxfrOutcome, CnameHop,
    DanglingCnameObservation, DanglingCnameStatus, DmarcObservation, DnsObservation, DnsRecord,
    DnssecObservation, DnssecRecordType, DnssecRrsetObservation, DnssecStatus, MailObservation,
    ResolvedHost, SpfObservation, WildcardDnsObservation, WildcardDnsRecordType, WildcardDnsStatus,
    analyze_dns, interpret_mail, lookup_txt,
};
#[doc(inline)]
pub use engine::{
    run_scan, run_scan_selected_until_with_progress, run_scan_selected_with_progress,
    run_scan_with_progress,
};
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
pub use intelligence::{
    BgpRouteObservation, CertificateTransparencyCandidate, CertificateTransparencyObservation,
    CveCandidate, DkimObservation, IntelligenceBundle, IntelligenceObservation, NetworkEntry,
    NetworkMetadata, NetworkRegistrationObservation, RelatedDomainCandidate,
    RelatedDomainsObservation, SubdomainObservation, VulnerabilityEntry, analyze_bgp_routes,
    analyze_certificate_transparency, analyze_intelligence, analyze_network_registrations,
    analyze_related_domains, parse_bundle,
};
#[doc(inline)]
pub use ports::{PortSelection, PortSpecError, parse_ports, parse_udp_ports};
#[doc(inline)]
pub use scanner::{
    HostObservation, PortObservation, PortState, TransportProtocol, scan_ports, scan_udp_ports,
};
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
    /// TCP connect and UDP response scanning.
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

/// Reports a scanner stage transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProgress {
    /// A stage started.
    Started(ScanStage),
    /// A stage completed with its primary observation count.
    Completed {
        /// Completed stage.
        stage: ScanStage,
        /// Number of primary observations produced by the stage.
        observations: usize,
    },
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
    /// A destination was rejected by an execution policy.
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

/// Captures effective Phase 1 scan settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfiguration {
    /// Sorted TCP ports selected by the user.
    pub ports: Vec<u16>,
    /// Sorted UDP ports selected by the user.
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    /// Maximum simultaneous network probes.
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
    /// Compatibility field retained for report schema 0.3.0; new scans always set this true.
    pub authorization_acknowledged: bool,
}

/// Selects active scan stages; dependencies are included automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "stage switches directly represent the selected scan groups"
)]
pub struct ScanSelection {
    pub(crate) ports: bool,
    pub(crate) services: bool,
    pub(crate) http: bool,
    pub(crate) tls: bool,
}

impl ScanSelection {
    /// Selects every built-in active scan stage.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            ports: true,
            services: true,
            http: true,
            tls: true,
        }
    }

    /// Selects stages and their required prerequisites.
    #[must_use]
    pub fn only(stages: &[ScanStage]) -> Self {
        let http = stages.contains(&ScanStage::Http);
        let tls = stages.contains(&ScanStage::Tls);
        let services = stages.contains(&ScanStage::Services) || http || tls;
        let ports = stages.contains(&ScanStage::Ports) || services;
        Self {
            ports,
            services,
            http,
            tls,
        }
    }
}

impl Default for ScanSelection {
    fn default() -> Self {
        Self::all()
    }
}

/// One intentionally omitted check and its reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedCheck {
    /// Stable check identifier.
    pub check: String,
    /// Human-readable reason.
    pub reason: String,
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
    /// Optional explicitly supplied passive and offline intelligence.
    #[serde(default)]
    pub intelligence: Option<IntelligenceObservation>,
    /// Checks omitted by selection, unavailable input, or missing credentials.
    #[serde(default)]
    pub skipped_checks: Vec<SkippedCheck>,
    /// Partial errors retained across stages.
    pub errors: Vec<ScanError>,
    /// Human-readable explanation of the lifecycle state.
    pub message: String,
}

impl ScanReport {
    /// Creates a report that explicitly records no scanning activity.
    #[must_use]
    pub fn not_started(target: NormalizedTarget, configuration: ScanConfiguration) -> Self {
        Self {
            schema_version: "0.3.0".to_owned(),
            scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
            scan_id: Uuid::new_v4(),
            started_at: OffsetDateTime::now_utc(),
            completed_at: None,
            target,
            configuration,
            status: ScanStatus::NotStarted,
            dns: None,
            hosts: Vec::new(),
            services: Vec::new(),
            http: Vec::new(),
            tls: Vec::new(),
            findings: Vec::new(),
            exposure_score: None,
            intelligence: None,
            skipped_checks: Vec::new(),
            errors: Vec::new(),
            message: "Scan has not started.".to_owned(),
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
                udp_ports: vec![53],
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
        assert!(report.dns.is_none());
        assert_eq!(report.message, "Scan has not started.");
    }
}
