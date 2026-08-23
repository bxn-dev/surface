//! Deterministic semantic comparison of Surface scan reports.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use surface_core::{PortState, ScanReport};

use super::escape_html;

// Rust guideline compliant 2026-02-21

/// Current scan-diff schema version.
pub const DIFF_SCHEMA_VERSION: &str = "1.0";

/// Identifies one side of a scan comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReference {
    /// Scan identifier.
    pub scan_id: String,
    /// Report schema version.
    pub schema_version: String,
    /// Scanner version.
    pub scanner_version: String,
    /// Normalized target identity.
    pub target: String,
}

/// Summary counts for a semantic diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Number of additions.
    pub added: usize,
    /// Number of removals.
    pub removed: usize,
    /// Number of changed observations.
    pub changed: usize,
}

/// One deterministic semantic change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Stable category.
    pub category: String,
    /// Stable comparison key.
    pub key: String,
    /// Previous value for removals or modifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<Value>,
    /// New value for additions or modifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<Value>,
    /// Affected target context.
    pub target: String,
    /// Conservative significance classification.
    pub significance: String,
    /// Confidence in the comparison.
    pub confidence: String,
    /// Concise evidence identity.
    pub evidence: String,
}

/// Structured deterministic comparison between compatible reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDiff {
    /// Diff schema version.
    pub schema_version: String,
    /// Earlier scan.
    pub old_scan: ScanReference,
    /// Later scan.
    pub new_scan: ScanReference,
    /// Aggregate counts.
    pub summary: DiffSummary,
    /// IP and port changes.
    pub network_changes: Vec<Change>,
    /// Service and HTTP changes.
    pub service_changes: Vec<Change>,
    /// Certificate changes.
    pub certificate_changes: Vec<Change>,
    /// DNS and mail-policy changes.
    pub dns_changes: Vec<Change>,
    /// Finding changes.
    pub finding_changes: Vec<Change>,
    /// Exposure-score changes.
    pub score_change: Option<Change>,
    /// Scan lifecycle/completeness changes.
    pub completeness_changes: Vec<Change>,
    /// Compatibility or interpretation warnings.
    pub warnings: Vec<String>,
}

/// Reports incompatible scan inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffError(String);

impl std::fmt::Display for DiffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DiffError {}

/// Compares two compatible reports without considering volatile fields.
///
/// # Errors
///
/// Returns an error when normalized targets or schema families differ.
pub fn diff_reports(old: &ScanReport, new: &ScanReport) -> Result<ScanDiff, DiffError> {
    let old_target = old.target.identity();
    let new_target = new.target.identity();
    if old_target != new_target {
        return Err(DiffError(format!(
            "cannot compare different targets '{old_target}' and '{new_target}'"
        )));
    }
    ensure_schema_supported(&old.schema_version)?;
    ensure_schema_supported(&new.schema_version)?;

    let network_changes = network_changes(old, new, &old_target);
    let service_changes = service_changes(old, new, &old_target);
    let certificate_changes = compare_maps(
        "certificate",
        tls_map(old),
        tls_map(new),
        &old_target,
        "high",
    );
    let dns_changes = dns_changes(old, new, &old_target);
    let finding_changes = compare_maps(
        "finding",
        finding_map(old),
        finding_map(new),
        &old_target,
        "high",
    );
    let completeness_changes = completeness_changes(old, new, &old_target);
    let mut warnings = Vec::new();
    let score_change = score_change(old, new, &old_target, &mut warnings);
    let all = network_changes
        .iter()
        .chain(&service_changes)
        .chain(&certificate_changes)
        .chain(&dns_changes)
        .chain(&finding_changes)
        .chain(&completeness_changes)
        .chain(score_change.iter());
    let mut summary = DiffSummary {
        added: 0,
        removed: 0,
        changed: 0,
    };
    for change in all {
        match (&change.old_value, &change.new_value) {
            (None, Some(_)) => summary.added += 1,
            (Some(_), None) => summary.removed += 1,
            _ => summary.changed += 1,
        }
    }

    Ok(ScanDiff {
        schema_version: DIFF_SCHEMA_VERSION.to_owned(),
        old_scan: reference(old, old_target.clone()),
        new_scan: reference(new, new_target),
        summary,
        network_changes,
        service_changes,
        certificate_changes,
        dns_changes,
        finding_changes,
        score_change,
        completeness_changes,
        warnings,
    })
}

/// Serializes a structured diff as deterministic pretty JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn render_diff_json(diff: &ScanDiff) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(diff)
}

/// Renders a concise terminal diff.
#[must_use]
pub fn render_diff_terminal(diff: &ScanDiff) -> String {
    let mut output = format!(
        "Surface scan diff\nOld: {}\nNew: {}\nTarget: {}\n\n",
        diff.old_scan.scan_id, diff.new_scan.scan_id, diff.new_scan.target
    );
    let sections = [
        ("Network", &diff.network_changes),
        ("Services and HTTP", &diff.service_changes),
        ("Certificates", &diff.certificate_changes),
        ("DNS and mail", &diff.dns_changes),
        ("Findings", &diff.finding_changes),
        ("Completeness", &diff.completeness_changes),
    ];
    for (title, changes) in sections {
        if changes.is_empty() {
            continue;
        }
        output.push_str(title);
        output.push('\n');
        for change in changes {
            let marker = match (&change.old_value, &change.new_value) {
                (None, Some(_)) => '+',
                (Some(_), None) => '-',
                _ => '~',
            };
            let _ = writeln!(output, "  {marker} {} {}", change.category, change.key);
        }
        output.push('\n');
    }
    if let Some(change) = &diff.score_change {
        let _ = writeln!(output, "Exposure score changed: {}", change.evidence);
    }
    for warning in &diff.warnings {
        let _ = writeln!(output, "Warning: {warning}");
    }
    if diff.summary.added == 0 && diff.summary.removed == 0 && diff.summary.changed == 0 {
        output.push_str("No semantic changes.\n");
    }
    output
}

/// Renders a self-contained escaped HTML diff.
#[must_use]
#[expect(
    clippy::format_collect,
    reason = "bounded deterministic change rows keep the escaped HTML template direct"
)]
pub fn render_diff_html(diff: &ScanDiff) -> String {
    let changes = diff
        .network_changes
        .iter()
        .chain(&diff.service_changes)
        .chain(&diff.certificate_changes)
        .chain(&diff.dns_changes)
        .chain(&diff.finding_changes)
        .chain(&diff.completeness_changes)
        .chain(diff.score_change.iter())
        .map(|change| {
            let operation = match (&change.old_value, &change.new_value) {
                (None, Some(_)) => "added",
                (Some(_), None) => "removed",
                _ => "changed",
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(operation),
                escape_html(&change.category),
                escape_html(&change.key),
                escape_html(&change.significance),
            )
        })
        .collect::<String>();
    let rows = if changes.is_empty() {
        "<tr><td colspan=\"4\">No semantic changes.</td></tr>".to_owned()
    } else {
        changes
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Surface scan diff</title><style>body{{font:16px system-ui;max-width:70rem;margin:2rem auto;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}th,td{{padding:.5rem;border-bottom:1px solid #888;text-align:left}}code{{overflow-wrap:anywhere}}</style></head><body><main><h1>Surface scan diff</h1><p><strong>Target:</strong> <code>{}</code></p><p><strong>Old:</strong> <code>{}</code><br><strong>New:</strong> <code>{}</code></p><table><thead><tr><th>Operation</th><th>Category</th><th>Key</th><th>Significance</th></tr></thead><tbody>{rows}</tbody></table><p>Changes are externally observed differences, not proof of compromise or security.</p></main></body></html>\n",
        escape_html(&diff.new_scan.target),
        escape_html(&diff.old_scan.scan_id),
        escape_html(&diff.new_scan.scan_id),
    )
}

fn ensure_schema_supported(version: &str) -> Result<(), DiffError> {
    if matches!(version, "0.1.0" | "0.1.1" | "0.1.2" | "0.2.0" | "0.3.0") {
        Ok(())
    } else {
        Err(DiffError(format!(
            "unsupported report schema version '{version}'"
        )))
    }
}

fn reference(report: &ScanReport, target: String) -> ScanReference {
    ScanReference {
        scan_id: report.scan_id.to_string(),
        schema_version: report.schema_version.clone(),
        scanner_version: report.scanner_version.clone(),
        target,
    }
}

fn network_changes(old: &ScanReport, new: &ScanReport, target: &str) -> Vec<Change> {
    let old_ips = old.hosts.iter().map(|host| host.ip.to_string()).collect();
    let new_ips = new.hosts.iter().map(|host| host.ip.to_string()).collect();
    let mut changes = compare_sets("ip_address", old_ips, new_ips, target, "medium");
    changes.extend(compare_maps(
        "port",
        port_map(old),
        port_map(new),
        target,
        "medium",
    ));
    sort_changes(&mut changes);
    changes
}

fn service_changes(old: &ScanReport, new: &ScanReport, target: &str) -> Vec<Change> {
    let service_map = |report: &ScanReport| {
        report
            .services
            .iter()
            .map(|service| {
                let value = serde_json::json!({
                    "transport": service.transport,
                    "service": service.service,
                    "confidence": service.confidence,
                    "banner": service.banner,
                    "protocol_details": service.protocol_details,
                });
                (
                    format!("{:?}:{}", service.transport, service.address).to_ascii_lowercase(),
                    value,
                )
            })
            .collect()
    };
    let mut changes = compare_maps(
        "service",
        service_map(old),
        service_map(new),
        target,
        "medium",
    );
    changes.extend(compare_maps(
        "http_endpoint",
        http_map(old),
        http_map(new),
        target,
        "medium",
    ));
    sort_changes(&mut changes);
    changes
}

fn dns_changes(old: &ScanReport, new: &ScanReport, target: &str) -> Vec<Change> {
    let old_records = old
        .dns
        .as_ref()
        .map(|dns| dns.records.iter().filter_map(json_key).collect())
        .unwrap_or_default();
    let new_records = new
        .dns
        .as_ref()
        .map(|dns| dns.records.iter().filter_map(json_key).collect())
        .unwrap_or_default();
    let mut changes = compare_sets("dns_record", old_records, new_records, target, "medium");
    let old_mail = old
        .dns
        .as_ref()
        .and_then(|dns| serde_json::to_value(&dns.mail).ok());
    let new_mail = new
        .dns
        .as_ref()
        .and_then(|dns| serde_json::to_value(&dns.mail).ok());
    if old_mail != new_mail {
        changes.push(change(
            "mail_policy",
            target,
            old_mail,
            new_mail,
            target,
            "high",
        ));
    }
    let old_intelligence = old
        .intelligence
        .as_ref()
        .and_then(|value| serde_json::to_value(value).ok());
    let new_intelligence = new
        .intelligence
        .as_ref()
        .and_then(|value| serde_json::to_value(value).ok());
    if old_intelligence != new_intelligence {
        changes.push(change(
            "passive_intelligence",
            target,
            old_intelligence,
            new_intelligence,
            target,
            "medium",
        ));
    }
    sort_changes(&mut changes);
    changes
}

fn sort_changes(changes: &mut [Change]) {
    changes.sort_by(|left, right| (&left.category, &left.key).cmp(&(&right.category, &right.key)));
}

fn completeness_changes(old: &ScanReport, new: &ScanReport, target: &str) -> Vec<Change> {
    let old_value = serde_json::json!({
        "status": old.status,
        "error_kinds": old.errors.iter().filter_map(|error| json_key(&error.kind)).collect::<BTreeSet<_>>(),
    });
    let new_value = serde_json::json!({
        "status": new.status,
        "error_kinds": new.errors.iter().filter_map(|error| json_key(&error.kind)).collect::<BTreeSet<_>>(),
    });
    (old_value != new_value)
        .then(|| {
            change(
                "scan_completeness",
                target,
                Some(old_value),
                Some(new_value),
                target,
                "high",
            )
        })
        .into_iter()
        .collect()
}

fn score_change(
    old: &ScanReport,
    new: &ScanReport,
    target: &str,
    warnings: &mut Vec<String>,
) -> Option<Change> {
    match (&old.exposure_score, &new.exposure_score) {
        (Some(old_score), Some(new_score))
            if old_score.model_version == new_score.model_version =>
        {
            (old_score != new_score).then(|| {
                change(
                    "exposure_score",
                    target,
                    serde_json::to_value(old_score).ok(),
                    serde_json::to_value(new_score).ok(),
                    target,
                    "high",
                )
            })
        }
        (Some(old_score), Some(new_score)) => {
            warnings.push(format!(
                "score models differ: {} versus {}; no numeric delta is claimed",
                old_score.model_version, new_score.model_version
            ));
            None
        }
        (None, None) => None,
        (old_score, new_score) => Some(change(
            "exposure_score",
            target,
            old_score
                .as_ref()
                .and_then(|value| serde_json::to_value(value).ok()),
            new_score
                .as_ref()
                .and_then(|value| serde_json::to_value(value).ok()),
            target,
            "high",
        )),
    }
}

fn port_map(report: &ScanReport) -> BTreeMap<String, Value> {
    report
        .hosts
        .iter()
        .flat_map(|host| &host.ports)
        .map(|port| {
            (
                format!("{:?}:{}", port.transport, port.address).to_ascii_lowercase(),
                Value::String(
                    match port.state {
                        PortState::Open => "open",
                        PortState::Closed => "closed",
                        PortState::OpenFiltered => "open_filtered",
                        PortState::TimedOut => "timed_out",
                        PortState::Unreachable => "unreachable",
                        PortState::Error => "error",
                        PortState::Cancelled => "cancelled",
                    }
                    .to_owned(),
                ),
            )
        })
        .collect()
}

fn http_map(report: &ScanReport) -> BTreeMap<String, Value> {
    report
        .http
        .iter()
        .map(|http| {
            let value = serde_json::json!({
                "final_url": http.final_url,
                "status": http.status,
                "redirects": http.redirects,
                "headers": http.headers,
                "cookies": http.cookies,
                "robots_txt": http.robots_txt,
                "security_txt": http.security_txt,
                "sitemap_xml": http.sitemap_xml,
                "error": http.error,
            });
            (http.url.clone(), value)
        })
        .collect()
}

fn tls_map(report: &ScanReport) -> BTreeMap<String, Value> {
    report
        .tls
        .iter()
        .map(|tls| {
            let value = serde_json::json!({
                "server_name": tls.server_name,
                "handshake_succeeded": tls.handshake_succeeded,
                "certificate_trusted": tls.certificate_trusted,
                "hostname_matches": tls.hostname_matches,
                "protocol_version": tls.protocol_version,
                "alpn": tls.alpn,
                "subject": tls.subject,
                "issuer": tls.issuer,
                "serial_number": tls.serial_number,
                "valid_from_unix": tls.valid_from_unix,
                "valid_until_unix": tls.valid_until_unix,
                "subject_alt_names": tls.subject_alt_names,
                "public_key_algorithm": tls.public_key_algorithm,
                "signature_algorithm": tls.signature_algorithm,
            });
            (format!("{}|{}", tls.address, tls.server_name), value)
        })
        .collect()
}

fn finding_map(report: &ScanReport) -> BTreeMap<String, Value> {
    report
        .findings
        .iter()
        .map(|finding| {
            let value = serde_json::json!({
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "description": finding.description,
                "evidence_locations": finding.evidence.iter().map(|item| &item.location).collect::<BTreeSet<_>>(),
                "remediation": finding.remediation,
                "references": finding.references,
                "confidence": finding.confidence,
            });
            let locations = finding
                .evidence
                .iter()
                .map(|item| &item.location)
                .collect::<BTreeSet<_>>();
            (
                format!(
                    "{}|{}|{}",
                    finding.id,
                    finding.target,
                    serde_json::to_string(&locations).unwrap_or_default()
                ),
                value,
            )
        })
        .collect()
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "callers transfer short-lived normalized maps into one comparison"
)]
fn compare_maps(
    category: &str,
    old: BTreeMap<String, Value>,
    new: BTreeMap<String, Value>,
    target: &str,
    significance: &str,
) -> Vec<Change> {
    old.keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|key| {
            let old_value = old.get(key).cloned();
            let new_value = new.get(key).cloned();
            (old_value != new_value)
                .then(|| change(category, key, old_value, new_value, target, significance))
        })
        .collect()
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "callers transfer short-lived normalized sets into one comparison"
)]
fn compare_sets(
    category: &str,
    old: BTreeSet<String>,
    new: BTreeSet<String>,
    target: &str,
    significance: &str,
) -> Vec<Change> {
    let removed = old.difference(&new).map(|key| {
        change(
            category,
            key,
            Some(Value::String(key.clone())),
            None,
            target,
            significance,
        )
    });
    let added = new.difference(&old).map(|key| {
        change(
            category,
            key,
            None,
            Some(Value::String(key.clone())),
            target,
            significance,
        )
    });
    removed.chain(added).collect()
}

fn change(
    category: &str,
    key: &str,
    old_value: Option<Value>,
    new_value: Option<Value>,
    target: &str,
    significance: &str,
) -> Change {
    Change {
        category: category.to_owned(),
        key: key.to_owned(),
        old_value,
        new_value,
        target: target.to_owned(),
        significance: significance.to_owned(),
        confidence: "high".to_owned(),
        evidence: key.to_owned(),
    }
}

fn json_key(value: &impl Serialize) -> Option<String> {
    serde_json::to_string(value).ok()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use surface_core::{
        normalize_target, Evidence, Finding, FindingCategory, FindingConfidence, HostObservation,
        PortObservation, PortState, ScanConfiguration, ScanError, ScanErrorKind, ScanReport,
        ScanStage, ScanStatus, Severity, TransportProtocol,
    };

    use super::{diff_reports, render_diff_json};

    fn report() -> ScanReport {
        let mut report = ScanReport::not_started(
            normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![80],
                udp_ports: Vec::new(),
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        );
        report.status = ScanStatus::Completed;
        report
    }

    #[test]
    fn ignores_volatile_fields_and_detects_port_state_changes() {
        let mut old = report();
        let mut new = report();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        old.hosts = vec![HostObservation {
            ip: address.ip(),
            ports: vec![PortObservation {
                transport: TransportProtocol::Tcp,
                address,
                state: PortState::Closed,
                latency_ms: Some(1),
                error: None,
            }],
        }];
        new.hosts = vec![HostObservation {
            ip: address.ip(),
            ports: vec![PortObservation {
                transport: TransportProtocol::Tcp,
                address,
                state: PortState::Open,
                latency_ms: Some(999),
                error: None,
            }],
        }];

        let diff = diff_reports(&old, &new).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(diff.network_changes.len(), 1);
        assert_eq!(diff.summary.changed, 1);
        assert_eq!(
            render_diff_json(&diff).unwrap_or_else(|error| panic!("{error}")),
            render_diff_json(&diff).unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[test]
    fn ignores_finding_evidence_values_and_error_order() {
        let mut old = report();
        let mut new = report();
        let finding = |observed: &str| Finding {
            id: "TLS-CERTIFICATE-EXPIRING".to_owned(),
            title: "Certificate expires soon".to_owned(),
            severity: Severity::Medium,
            category: FindingCategory::Tls,
            target: "example.com".to_owned(),
            description: "Certificate validity requires review.".to_owned(),
            evidence: vec![Evidence {
                location: "remaining_days".to_owned(),
                observed: observed.to_owned(),
            }],
            remediation: Some("Renew the certificate.".to_owned()),
            references: Vec::new(),
            confidence: FindingConfidence::High,
        };
        let mut old_endpoint = finding("20");
        old_endpoint.evidence[0].location = "endpoint-b/remaining_days".to_owned();
        let mut new_endpoint = old_endpoint.clone();
        new_endpoint.severity = Severity::High;
        old.findings = vec![finding("29"), old_endpoint];
        new.findings = vec![finding("28"), new_endpoint];
        old.errors = vec![
            ScanError::new(ScanStage::Tls, None, ScanErrorKind::Tls, "first", true),
            ScanError::new(ScanStage::Http, None, ScanErrorKind::Http, "second", true),
        ];
        new.errors = vec![
            ScanError::new(ScanStage::Http, None, ScanErrorKind::Http, "changed", true),
            ScanError::new(ScanStage::Tls, None, ScanErrorKind::Tls, "changed", true),
            ScanError::new(ScanStage::Tls, None, ScanErrorKind::Tls, "duplicate", true),
        ];

        let diff = diff_reports(&old, &new).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(diff.finding_changes.len(), 1);
        assert!(diff.completeness_changes.is_empty());
    }

    #[test]
    fn identical_semantics_produce_empty_diff() {
        let old = report();
        let new = report();

        let diff = diff_reports(&old, &new).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            diff.summary.added + diff.summary.removed + diff.summary.changed,
            0
        );
    }
}
