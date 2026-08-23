//! Deterministic terminal, JSON, HTML, diff, and integration reports.

mod diff;
mod exports;
mod signing;

use std::fmt::Write;

use surface_core::{PortState, ScanReport, Severity};

#[doc(inline)]
pub use diff::{
    diff_reports, render_diff_html, render_diff_json, render_diff_terminal, Change, DiffError,
    DiffSummary, ScanDiff, ScanReference, DIFF_SCHEMA_VERSION,
};
#[doc(inline)]
pub use exports::{render_cyclonedx, render_sarif};
pub use signing::{decode_key, sign_bytes, verify_bytes, SignatureEnvelope, VerificationError};

// Rust guideline compliant 2026-02-21

/// Renders a report as human-readable plain text.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "linear report sections keep presentation deterministic"
)]
pub fn render_terminal(report: &ScanReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Surface {}", report.scanner_version);
    let _ = writeln!(
        output,
        "Target: {}",
        clean_terminal(&report.target.original)
    );
    let _ = writeln!(output, "Started: {}", report.started_at);
    let _ = writeln!(output, "Status: {:?}\n", report.status);

    if let Some(dns) = &report.dns {
        let _ = writeln!(output, "DNS");
        for record in &dns.records {
            let _ = writeln!(output, "  {record:?}");
        }
        let _ = writeln!(output, "  SPF records: {}", dns.mail.spf.records.len());
        let _ = writeln!(output, "  DMARC records: {}\n", dns.mail.dmarc.len());
    }

    if !report.hosts.is_empty() {
        let _ = writeln!(output, "Hosts");
        for host in &report.hosts {
            let _ = writeln!(output, "  {}", host.ip);
            for port in host.ports.iter().filter(|port| {
                port.state == PortState::Open
                    || (port.state == PortState::OpenFiltered
                        && report.services.iter().any(|service| {
                            service.address == port.address && service.transport == port.transport
                        }))
            }) {
                let service = report
                    .services
                    .iter()
                    .find(|service| {
                        service.address == port.address && service.transport == port.transport
                    })
                    .map_or_else(
                        || "unknown".to_owned(),
                        |service| service.service.to_string(),
                    );
                let state = if port.state == PortState::Open {
                    "open"
                } else {
                    "open|filtered"
                };
                let _ = writeln!(
                    output,
                    "    {}/{}  {state}  {service}",
                    port.address.port(),
                    port.transport.as_str()
                );
            }
        }
        output.push('\n');
    }

    if !report.http.is_empty() {
        let _ = writeln!(output, "HTTP");
        for http in &report.http {
            let _ = writeln!(
                output,
                "  {}  status={}  HSTS={}  security.txt={}",
                clean_terminal(&http.url),
                http.status
                    .map_or_else(|| "error".to_owned(), |status| status.to_string()),
                if http.headers.contains_key("strict-transport-security") {
                    "present"
                } else {
                    "missing"
                },
                option_bool(http.security_txt),
            );
        }
        output.push('\n');
    }

    if !report.tls.is_empty() {
        let _ = writeln!(output, "TLS");
        for tls in &report.tls {
            if tls.handshake_succeeded {
                let _ = writeln!(
                    output,
                    "  {}  trusted=yes  hostname=yes  protocol={}",
                    tls.address,
                    tls.protocol_version.as_deref().unwrap_or("unknown")
                );
            }
        }
        output.push('\n');
    }

    let _ = writeln!(output, "Findings");
    if report.findings.is_empty() {
        let _ = writeln!(output, "  No findings generated.");
    } else {
        for finding in &report.findings {
            let _ = writeln!(
                output,
                "  {:<8} {} — {}",
                format!("{:?}", finding.severity).to_uppercase(),
                clean_terminal(&finding.title),
                clean_terminal(&finding.target)
            );
        }
    }

    if let Some(score) = &report.exposure_score {
        let _ = writeln!(
            output,
            "\nSurface Exposure Score: {}/100 ({:?}, model {})",
            score.value, score.classification, score.model_version
        );
        if score.incomplete {
            let _ = writeln!(
                output,
                "  Incomplete scan: score interpretation is limited."
            );
        }
        for deduction in &score.deductions {
            let _ = writeln!(
                output,
                "  -{}  {}",
                deduction.points,
                clean_terminal(&deduction.reason)
            );
        }
    }

    let _ = writeln!(output, "\nSummary");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = report
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count();
        let _ = writeln!(output, "  {severity:?}: {count}");
    }
    if !report.errors.is_empty() {
        let _ = writeln!(output, "  Partial errors: {}", report.errors.len());
    }
    output
}

/// Serializes a report as pretty-printed JSON.
///
/// # Errors
///
/// Returns an error if report serialization fails.
pub fn render_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Renders a self-contained, escaped, print-friendly HTML report.
#[must_use]
#[expect(
    clippy::format_collect,
    clippy::too_many_lines,
    reason = "small bounded report fragments favor one auditable escaped template"
)]
pub fn render_html(report: &ScanReport) -> String {
    let mut findings = String::new();
    for finding in &report.findings {
        let evidence = finding
            .evidence
            .iter()
            .map(|item| {
                format!(
                    "<li><code>{}</code>: {}</li>",
                    escape_html(&item.location),
                    escape_html(&item.observed)
                )
            })
            .collect::<String>();
        let remediation = finding
            .remediation
            .as_deref()
            .map_or_else(String::new, |value| {
                format!(
                    "<p><strong>Remediation:</strong> {}</p>",
                    escape_html(value)
                )
            });
        let _ = write!(
            findings,
            "<article class=\"finding {}\"><h3>{} — {}</h3><p>{}</p><ul>{}</ul>{}</article>",
            severity_class(finding.severity),
            escape_html(&format!("{:?}", finding.severity).to_uppercase()),
            escape_html(&finding.title),
            escape_html(&finding.description),
            evidence,
            remediation
        );
    }
    if findings.is_empty() {
        findings.push_str("<p>No findings generated.</p>");
    }

    let dns = report.dns.as_ref().map_or_else(
        || "<p>DNS stage produced no observation.</p>".to_owned(),
        |dns| {
            let records = dns
                .records
                .iter()
                .map(|record| {
                    format!(
                        "<li><code>{}</code></li>",
                        escape_html(&format!("{record:?}"))
                    )
                })
                .collect::<String>();
            format!("<ul>{records}</ul>")
        },
    );
    let hosts = report
        .hosts
        .iter()
        .map(|host| {
            let ports = host
                .ports
                .iter()
                .filter(|port| {
                    port.state == PortState::Open
                        || (port.state == PortState::OpenFiltered
                            && report.services.iter().any(|service| {
                                service.address == port.address
                                    && service.transport == port.transport
                            }))
                })
                .map(|port| {
                    let state = if port.state == PortState::Open {
                        "open"
                    } else {
                        "open|filtered"
                    };
                    format!(
                        "<li>{}/{} {state}</li>",
                        port.address.port(),
                        port.transport.as_str()
                    )
                })
                .collect::<String>();
            format!(
                "<article><h3>{}</h3><ul>{ports}</ul></article>",
                escape_html(&host.ip.to_string())
            )
        })
        .collect::<String>();
    let score = report.exposure_score.as_ref().map_or_else(
        || "<p>Score unavailable.</p>".to_owned(),
        |score| {
            let deductions = score
                .deductions
                .iter()
                .map(|deduction| {
                    format!(
                        "<li>-{}: {}</li>",
                        deduction.points,
                        escape_html(&deduction.reason)
                    )
                })
                .collect::<String>();
            format!(
                "<p><strong>{}/100</strong> ({:?}, model {})</p><ul>{deductions}</ul>",
                score.value,
                score.classification,
                escape_html(&score.model_version)
            )
        },
    );

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Surface report</title><style>:root{{color-scheme:light dark}}body{{font:16px system-ui;max-width:70rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}code{{overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%}}th,td{{padding:.4rem;border-bottom:1px solid #888;text-align:left}}.finding{{border-left:.4rem solid #888;padding:.2rem 1rem;margin:1rem 0}}.high,.critical{{border-color:#c62828}}.medium{{border-color:#ef6c00}}.low{{border-color:#f9a825}}@media print{{:root{{color-scheme:light}}body{{margin:0;max-width:none}}}}</style></head><body><main><h1>Surface {}</h1><dl><dt>Target</dt><dd><code>{}</code></dd><dt>Scan ID</dt><dd><code>{}</code></dd><dt>Started</dt><dd>{}</dd><dt>Completed</dt><dd>{}</dd><dt>Status</dt><dd>{:?}</dd></dl><h2>DNS</h2>{}<h2>Hosts and open ports</h2>{}<h2>Findings</h2>{}<h2>Surface Exposure Score</h2>{}<h2>Scan limitations</h2><p>Surface analyzes externally observable services and security-related configuration. It performs no active exploitation. Timeouts and a clean report do not prove security.</p><footer>Surface {} · schema {}</footer></main></body></html>\n",
        escape_html(&report.scanner_version),
        escape_html(&report.target.original),
        escape_html(&report.scan_id.to_string()),
        escape_html(&report.started_at.to_string()),
        escape_html(
            &report
                .completed_at
                .map_or_else(|| "incomplete".to_owned(), |value| value.to_string())
        ),
        report.status,
        dns,
        hosts,
        findings,
        score,
        escape_html(&report.scanner_version),
        escape_html(&report.schema_version),
    )
}

fn clean_terminal(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Escapes target-controlled text for HTML text and attribute contexts.
#[must_use]
pub fn escape_html(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn option_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "present",
        Some(false) => "not found",
        None => "unknown",
    }
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use surface_core::{normalize_target, ScanConfiguration, ScanReport};

    use super::{render_html, render_json, render_terminal};

    fn report(target: &str) -> ScanReport {
        ScanReport::not_started(
            normalize_target(target).unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![80],
                udp_ports: Vec::new(),
                concurrency: 64,
                connect_timeout_ms: 1_500,
                request_timeout_ms: 5_000,
                global_timeout_ms: 300_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        )
    }

    #[test]
    fn renderers_expose_truthful_status() {
        let report = report("example.com");
        assert!(render_terminal(&report).contains("Status: NotStarted"));
        let json = render_json(&report).unwrap_or_default();
        assert!(json.contains("\"status\": \"not_started\""));
        assert!(json.contains("\"schema_version\": \"0.3.0\""));
    }

    #[test]
    fn html_escapes_target_input() {
        let mut report = report("example.com");
        report.target.original = "<script>alert(1)</script>".to_owned();
        let html = render_html(&report);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("src=\"http"));
    }
}
