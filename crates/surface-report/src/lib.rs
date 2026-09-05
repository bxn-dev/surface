//! Deterministic terminal, JSON, HTML, diff, and integration reports.

mod diff;
mod exports;
mod projection;
mod signing;

use std::fmt::Write;

use surface_core::{CertificateTransparencyDnsStatus, HstsState, ScanReport, Severity};

#[doc(inline)]
pub use diff::{
    Change, DIFF_SCHEMA_VERSION, DiffError, DiffSummary, ScanDiff, ScanReference, diff_reports,
    render_diff_html, render_diff_json, render_diff_terminal,
};
#[doc(inline)]
pub use exports::{render_cyclonedx, render_sarif};
pub use signing::{SignatureEnvelope, VerificationError, decode_key, sign_bytes, verify_bytes};

// Rust guideline compliant 2026-02-21

/// Maximum characters rendered for one externally supplied SSH text value.
const SSH_DISPLAY_CHARS: usize = 255;
/// Renders a report as human-readable plain text.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "linear report sections keep presentation deterministic"
)]
pub fn render_terminal(report: &ScanReport) -> String {
    let mut output = String::new();
    let lifecycle = projection::lifecycle(report);
    let _ = writeln!(
        output,
        "Surface {}",
        clean_terminal(&report.scanner_version)
    );
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
        for hop in &dns.cname_chain {
            let _ = writeln!(
                output,
                "  CNAME {} → {}",
                clean_terminal(&hop.from),
                clean_terminal(&hop.to)
            );
        }
        if dns.dangling_cnames.is_empty() {
            let _ = writeln!(output, "  CNAME destination indicators: none recorded");
        } else {
            let _ = writeln!(output, "  CNAME destination indicators");
            for observation in &dns.dangling_cnames {
                let _ = writeln!(
                    output,
                    "    {} -> {}: {}",
                    clean_terminal(&observation.source_alias),
                    clean_terminal(&observation.canonical_target),
                    observation.status.as_str()
                );
                for evidence in &observation.evidence {
                    let _ = writeln!(output, "      Evidence: {}", clean_terminal(evidence));
                }
                for error in &observation.errors {
                    let _ = writeln!(output, "      Error: {}", clean_terminal(error));
                }
                for limitation in &observation.limitations {
                    let _ = writeln!(output, "      Limitation: {}", clean_terminal(limitation));
                }
            }
            let _ = writeln!(
                output,
                "    Destination addresses were not scanned; ownership, claimability, and takeover feasibility were not tested."
            );
        }
        let _ = writeln!(output, "  SPF records: {}", dns.mail.spf.records.len());
        let _ = writeln!(output, "  DMARC records: {}", dns.mail.dmarc.len());
        if let Some(dnssec) = &dns.dnssec {
            let _ = writeln!(output, "  DNSSEC status: {}", dnssec.status.as_str());
            for rrset in &dnssec.checked_rrsets {
                let _ = writeln!(
                    output,
                    "    {} {}: {}",
                    clean_terminal(&rrset.name),
                    rrset.record_type.as_str(),
                    rrset.status.as_str()
                );
            }
            for error in &dnssec.errors {
                let _ = writeln!(output, "    Error: {}", clean_terminal(error));
            }
            for limitation in &dnssec.limitations {
                let _ = writeln!(output, "    Limitation: {}", clean_terminal(limitation));
            }
        } else {
            let _ = writeln!(output, "  DNSSEC status: not recorded (older report)");
        }
        if let Some(wildcard) = &dns.wildcard_dns {
            let answer_types = wildcard
                .answer_types
                .iter()
                .map(|record_type| record_type.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                output,
                "  Wildcard DNS status: {}",
                wildcard.status.as_str()
            );
            let _ = writeln!(
                output,
                "    Probes attempted: {}/2  answer types: {}  fingerprints: {}",
                wildcard.probes_attempted,
                if answer_types.is_empty() {
                    "none"
                } else {
                    &answer_types
                },
                wildcard.answer_fingerprints.len()
            );
            for fingerprint in &wildcard.answer_fingerprints {
                let _ = writeln!(output, "    Fingerprint: {}", clean_terminal(fingerprint));
            }
            for error in &wildcard.errors {
                let _ = writeln!(output, "    Error: {}", clean_terminal(error));
            }
            for limitation in &wildcard.limitations {
                let _ = writeln!(output, "    Limitation: {}", clean_terminal(limitation));
            }
            let _ = writeln!(
                output,
                "    Probe answers were not scanned or used as downstream targets."
            );
        } else {
            let _ = writeln!(output, "  Wildcard DNS status: not recorded (older report)");
        }
        if let Some(axfr) = &dns.authoritative_axfr {
            let _ = writeln!(
                output,
                "  Authoritative AXFR zone: {}",
                clean_terminal(&axfr.zone)
            );
            let _ = writeln!(
                output,
                "    NS names={}/{}  IPs/NS<={}  endpoints={}/{}",
                axfr.nameservers.len(),
                axfr.limits.nameservers,
                axfr.limits.ips_per_nameserver,
                axfr.attempts.len(),
                axfr.limits.endpoints
            );
            for attempt in &axfr.attempts {
                let _ = writeln!(
                    output,
                    "    {}  {}  outcome={}  response={}  messages={}/{}  records={}/{}  bytes={}/{}",
                    clean_terminal(&attempt.server),
                    attempt.endpoint,
                    attempt.outcome.as_str(),
                    clean_terminal(attempt.response_code.as_deref().unwrap_or("none")),
                    attempt.messages,
                    axfr.limits.messages,
                    attempt.records,
                    axfr.limits.records,
                    attempt.bytes,
                    axfr.limits.bytes
                );
                if let Some(error) = &attempt.error {
                    let _ = writeln!(output, "      Error: {}", clean_terminal(error));
                }
            }
            let _ = writeln!(
                output,
                "    Transferred owner names and records were neither retained nor scanned."
            );
        }
        output.push('\n');
    }

    if !report.hosts.is_empty() {
        let _ = writeln!(output, "Hosts");
        for host in &report.hosts {
            let _ = writeln!(output, "  {}", host.ip);
            for port in projection::ports(report, host) {
                let _ = writeln!(
                    output,
                    "    {}/{}  {}  {}",
                    port.number, port.transport, port.state, port.service
                );
            }
        }
        output.push('\n');
    }

    if report.services.iter().any(|service| service.ssh.is_some()) {
        let _ = writeln!(output, "SSH posture");
        for service in report
            .services
            .iter()
            .filter(|service| service.ssh.is_some())
        {
            let Some(posture) = projection::ssh(service) else {
                continue;
            };
            let _ = writeln!(
                output,
                "  {}  protocol={}  software={}  status={}",
                service.address,
                clean_terminal(&bounded_ssh_value(posture.protocol)),
                clean_terminal(&bounded_ssh_value(posture.software)),
                posture.status
            );
            if let Some(banner) = service.banner.as_deref() {
                let _ = writeln!(
                    output,
                    "    Banner: {}",
                    clean_terminal(&bounded_ssh_value(Some(banner)))
                );
            }
            if posture.selections.kex.is_some() {
                let _ = writeln!(
                    output,
                    "    KEXINIT-inferred selections ({}; no completed key exchange): KEX={}  host-key={}",
                    posture.status,
                    clean_terminal(&bounded_ssh_value(posture.selections.kex)),
                    clean_terminal(&bounded_ssh_value(posture.selections.host_key))
                );
                let _ = writeln!(
                    output,
                    "      cipher c2s={}  s2c={}  MAC c2s={}  s2c={}",
                    clean_terminal(&bounded_ssh_value(posture.selections.cipher_c2s)),
                    clean_terminal(&bounded_ssh_value(posture.selections.cipher_s2c)),
                    clean_terminal(&bounded_ssh_value(posture.selections.mac_c2s)),
                    clean_terminal(&bounded_ssh_value(posture.selections.mac_s2c))
                );
            } else {
                let _ = writeln!(output, "    No inferred selections available.");
            }
            if let Some(reason) = posture.reason {
                let _ = writeln!(
                    output,
                    "    Skip reason (bounded): {}",
                    clean_terminal(&bounded_ssh_value(Some(reason)))
                );
            }
        }
        output.push('\n');
    }

    if !report.http.is_empty() {
        let _ = writeln!(output, "HTTP");
        for http in &report.http {
            let _ = write!(
                output,
                "  {}  status={}",
                clean_terminal(&http.url),
                http.status
                    .map_or_else(|| "error".to_owned(), |status| status.to_string()),
            );
            if http.hsts_state() != HstsState::NotApplicable {
                let _ = write!(output, "  HSTS={}", hsts_label(http.hsts_state()));
            }
            let _ = writeln!(output, "  security.txt={}", option_bool(http.security_txt));
            for redirect in &http.redirects {
                let _ = writeln!(
                    output,
                    "    {} --{}--> {}",
                    clean_terminal(&redirect.from),
                    redirect.status,
                    clean_terminal(&redirect.to)
                );
            }
        }
        output.push('\n');
    }

    if !report.tls.is_empty() {
        let _ = writeln!(output, "TLS");
        for tls in &report.tls {
            let _ = writeln!(
                output,
                "  {}  validation={}  trusted={}  hostname={}  protocol={}  cipher={}  chain={}  key_bits={}",
                tls.address,
                if tls.handshake_succeeded {
                    "passed"
                } else {
                    "failed"
                },
                option_yes_no(tls.certificate_trusted),
                option_yes_no(tls.hostname_matches),
                clean_terminal(tls.protocol_version.as_deref().unwrap_or("unknown")),
                clean_terminal(tls.cipher_suite.as_deref().unwrap_or("unknown")),
                tls.certificate_chain_length
                    .map_or_else(|| "unknown".to_owned(), |length| length.to_string()),
                tls.public_key_bits
                    .map_or_else(|| "unknown".to_owned(), |bits| bits.to_string())
            );
            let _ = writeln!(
                output,
                "    Leaf SHA-256: {}",
                clean_terminal(tls.leaf_certificate_sha256.as_deref().unwrap_or("unknown"))
            );
            let _ = writeln!(
                output,
                "    Subject: {}  Issuer: {}  Serial: {}",
                clean_terminal(tls.subject.as_deref().unwrap_or("unknown")),
                clean_terminal(tls.issuer.as_deref().unwrap_or("unknown")),
                clean_terminal(tls.serial_number.as_deref().unwrap_or("unknown"))
            );
            let _ = writeln!(
                output,
                "    Validity: {} to {}  key_oid={}  signature_oid={}",
                tls.valid_from_unix
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                tls.valid_until_unix
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                clean_terminal(tls.public_key_algorithm.as_deref().unwrap_or("unknown")),
                clean_terminal(tls.signature_algorithm.as_deref().unwrap_or("unknown"))
            );
            let _ = writeln!(
                output,
                "    SANs{}: {}",
                if tls.subject_alt_names_truncated {
                    " (truncated)"
                } else {
                    ""
                },
                clean_terminal(&tls.subject_alt_names.join(", "))
            );
            for limitation in &tls.errors {
                let _ = writeln!(
                    output,
                    "    Error/limitation: {}",
                    clean_terminal(limitation)
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

    if let Some(certificate_transparency) = report
        .intelligence
        .as_ref()
        .and_then(|intelligence| intelligence.certificate_transparency.as_ref())
    {
        let _ = writeln!(output, "\nCertificate Transparency candidates");
        let _ = writeln!(
            output,
            "  Source: {} · issuances: {} · pages: {} · complete: {}",
            clean_terminal(&certificate_transparency.source),
            certificate_transparency.issuance_count,
            certificate_transparency.pages_fetched,
            certificate_transparency.complete
        );
        let _ = writeln!(
            output,
            "  Non-wildcard names received only a bounded passive DNS address lookup; they were not actively scanned."
        );
        for (status, label) in CT_DNS_GROUPS {
            let mut group = certificate_transparency
                .candidates
                .iter()
                .filter(|candidate| candidate.dns_status == status)
                .peekable();
            if group.peek().is_none() {
                continue;
            }
            let _ = writeln!(output, "  {label}");
            for candidate in group {
                let _ = writeln!(
                    output,
                    "    {:<8} {}  issuances={}",
                    if candidate.wildcard {
                        "wildcard"
                    } else {
                        "name"
                    },
                    clean_terminal(&candidate.name),
                    candidate.issuance_count
                );
            }
        }
        for error in &certificate_transparency.errors {
            let _ = writeln!(output, "  Limitation: {}", clean_terminal(error));
        }
    }

    if let Some(related) = report
        .intelligence
        .as_ref()
        .and_then(|intelligence| intelligence.related_domains.as_ref())
    {
        let _ = writeln!(output, "\nRelated domain candidates");
        let _ = writeln!(
            output,
            "  Nameservers: {}",
            clean_terminal(&related.nameservers.join(", "))
        );
        if let Some(provider) = &related.provider {
            let _ = writeln!(output, "  Provider: {}", clean_terminal(provider));
        }
        let _ = writeln!(
            output,
            "  Shared DNS infrastructure does not prove common ownership."
        );
        for candidate in &related.candidates {
            let _ = writeln!(
                output,
                "  {:<8} {}",
                clean_terminal(&candidate.confidence.to_uppercase()),
                clean_terminal(&candidate.name)
            );
        }
        for error in &related.errors {
            let _ = writeln!(output, "  Error: {}", clean_terminal(error));
        }
    }

    if let Some(score) = &report.exposure_score {
        let _ = writeln!(
            output,
            "\nSurface Exposure Score: {}/100 ({:?}, model {})",
            score.value,
            score.classification,
            clean_terminal(&score.model_version)
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

    if !report.skipped_checks.is_empty() {
        let _ = writeln!(output, "\nChecks not run");
        for skipped in &report.skipped_checks {
            let _ = writeln!(
                output,
                "  {} — {}",
                clean_terminal(&skipped.check),
                clean_terminal(&skipped.reason)
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
    if lifecycle.errors > 0 {
        let _ = writeln!(output, "  {:?} errors: {}", report.status, lifecycle.errors);
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
    let lifecycle = projection::lifecycle(report);
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
        let references = finding
            .references
            .iter()
            .map(|reference| format!("<li><code>{}</code></li>", escape_html(reference)))
            .collect::<String>();
        let _ = write!(
            findings,
            "<article class=\"finding {}\"><h3>{} — {}</h3><p><strong>ID:</strong> <code>{}</code> · <strong>Target:</strong> <code>{}</code> · <strong>Category:</strong> {:?} · <strong>Confidence:</strong> {:?}</p><p>{}</p><h4>Evidence</h4><ul>{}</ul>{}<details><summary>References</summary><ul>{}</ul></details></article>",
            severity_class(finding.severity),
            escape_html(&format!("{:?}", finding.severity).to_uppercase()),
            escape_html(&finding.title),
            escape_html(&finding.id),
            escape_html(&finding.target),
            finding.category,
            finding.confidence,
            escape_html(&finding.description),
            evidence,
            remediation,
            if references.is_empty() {
                "<li>None.</li>"
            } else {
                &references
            }
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
            let cname_chain = dns
                .cname_chain
                .iter()
                .map(|hop| {
                    format!(
                        "<li><code>{}</code> → <code>{}</code></li>",
                        escape_html(&hop.from),
                        escape_html(&hop.to)
                    )
                })
                .collect::<String>();
            let dangling_cnames = if dns.dangling_cnames.is_empty() {
                "<p>No primary-chain CNAME destinations were checked.</p>".to_owned()
            } else {
                let observations = dns
                    .dangling_cnames
                    .iter()
                    .map(|observation| {
                        let evidence = observation
                            .evidence
                            .iter()
                            .map(|item| format!("<li>{}</li>", escape_html(item)))
                            .collect::<String>();
                        let errors = observation
                            .errors
                            .iter()
                            .map(|item| format!("<li>{}</li>", escape_html(item)))
                            .collect::<String>();
                        let limitations = observation
                            .limitations
                            .iter()
                            .map(|item| format!("<li>{}</li>", escape_html(item)))
                            .collect::<String>();
                        format!(
                            "<li><code>{}</code> -&gt; <code>{}</code>: <strong>{}</strong><ul>{}</ul><ul class=\"error\">{}</ul><ul>{}</ul></li>",
                            escape_html(&observation.source_alias),
                            escape_html(&observation.canonical_target),
                            observation.status.as_str(),
                            if evidence.is_empty() { "<li>No conclusive evidence retained.</li>" } else { &evidence },
                            errors,
                            limitations
                        )
                    })
                    .collect::<String>();
                format!(
                    "<ul>{observations}</ul><p>Destination addresses were not scanned; ownership, claimability, and takeover feasibility were not tested.</p>"
                )
            };
            let resolved = dns
                .resolved_hosts
                .iter()
                .map(|host| {
                    format!(
                        "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{:?}</td></tr>",
                        escape_html(host.hostname.as_deref().unwrap_or("—")),
                        escape_html(&host.ip.to_string()),
                        host.source
                    )
                })
                .collect::<String>();
            let axfr = dns.authoritative_axfr.as_ref().map_or_else(
                || "<p>Not recorded or not confidently applicable.</p>".to_owned(),
                |axfr| {
                    let attempts = axfr
                        .attempts
                        .iter()
                        .map(|attempt| {
                            format!(
                                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}/{}</td><td>{}/{}</td><td>{}</td></tr>",
                                escape_html(&attempt.server),
                                escape_html(&attempt.endpoint.to_string()),
                                attempt.outcome.as_str(),
                                escape_html(attempt.response_code.as_deref().unwrap_or("none")),
                                attempt.messages,
                                axfr.limits.messages,
                                attempt.records,
                                axfr.limits.records,
                                attempt.bytes,
                                axfr.limits.bytes,
                                escape_html(attempt.error.as_deref().unwrap_or("—"))
                            )
                        })
                        .collect::<String>();
                    format!(
                        "<p><strong>Zone:</strong> <code>{}</code> · <strong>NS names:</strong> {}/{} · <strong>IPs per NS:</strong> at most {} · <strong>Endpoints:</strong> {}/{}</p><table><thead><tr><th>Server</th><th>TCP endpoint</th><th>Outcome</th><th>Response</th><th>Messages</th><th>Records</th><th>Bytes</th><th>Error</th></tr></thead><tbody>{}</tbody></table><p>Transferred owner names and records were neither retained nor scanned.</p>",
                        escape_html(&axfr.zone),
                        axfr.nameservers.len(),
                        axfr.limits.nameservers,
                        axfr.limits.ips_per_nameserver,
                        axfr.attempts.len(),
                        axfr.limits.endpoints,
                        if attempts.is_empty() { "<tr><td colspan=\"8\">No endpoint attempts.</td></tr>" } else { &attempts }
                    )
                },
            );
            let wildcard = dns.wildcard_dns.as_ref().map_or_else(
                || "<p>Status: not recorded (older report).</p>".to_owned(),
                |wildcard| {
                    let answer_types = wildcard
                        .answer_types
                        .iter()
                        .map(|record_type| record_type.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let fingerprints = wildcard
                        .answer_fingerprints
                        .iter()
                        .map(|fingerprint| {
                            format!("<li><code>{}</code></li>", escape_html(fingerprint))
                        })
                        .collect::<String>();
                    let errors = wildcard
                        .errors
                        .iter()
                        .map(|error| format!("<li>{}</li>", escape_html(error)))
                        .collect::<String>();
                    let limitations = wildcard
                        .limitations
                        .iter()
                        .map(|limitation| format!("<li>{}</li>", escape_html(limitation)))
                        .collect::<String>();
                    format!(
                        "<p><strong>Status:</strong> {} · <strong>Probes attempted:</strong> {}/2 · <strong>Answer types:</strong> {} · <strong>Fingerprints:</strong> {}</p><ul>{}</ul><h4>Errors</h4><ul class=\"error\">{}</ul><h4>Limitations</h4><ul>{}</ul><p>Probe answers were not scanned or used as downstream targets.</p>",
                        wildcard.status.as_str(),
                        wildcard.probes_attempted,
                        escape_html(if answer_types.is_empty() { "none" } else { &answer_types }),
                        wildcard.answer_fingerprints.len(),
                        if fingerprints.is_empty() { "<li>None.</li>" } else { &fingerprints },
                        if errors.is_empty() { "<li>None.</li>" } else { &errors },
                        if limitations.is_empty() { "<li>None.</li>" } else { &limitations }
                    )
                },
            );
            let dnssec = dns.dnssec.as_ref().map_or_else(
                || "<p>Status: not recorded (older report).</p>".to_owned(),
                |dnssec| {
                    let checked = dnssec
                        .checked_rrsets
                        .iter()
                        .map(|rrset| {
                            format!(
                                "<li><code>{}</code> <code>{}</code>: {}</li>",
                                escape_html(&rrset.name),
                                rrset.record_type.as_str(),
                                rrset.status.as_str()
                            )
                        })
                        .collect::<String>();
                    let errors = dnssec
                        .errors
                        .iter()
                        .map(|error| format!("<li>{}</li>", escape_html(error)))
                        .collect::<String>();
                    let limitations = dnssec
                        .limitations
                        .iter()
                        .map(|limitation| format!("<li>{}</li>", escape_html(limitation)))
                        .collect::<String>();
                    format!(
                        "<p><strong>Status:</strong> {}</p><h4>Checked names and types</h4><ul>{}</ul><h4>Errors</h4><ul class=\"error\">{}</ul><h4>Limitations</h4><ul>{}</ul>",
                        dnssec.status.as_str(),
                        if checked.is_empty() { "<li>None completed.</li>" } else { &checked },
                        if errors.is_empty() { "<li>None.</li>" } else { &errors },
                        if limitations.is_empty() { "<li>None.</li>" } else { &limitations }
                    )
                },
            );
            format!(
                "<p>Queried <code>{}</code></p><h3>CNAME chain</h3><ul>{}</ul><h3>Dangling CNAME indicators</h3>{dangling_cnames}<h3>Records</h3><ul>{records}</ul><h3>Resolved scan addresses</h3><table><thead><tr><th>Host</th><th>Address</th><th>Source</th></tr></thead><tbody>{resolved}</tbody></table><h3>DNSSEC</h3>{dnssec}<h3>Authoritative AXFR</h3>{axfr}<h3>Wildcard DNS detection</h3>{wildcard}<p><strong>MX:</strong> {} · <strong>SPF records:</strong> {} · <strong>DMARC records:</strong> {} · <strong>MTA-STS:</strong> {} · <strong>TLS-RPT:</strong> {}</p>",
                escape_html(&dns.queried_name),
                if cname_chain.is_empty() { "<li>None observed.</li>" } else { &cname_chain },
                option_bool(Some(dns.mail.mx_present)),
                dns.mail.spf.records.len(),
                dns.mail.dmarc.len(),
                dns.mail.mta_sts.len(),
                dns.mail.tls_rpt.len()
            )
        },
    );
    let hosts = report
        .hosts
        .iter()
        .map(|host| {
            let ports = projection::ports(report, host)
                .into_iter()
                .map(|port| {
                    format!(
                        "<li>{}/{} {} {}</li>",
                        port.number,
                        port.transport,
                        port.state,
                        escape_html(&port.service)
                    )
                })
                .collect::<String>();
            format!(
                "<article><h3>{}</h3><ul>{ports}</ul></article>",
                escape_html(&host.ip.to_string())
            )
        })
        .collect::<String>();
    let services = report
        .services
        .iter()
        .map(|service| {
            let details = service
                .protocol_details
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        escape_html(&bounded_ssh_value(Some(key))),
                        escape_html(&bounded_ssh_value(Some(value)))
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td></tr>",
                escape_html(&service.address.to_string()),
                service.transport.as_str(),
                escape_html(&service.service.to_string()),
                service.confidence,
                if details.is_empty() { "—" } else { &details }
            )
        })
        .collect::<String>();
    let ssh_entries = report
        .services
        .iter()
        .filter_map(|service| projection::ssh(service).map(|posture| (service, posture)))
        .map(|(service, posture)| {
            let detail = |value| escape_html(&bounded_ssh_value(value));
            let selections = if posture.selections.kex.is_some() {
                format!(
                    "<p><strong>KEXINIT-inferred selections ({}; no completed key exchange):</strong> KEX <code>{}</code> · host key <code>{}</code> · cipher c2s/s2c <code>{}</code>/<code>{}</code> · MAC c2s/s2c <code>{}</code>/<code>{}</code></p>",
                    posture.status,
                    detail(posture.selections.kex),
                    detail(posture.selections.host_key),
                    detail(posture.selections.cipher_c2s),
                    detail(posture.selections.cipher_s2c),
                    detail(posture.selections.mac_c2s),
                    detail(posture.selections.mac_s2c)
                )
            } else {
                "<p><strong>No inferred selections available.</strong></p>".to_owned()
            };
            let skip_reason = posture.reason.map_or_else(String::new, |reason| {
                    format!(
                        "<p><strong>Skip reason (bounded):</strong> <code>{}</code></p>",
                        escape_html(&bounded_ssh_value(Some(reason)))
                    )
                });
            format!(
                "<details class=\"card\"><summary><code>{}</code> · status <code>{}</code></summary><p><strong>Protocol:</strong> <code>{}</code> · <strong>Software:</strong> <code>{}</code> · <strong>Banner:</strong> <code>{}</code></p>{selections}{skip_reason}</details>",
                escape_html(&service.address.to_string()),
                posture.status,
                detail(posture.protocol),
                detail(posture.software),
                escape_html(&bounded_ssh_value(service.banner.as_deref())),
            )
        })
        .collect::<String>();
    let ssh = if ssh_entries.is_empty() {
        String::new()
    } else {
        format!("<section><h2>SSH posture</h2>{ssh_entries}</section>")
    };
    let http = report
        .http
        .iter()
        .map(|http| {
            let effective_url = http.effective_url();
            let hsts_state = hsts_label(http.hsts_state());
            let redirects = http
                .redirects
                .iter()
                .map(|redirect| {
                    format!(
                        "<li><code>{}</code> <strong>—{}→</strong> <code>{}</code></li>",
                        escape_html(&redirect.from),
                        redirect.status,
                        escape_html(&redirect.to)
                    )
                })
                .collect::<String>();
            let headers = http
                .headers
                .iter()
                .map(|(name, value)| {
                    format!(
                        "<li><code>{}</code>: {}</li>",
                        escape_html(name),
                        escape_html(value)
                    )
                })
                .collect::<String>();
            let cookies = http
                .cookies
                .iter()
                .map(|cookie| {
                    format!(
                        "<li><code>{}</code>: Secure={} HttpOnly={} SameSite={} Domain={} Path={}</li>",
                        escape_html(&cookie.name),
                        cookie.secure,
                        cookie.http_only,
                        escape_html(cookie.same_site.as_deref().unwrap_or("—")),
                        escape_html(cookie.domain.as_deref().unwrap_or("—")),
                        escape_html(cookie.path.as_deref().unwrap_or("—"))
                    )
                })
                .collect::<String>();
            format!(
                "<article class=\"card\"><h3><code>{}</code></h3><p><strong>Status:</strong> {} · <strong>Final URL:</strong> <code>{}</code> · <strong>Protocol:</strong> {} · <strong>Latency:</strong> {} ms</p><p><strong>Title:</strong> {} · <strong>HSTS:</strong> {hsts_state} · <strong>security.txt:</strong> {} · <strong>robots.txt:</strong> {} · <strong>sitemap.xml:</strong> {}</p><p><strong>Retained body:</strong> {} bytes{}</p><h4>Redirects</h4><ul>{}</ul><details><summary>Selected headers</summary><ul>{}</ul></details><details><summary>Cookies (values omitted)</summary><ul>{}</ul></details>{}</article>",
                escape_html(&http.url),
                http.status.map_or_else(|| "error".to_owned(), |status| status.to_string()),
                escape_html(effective_url),
                escape_html(http.version.as_deref().unwrap_or("unknown")),
                http.latency_ms.map_or_else(|| "—".to_owned(), |value| value.to_string()),
                escape_html(http.title.as_deref().unwrap_or("—")),
                option_bool(http.security_txt),
                option_bool(http.robots_txt),
                option_bool(http.sitemap_xml),
                http.body_bytes,
                if http.body_truncated { " (truncated)" } else { "" },
                if redirects.is_empty() { "<li>None.</li>" } else { &redirects },
                if headers.is_empty() { "<li>None retained.</li>" } else { &headers },
                if cookies.is_empty() { "<li>None.</li>" } else { &cookies },
                http.error.as_deref().map_or_else(String::new, |error| format!("<p class=\"error\"><strong>Error:</strong> {}</p>", escape_html(error)))
            )
        })
        .collect::<String>();
    let tls = report
        .tls
        .iter()
        .map(|tls| {
            let names = tls
                .subject_alt_names
                .iter()
                .map(|name| escape_html(name))
                .collect::<Vec<_>>()
                .join(", ");
            let tls_errors = tls
                .errors
                .iter()
                .map(|error| escape_html(error))
                .collect::<Vec<_>>()
                .join("; ");
            format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&tls.address.to_string()),
                escape_html(&tls.server_name),
                if tls.handshake_succeeded { "passed" } else { "failed" },
                option_yes_no(tls.certificate_trusted),
                option_yes_no(tls.hostname_matches),
                escape_html(tls.protocol_version.as_deref().unwrap_or("—")),
                escape_html(tls.cipher_suite.as_deref().unwrap_or("—")),
                tls.certificate_chain_length.map_or_else(|| "—".to_owned(), |value| value.to_string()),
                escape_html(tls.leaf_certificate_sha256.as_deref().unwrap_or("—")),
                escape_html(tls.subject.as_deref().unwrap_or("—")),
                escape_html(tls.issuer.as_deref().unwrap_or("—")),
                escape_html(tls.serial_number.as_deref().unwrap_or("—")),
                tls.valid_from_unix.map_or_else(|| "—".to_owned(), |value| value.to_string()),
                tls.valid_until_unix.map_or_else(|| "—".to_owned(), |value| value.to_string()),
                if names.is_empty() { "—" } else { &names },
                if tls.subject_alt_names_truncated { "yes" } else { "no" },
                escape_html(tls.public_key_algorithm.as_deref().unwrap_or("—")),
                tls.public_key_bits.map_or_else(|| "—".to_owned(), |value| value.to_string()),
                escape_html(tls.signature_algorithm.as_deref().unwrap_or("—")),
                if tls_errors.is_empty() { "—" } else { &tls_errors }
            )
        })
        .collect::<String>();
    let errors = report
        .errors
        .iter()
        .map(|error| {
            format!(
                "<li><strong>{:?}/{:?}</strong> {}{}</li>",
                error.stage,
                error.kind,
                error
                    .target
                    .as_deref()
                    .map_or_else(String::new, |target| format!(
                        "<code>{}</code>: ",
                        escape_html(target)
                    )),
                escape_html(&error.message)
            )
        })
        .collect::<String>();
    let certificate_transparency = report
        .intelligence
        .as_ref()
        .and_then(|intelligence| intelligence.certificate_transparency.as_ref())
        .map_or_else(
            || "<p>Not available.</p>".to_owned(),
            |observation| {
                let candidates = CT_DNS_GROUPS
                    .iter()
                    .filter_map(|(status, label)| {
                        let rows = observation
                            .candidates
                            .iter()
                            .filter(|candidate| candidate.dns_status == *status)
                            .map(|candidate| {
                                format!(
                                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                                    escape_html(&candidate.name),
                                    if candidate.wildcard { "yes" } else { "no" },
                                    candidate.issuance_count
                                )
                            })
                            .collect::<String>();
                        (!rows.is_empty()).then(|| {
                            format!("<tr><th colspan=\"3\">{label}</th></tr>{rows}")
                        })
                    })
                    .collect::<String>();
                let limitations = observation
                    .errors
                    .iter()
                    .map(|error| format!("<li>{}</li>", escape_html(error)))
                    .collect::<String>();
                format!(
                    "<p><strong>Source:</strong> {} · <strong>Issuances:</strong> {} · <strong>Pages:</strong> {} · <strong>Complete:</strong> {}</p><p>Non-wildcard names received only a bounded passive DNS address lookup; they were not actively scanned.</p><table><thead><tr><th>Name</th><th>Wildcard</th><th>Issuances</th></tr></thead><tbody>{}</tbody></table><ul class=\"error\">{}</ul>",
                    escape_html(&observation.source),
                    observation.issuance_count,
                    observation.pages_fetched,
                    observation.complete,
                    candidates,
                    limitations
                )
            },
        );
    let related = report
        .intelligence
        .as_ref()
        .and_then(|intelligence| intelligence.related_domains.as_ref())
        .map_or_else(
            || "<p>Not requested.</p>".to_owned(),
            |related| {
                let candidates = related
                    .candidates
                    .iter()
                    .map(|candidate| {
                        let evidence = candidate
                            .evidence
                            .iter()
                            .map(|item| format!("<li>{}</li>", escape_html(item)))
                            .collect::<String>();
                        format!(
                            "<article class=\"card\"><h3><code>{}</code></h3><p><strong>Confidence:</strong> {}</p><ul>{}</ul></article>",
                            escape_html(&candidate.name),
                            escape_html(&candidate.confidence),
                            evidence
                        )
                    })
                    .collect::<String>();
                let related_errors = related
                    .errors
                    .iter()
                    .map(|error| format!("<li>{}</li>", escape_html(error)))
                    .collect::<String>();
                format!(
                    "<p><strong>Nameservers:</strong> <code>{}</code> · <strong>Provider:</strong> {}</p><p>Shared DNS infrastructure does not prove common ownership.</p>{}<ul class=\"error\">{}</ul>",
                    escape_html(&related.nameservers.join(", ")),
                    escape_html(related.provider.as_deref().unwrap_or("unknown")),
                    if candidates.is_empty() { "<p>No candidates returned.</p>" } else { &candidates },
                    related_errors
                )
            },
        );
    let skipped_checks = report
        .skipped_checks
        .iter()
        .map(|skipped| {
            format!(
                "<li><code>{}</code> — {}</li>",
                escape_html(&skipped.check),
                escape_html(&skipped.reason)
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
            let incomplete = if lifecycle.score_incomplete {
                "<p><strong>Incomplete scan: score interpretation is limited.</strong></p>"
            } else {
                ""
            };
            format!(
                "<p><strong>{}/100</strong> ({:?}, model {})</p>{incomplete}<ul>{deductions}</ul>",
                score.value,
                score.classification,
                escape_html(&score.model_version)
            )
        },
    );

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Surface report — {target}</title><style>:root{{color-scheme:light;--bg:#f4f7fb;--panel:#fff;--text:#172033;--muted:#607089;--line:#dbe3ee;--accent:#3157d5}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}}main{{max-width:76rem;margin:auto;padding:2rem 1rem 4rem}}header{{padding:1.5rem;border-radius:1rem;background:linear-gradient(135deg,#172554,#3157d5);color:#fff}}header h1{{margin:0}}.meta,.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:.8rem}}.meta div,.card,.finding,section{{background:var(--panel);border:1px solid var(--line);border-radius:.8rem;padding:1rem}}header .meta div{{background:#ffffff18;border-color:#ffffff33}}dt{{font-size:.78rem;text-transform:uppercase;color:var(--muted)}}header dt{{color:#dbeafe}}dd{{margin:0;font-weight:650}}section{{margin-top:1rem}}section>h2{{margin-top:0}}.cards{{margin:1rem 0}}.cards .card{{font-size:1.2rem;font-weight:700}}.cards small{{display:block;color:var(--muted);font-size:.78rem}}code{{overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%;display:block;overflow:auto}}th,td{{padding:.55rem;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}}ul{{padding-left:1.3rem}}.finding{{border-left:.45rem solid #64748b;margin:.8rem 0}}.critical,.high{{border-left-color:#c62828}}.medium{{border-left-color:#ef6c00}}.low{{border-left-color:#ca8a04}}.info{{border-left-color:#2563eb}}.error{{color:#b91c1c}}footer{{margin-top:2rem;color:var(--muted)}}@media print{{body{{background:#fff}}main{{max-width:none;padding:0}}section,.card,.finding,header{{break-inside:avoid}}}}</style></head><body><main><header><h1>Surface report</h1><p><code>{target}</code></p><dl class=\"meta\"><div><dt>Status</dt><dd>{status:?}</dd></div><div><dt>Started</dt><dd>{started}</dd></div><div><dt>Completed</dt><dd>{completed}</dd></div><div><dt>Scan ID</dt><dd><code>{scan_id}</code></dd></div></dl></header><div class=\"cards\"><div class=\"card\"><small>Exposure score</small>{score_value}</div><div class=\"card\"><small>Findings</small>{finding_count}</div><div class=\"card\"><small>Hosts</small>{host_count}</div><div class=\"card\"><small>Services</small>{service_count}</div><div class=\"card\"><small>HTTP endpoints</small>{http_count}</div><div class=\"card\"><small>Partial errors</small>{error_count}</div></div><section><h2>Findings</h2>{findings}</section><section><h2>DNS</h2>{dns}</section><section><h2>Hosts and open ports</h2>{hosts}</section><section><h2>Services</h2><table><thead><tr><th>Endpoint</th><th>Transport</th><th>Service</th><th>Confidence</th><th>Details</th></tr></thead><tbody>{services}</tbody></table></section>{ssh}<section><h2>HTTP</h2>{http}</section><section><h2>TLS</h2><table><thead><tr><th>Endpoint</th><th>Server name</th><th>Validation</th><th>Trusted</th><th>Hostname</th><th>Protocol</th><th>Cipher</th><th>Chain length</th><th>Leaf SHA-256</th><th>Subject</th><th>Issuer</th><th>Serial</th><th>Valid from</th><th>Valid until</th><th>Names</th><th>SANs truncated</th><th>Key algorithm</th><th>Key bits</th><th>Signature algorithm</th><th>Errors/limitations</th></tr></thead><tbody>{tls}</tbody></table></section><section><h2>Certificate Transparency candidates</h2>{certificate_transparency}</section><section><h2>Related domain candidates</h2>{related}</section><section><h2>Surface Exposure Score</h2>{score}</section><section><h2>Partial errors</h2><ul>{errors_html}</ul></section><section><h2>Checks not run</h2><ul>{skipped_html}</ul></section><section><h2>Configuration</h2><p>TCP ports: {tcp_ports} · UDP ports: {udp_ports} · concurrency: {concurrency} · connect timeout: {connect_timeout} ms · request timeout: {request_timeout} ms · global timeout: {global_timeout} ms</p></section><section><h2>Limitations</h2><p>Surface analyzes externally observable services and security-related configuration. It performs no active exploitation. DNS answers, redirects, timeouts, and a clean report do not prove security.</p></section><footer>Surface {version} · schema {schema}</footer></main></body></html>\n",
        target = escape_html(&report.target.original),
        status = report.status,
        started = escape_html(&report.started_at.to_string()),
        completed = escape_html(
            &report
                .completed_at
                .map_or_else(|| "incomplete".to_owned(), |value| value.to_string())
        ),
        scan_id = escape_html(&report.scan_id.to_string()),
        score_value = report
            .exposure_score
            .as_ref()
            .map_or_else(|| "—".to_owned(), |value| format!("{}/100", value.value)),
        finding_count = report.findings.len(),
        host_count = report.hosts.len(),
        service_count = report.services.len(),
        http_count = report.http.len(),
        error_count = report.errors.len(),
        findings = findings,
        dns = dns,
        hosts = if hosts.is_empty() {
            "<p>No hosts observed.</p>"
        } else {
            &hosts
        },
        services = services,
        ssh = ssh,
        http = if http.is_empty() {
            "<p>No HTTP endpoints observed.</p>"
        } else {
            &http
        },
        tls = tls,
        certificate_transparency = certificate_transparency,
        score = score,
        errors_html = if errors.is_empty() {
            "<li>None.</li>"
        } else {
            &errors
        },
        skipped_html = if skipped_checks.is_empty() {
            "<li>None.</li>"
        } else {
            &skipped_checks
        },
        tcp_ports = report.configuration.ports.len(),
        udp_ports = report.configuration.udp_ports.len(),
        concurrency = report.configuration.concurrency,
        connect_timeout = report.configuration.connect_timeout_ms,
        request_timeout = report.configuration.request_timeout_ms,
        global_timeout = report.configuration.global_timeout_ms,
        version = escape_html(&report.scanner_version),
        schema = escape_html(&report.schema_version),
    )
}

fn bounded_ssh_value(value: Option<&str>) -> String {
    value
        .unwrap_or("unknown")
        .chars()
        .take(SSH_DISPLAY_CHARS)
        .collect()
}

pub(crate) fn clean_terminal(value: &str) -> String {
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

const fn hsts_label(state: HstsState) -> &'static str {
    match state {
        HstsState::Present => "present",
        HstsState::Missing => "missing",
        HstsState::NotApplicable => "not applicable",
    }
}

fn option_yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
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

const CT_DNS_GROUPS: [(CertificateTransparencyDnsStatus, &str); 5] = [
    (
        CertificateTransparencyDnsStatus::Resolved,
        "Currently resolved",
    ),
    (
        CertificateTransparencyDnsStatus::NoAddress,
        "No current address record",
    ),
    (
        CertificateTransparencyDnsStatus::NxDomain,
        "Historical certificate names",
    ),
    (
        CertificateTransparencyDnsStatus::Indeterminate,
        "DNS verification indeterminate",
    ),
    (
        CertificateTransparencyDnsStatus::NotChecked,
        "Wildcard or unverified certificate names",
    ),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use surface_core::{
        AuthoritativeAxfrObservation, AxfrAttempt, AxfrOutcome, CertificateTransparencyCandidate,
        CertificateTransparencyDnsStatus, CertificateTransparencyObservation, CnameHop,
        DanglingCnameObservation, DanglingCnameStatus, DetectionConfidence, DnsObservation,
        DnssecObservation, DnssecRecordType, DnssecRrsetObservation, DnssecStatus, HostObservation,
        HttpObservation, IntelligenceObservation, MailObservation, PartialSshAlgorithmSelections,
        PortObservation, PortState, RedirectObservation, RelatedDomainCandidate,
        RelatedDomainsObservation, ScanConfiguration, ScanError, ScanErrorKind, ScanReport,
        ScanStage, ScanStatus, ServiceKind, ServiceObservation, SkippedCheck, SpfObservation,
        SshAlgorithmSelections, SshIdentification, SshPosture, SshPostureOutcome, TlsObservation,
        TransportProtocol, WildcardDnsObservation, WildcardDnsRecordType, WildcardDnsStatus,
        calculate_exposure, normalize_target,
    };

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

    fn ssh_service(port: u16, banner: Option<&str>, ssh: Option<SshPosture>) -> ServiceObservation {
        ServiceObservation {
            transport: TransportProtocol::Tcp,
            address: format!("127.0.0.1:{port}")
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            service: ServiceKind::Ssh,
            confidence: DetectionConfidence::High,
            banner: banner.map(str::to_owned),
            protocol_details: BTreeMap::new(),
            ssh,
        }
    }

    fn ssh_selections() -> SshAlgorithmSelections {
        SshAlgorithmSelections {
            kex: "<kex>".to_owned(),
            host_key: "<host-key>".to_owned(),
            cipher_c2s: "<cipher-c2s>".to_owned(),
            cipher_s2c: "<cipher-s2c>".to_owned(),
            mac_c2s: "<mac-c2s>".to_owned(),
            mac_s2c: "<mac-s2c>".to_owned(),
        }
    }

    #[test]
    fn renderers_expose_truthful_status() {
        let report = report("example.com");
        assert!(render_terminal(&report).contains("Status: NotStarted"));
        let json = render_json(&report).unwrap_or_default();
        assert!(json.contains("\"status\": \"not_started\""));
        assert!(json.contains("\"schema_version\": \"0.4.0\""));
        assert!(!render_terminal(&report).contains("\nSSH posture\n"));
        assert!(!render_html(&report).contains("<h2>SSH posture</h2>"));
    }

    #[test]
    fn human_renderers_expose_exact_failure_and_incomplete_score() {
        let mut report = report("example.com");
        report.status = ScanStatus::Failed;
        report.errors.push(ScanError::new(
            ScanStage::Preflight,
            None,
            ScanErrorKind::Configuration,
            "invalid configuration",
            false,
        ));
        let mut score = calculate_exposure(&report);
        score.incomplete = true;
        report.exposure_score = Some(score);

        let terminal = render_terminal(&report);
        let html = render_html(&report);

        assert!(terminal.contains("Failed errors: 1"));
        assert!(!terminal.contains("Partial errors"));
        assert!(html.contains("Incomplete scan: score interpretation is limited."));
    }

    #[test]
    fn human_renderers_share_visible_port_semantics() {
        let mut report = report("example.com");
        let ip = "192.0.2.1"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        let port = |number, transport, state| PortObservation {
            transport,
            address: (ip, number).into(),
            state,
            latency_ms: None,
            error: None,
        };
        report.hosts.push(HostObservation {
            ip,
            ports: vec![
                port(80, TransportProtocol::Tcp, PortState::Open),
                port(53, TransportProtocol::Udp, PortState::OpenFiltered),
                port(54, TransportProtocol::Udp, PortState::OpenFiltered),
                port(81, TransportProtocol::Tcp, PortState::Closed),
            ],
        });
        report.services.push(ServiceObservation {
            transport: TransportProtocol::Udp,
            address: (ip, 53).into(),
            service: ServiceKind::Dns,
            confidence: DetectionConfidence::High,
            banner: None,
            protocol_details: BTreeMap::new(),
            ssh: None,
        });

        let terminal = render_terminal(&report);
        let html = render_html(&report);

        assert!(terminal.contains("80/tcp  open  unknown"));
        assert!(terminal.contains("53/udp  open|filtered  DNS"));
        assert!(!terminal.contains("54/udp"));
        assert!(!terminal.contains("81/tcp"));
        assert!(html.contains("<li>80/tcp open unknown</li>"));
        assert!(html.contains("<li>53/udp open|filtered DNS</li>"));
        assert!(!html.contains("54/udp"));
        assert!(!html.contains("81/tcp"));
    }

    #[test]
    fn terminal_sanitizes_imported_dynamic_metadata() {
        let mut report = report("example.com");
        report.scanner_version = "scanner\u{1b}[31m\nINJECTED-SCANNER\u{7}\u{9b}".to_owned();
        let mut score = calculate_exposure(&report);
        score.model_version = "model\u{1b}]0;owned\nINJECTED-MODEL\u{0}\u{85}".to_owned();
        report.exposure_score = Some(score);
        report.intelligence = Some(IntelligenceObservation {
            related_domains: Some(RelatedDomainsObservation {
                nameservers: Vec::new(),
                provider: None,
                candidates: vec![RelatedDomainCandidate {
                    name: "café.example".to_owned(),
                    matched_nameservers: Vec::new(),
                    confidence: "mé\u{1b}[31m\nBAD\u{0}\u{85}".to_owned(),
                    evidence: Vec::new(),
                }],
                complete: true,
                errors: Vec::new(),
            }),
            ..IntelligenceObservation::default()
        });

        let terminal = render_terminal(&report);
        assert_eq!(
            terminal.lines().next(),
            Some("Surface scanner [31m INJECTED-SCANNER  ")
        );
        assert!(terminal.lines().any(|line| {
            line == "Surface Exposure Score: 100/100 (Favorable, model model ]0;owned INJECTED-MODEL  )"
        }));
        assert!(
            terminal
                .lines()
                .any(|line| line == "  MÉ [31M BAD   café.example")
        );
        assert!(
            terminal
                .chars()
                .all(|character| character == '\n' || !character.is_control())
        );
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

    #[test]
    fn complete_ssh_posture_is_bounded_sanitized_escaped_and_truthful() {
        let mut report = report("example.com");
        report.services.push(ssh_service(
            22,
            Some("SSH-2.0-<banner>\u{1b}[31m"),
            Some(SshPosture {
                identification: Some(SshIdentification {
                    protocol: "2.0".to_owned(),
                    software: "<software>&\u{7}".to_owned(),
                }),
                outcome: SshPostureOutcome::Complete {
                    selections: ssh_selections(),
                },
            }),
        ));

        let terminal = render_terminal(&report);
        assert!(terminal.contains("127.0.0.1:22  protocol=2.0"));
        assert!(terminal.contains("status=complete"));
        assert!(
            terminal.contains("KEXINIT-inferred selections (complete; no completed key exchange)")
        );
        assert!(!terminal.contains('\u{1b}'));
        assert!(!terminal.contains('\u{7}'));

        let html = render_html(&report);
        assert!(html.contains("KEXINIT-inferred selections (complete; no completed key exchange)"));
        for escaped in [
            "&lt;banner&gt;",
            "&lt;software&gt;&amp;",
            "&lt;kex&gt;",
            "&lt;host-key&gt;",
            "&lt;cipher-c2s&gt;",
            "&lt;cipher-s2c&gt;",
            "&lt;mac-c2s&gt;",
            "&lt;mac-s2c&gt;",
        ] {
            assert!(html.contains(escaped));
        }
        assert!(!html.contains('\u{1b}'));
        assert!(!html.contains('\u{7}'));
        assert!(!html.contains("src=\"http"));
    }

    #[test]
    fn indeterminate_and_timeout_ssh_posture_has_no_selection_claim() {
        let mut report = report("example.com");
        report.services.push(ssh_service(
            2222,
            None,
            Some(SshPosture {
                identification: Some(SshIdentification {
                    protocol: "2.0".to_owned(),
                    software: "OpenSSH_<9>&".to_owned(),
                }),
                outcome: SshPostureOutcome::Indeterminate {
                    reason: format!("<request timeout>\u{1b}[31m{}END", "x".repeat(300)),
                },
            }),
        ));
        report.services.push(ssh_service(
            2200,
            None,
            Some(SshPosture {
                identification: None,
                outcome: SshPostureOutcome::Indeterminate {
                    reason: "identification timeout".to_owned(),
                },
            }),
        ));

        let terminal = render_terminal(&report);
        assert!(terminal.contains("protocol=2.0  software=OpenSSH_<9>&  status=indeterminate"));
        assert_eq!(terminal.matches("status=indeterminate").count(), 2);
        assert_eq!(
            terminal
                .matches("No inferred selections available.")
                .count(),
            2
        );
        assert!(terminal.contains("Skip reason (bounded): <request timeout>"));
        assert!(!terminal.contains("KEXINIT"));
        assert!(!terminal.contains('\u{1b}'));
        assert!(!terminal.contains("END"));

        let html = render_html(&report);
        assert!(html.contains("status <code>indeterminate</code>"));
        assert_eq!(html.matches("status <code>indeterminate</code>").count(), 2);
        assert_eq!(html.matches("No inferred selections available.").count(), 2);
        assert!(html.contains("OpenSSH_&lt;9&gt;&amp;"));
        assert!(html.contains("&lt;request timeout&gt;"));
        assert!(!html.contains("KEXINIT"));
        assert!(!html.contains('\u{1b}'));
        assert!(!html.contains("END"));
    }

    #[test]
    fn partial_ssh_selections_are_rendered_as_incomplete() {
        let mut report = report("example.com");
        report.services.push(ssh_service(
            22,
            None,
            Some(SshPosture {
                identification: None,
                outcome: SshPostureOutcome::Partial {
                    selections: PartialSshAlgorithmSelections {
                        kex: Some("partial-kex".to_owned()),
                        host_key: Some("partial-host-key".to_owned()),
                        ..PartialSshAlgorithmSelections::default()
                    },
                    reason: "no common cipher".to_owned(),
                },
            }),
        ));

        for rendered in [render_terminal(&report), render_html(&report)] {
            assert!(rendered.contains("partial-kex"));
            assert!(rendered.contains("partial-host-key"));
            assert!(rendered.contains("no common cipher"));
        }
    }

    #[test]
    fn older_report_json_remains_renderable_without_ssh_posture() {
        let mut report = report("example.com");
        report.services.push(ServiceObservation {
            transport: TransportProtocol::Tcp,
            address: "127.0.0.1:80"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            service: ServiceKind::Http,
            confidence: DetectionConfidence::Medium,
            banner: None,
            protocol_details: BTreeMap::new(),
            ssh: None,
        });
        let mut value = serde_json::to_value(report).unwrap_or_else(|error| panic!("{error}"));
        value["schema_version"] = serde_json::json!("0.2.0");
        if let Some(configuration) = value["configuration"].as_object_mut() {
            configuration.remove("udp_ports");
        }
        if let Some(service) = value["services"][0].as_object_mut() {
            service.remove("transport");
        }

        let old: ScanReport =
            serde_json::from_value(value).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(old.schema_version, "0.2.0");
        assert_eq!(old.services[0].transport, TransportProtocol::Tcp);
        assert!(!render_terminal(&old).contains("\nSSH posture\n"));
        assert!(!render_html(&old).contains("<h2>SSH posture</h2>"));
    }

    #[test]
    fn tls_evidence_is_rendered_and_html_escaped() {
        let mut report = report("example.com");
        report.tls.push(TlsObservation {
            address: "127.0.0.1:443"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            server_name: "example.com".to_owned(),
            handshake_succeeded: false,
            certificate_trusted: None,
            hostname_matches: None,
            protocol_version: Some("TLSv1_3".to_owned()),
            cipher_suite: Some("<cipher>".to_owned()),
            alpn: Some("h2".to_owned()),
            certificate_chain_length: Some(2),
            leaf_certificate_sha256: Some("<fingerprint>".to_owned()),
            subject: Some("<subject>".to_owned()),
            issuer: Some("<issuer>".to_owned()),
            serial_number: Some("<serial>".to_owned()),
            valid_from_unix: Some(1),
            valid_until_unix: Some(2),
            subject_alt_names: vec!["<san.example>".to_owned()],
            subject_alt_names_truncated: true,
            public_key_algorithm: Some("<key-oid>".to_owned()),
            public_key_bits: Some(256),
            signature_algorithm: Some("<signature-oid>".to_owned()),
            errors: vec!["<bounded>".to_owned()],
        });

        let terminal = render_terminal(&report);
        assert!(terminal.contains("validation=failed  trusted=unknown  hostname=unknown"));
        assert!(terminal.contains("cipher=<cipher>  chain=2  key_bits=256"));
        assert!(terminal.contains("Leaf SHA-256: <fingerprint>"));
        assert!(terminal.contains("SANs (truncated): <san.example>"));
        let json = render_json(&report).unwrap_or_else(|error| panic!("{error}"));
        assert!(json.contains("\"leaf_certificate_sha256\": \"<fingerprint>\""));
        let html = render_html(&report);
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.contains("src=\"http"));
        for escaped in [
            "&lt;cipher&gt;",
            "&lt;fingerprint&gt;",
            "&lt;subject&gt;",
            "&lt;issuer&gt;",
            "&lt;serial&gt;",
            "&lt;san.example&gt;",
            "&lt;key-oid&gt;",
            "&lt;signature-oid&gt;",
            "&lt;bounded&gt;",
        ] {
            assert!(html.contains(escaped));
        }
        assert!(!html.contains("<cipher>"));
    }

    #[test]
    fn certificate_transparency_candidates_are_escaped_and_disclaimed() {
        let mut report = report("example.com");
        report.intelligence = Some(IntelligenceObservation {
            complete: false,
            certificate_transparency: Some(CertificateTransparencyObservation {
                source: "CertSpotter".to_owned(),
                candidates: vec![
                    CertificateTransparencyCandidate {
                        name: "<api.example.com>".to_owned(),
                        wildcard: false,
                        issuance_count: 2,
                        dns_status: CertificateTransparencyDnsStatus::Resolved,
                    },
                    CertificateTransparencyCandidate {
                        name: "old.example.com".to_owned(),
                        wildcard: false,
                        issuance_count: 1,
                        dns_status: CertificateTransparencyDnsStatus::NxDomain,
                    },
                ],
                issuance_count: 2,
                pages_fetched: 1,
                complete: false,
                errors: vec!["bounded result".to_owned()],
            }),
            ..IntelligenceObservation::default()
        });

        let terminal = render_terminal(&report);
        let html = render_html(&report);

        assert!(terminal.contains("Currently resolved"));
        assert!(terminal.contains("Historical certificate names"));
        assert!(html.contains("&lt;api.example.com&gt;"));
        assert!(html.contains("Currently resolved"));
        assert!(html.contains("Historical certificate names"));
        assert!(html.contains("were not actively scanned"));
        assert!(!html.contains("<api.example.com>"));
    }

    #[test]
    fn related_domain_candidates_are_escaped_and_disclaimed() {
        let mut report = report("example.com");
        report.intelligence = Some(IntelligenceObservation {
            complete: true,
            related_domains: Some(RelatedDomainsObservation {
                nameservers: vec![
                    "a.ns.cloudflare.com".to_owned(),
                    "b.ns.cloudflare.com".to_owned(),
                ],
                provider: Some("Cloudflare".to_owned()),
                candidates: vec![RelatedDomainCandidate {
                    name: "<candidate.example>".to_owned(),
                    matched_nameservers: Vec::new(),
                    confidence: "medium".to_owned(),
                    evidence: vec!["shared infrastructure".to_owned()],
                }],
                complete: true,
                errors: Vec::new(),
            }),
            ..IntelligenceObservation::default()
        });
        let html = render_html(&report);
        assert!(html.contains("&lt;candidate.example&gt;"));
        assert!(html.contains("does not prove common ownership"));
        assert!(!html.contains("<candidate.example>"));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one report fixture verifies DNSSEC, AXFR, and wildcard DNS across all renderers"
    )]
    fn dnssec_rendering_is_complete_and_escaped() {
        let mut report = report("example.com");
        report.dns = Some(DnsObservation {
            queried_name: "example.com".to_owned(),
            records: Vec::new(),
            cname_chain: vec![CnameHop {
                from: "<alias.example.com>".to_owned(),
                to: "<missing.example.net>".to_owned(),
            }],
            dangling_cnames: vec![DanglingCnameObservation {
                source_alias: "<alias.example.com>".to_owned(),
                canonical_target: "<missing.example.net>".to_owned(),
                status: DanglingCnameStatus::NxDomain,
                evidence: vec!["A returned conclusive authenticated NXDOMAIN.".to_owned()],
                errors: Vec::new(),
                limitations: vec![
                    "Ownership, claimability, and takeover feasibility were not tested.".to_owned(),
                ],
            }],
            resolved_hosts: Vec::new(),
            mail: MailObservation {
                mx_present: false,
                spf: SpfObservation {
                    records: Vec::new(),
                    terminal_policy: None,
                },
                dmarc: Vec::new(),
                mta_sts: Vec::new(),
                mta_sts_policy_available: None,
                tls_rpt: Vec::new(),
            },
            dnssec: Some(DnssecObservation {
                status: DnssecStatus::Indeterminate,
                checked_rrsets: vec![DnssecRrsetObservation {
                    name: "<example.com>".to_owned(),
                    record_type: DnssecRecordType::A,
                    status: DnssecStatus::Indeterminate,
                }],
                errors: vec!["<validation error>".to_owned()],
                limitations: vec!["<bounded scope>".to_owned()],
            }),
            authoritative_axfr: Some(AuthoritativeAxfrObservation {
                zone: "<example.com>".to_owned(),
                nameservers: vec!["<ns1.example.com>".to_owned()],
                attempts: vec![AxfrAttempt {
                    server: "<ns1.example.com>".to_owned(),
                    endpoint: "192.0.2.53:53"
                        .parse()
                        .unwrap_or_else(|error| panic!("{error}")),
                    outcome: AxfrOutcome::Refused,
                    response_code: Some("Refused".to_owned()),
                    messages: 1,
                    records: 0,
                    bytes: 48,
                    error: None,
                }],
                ..AuthoritativeAxfrObservation::default()
            }),
            wildcard_dns: Some(WildcardDnsObservation {
                status: WildcardDnsStatus::Detected,
                probes_attempted: 2,
                answer_types: vec![WildcardDnsRecordType::A, WildcardDnsRecordType::Cname],
                answer_fingerprints: vec!["sha256:<fingerprint>".to_owned()],
                errors: vec!["<wildcard error>".to_owned()],
                limitations: vec!["<wildcard limitation>".to_owned()],
                probe_answers_scanned: false,
            }),
            errors: Vec::new(),
        });
        report.skipped_checks.push(SkippedCheck {
            check: "dnssec_validation".to_owned(),
            reason: "validation was indeterminate".to_owned(),
        });
        report.findings = surface_core::generate_findings(
            "example.com",
            report.dns.as_ref(),
            &[],
            &[],
            &[],
            &[],
            report.started_at,
        );

        let terminal = render_terminal(&report);
        assert!(terminal.contains("DNSSEC status: indeterminate"));
        assert!(terminal.contains("<example.com> A: indeterminate"));
        assert!(terminal.contains("<alias.example.com> -> <missing.example.net>: nxdomain"));
        assert!(terminal.contains("takeover feasibility were not tested"));
        assert!(terminal.contains("NS names=1/4  IPs/NS<=2  endpoints=1/8"));
        assert!(terminal.contains("outcome=refused"));
        assert!(terminal.contains("messages=1/64"));
        assert!(terminal.contains("records=0/4096"));
        assert!(terminal.contains("bytes=48/2097152"));
        assert!(terminal.contains("neither retained nor scanned"));
        assert!(terminal.contains("Wildcard DNS status: detected"));
        assert!(terminal.contains("Probes attempted: 2/2"));
        assert!(terminal.contains("answer types: A, CNAME"));
        assert!(terminal.contains("fingerprints: 1"));
        assert!(terminal.contains("Probe answers were not scanned"));
        assert!(terminal.contains("dnssec_validation"));

        let json = render_json(&report).unwrap_or_else(|error| panic!("{error}"));
        assert!(json.contains("\"status\": \"indeterminate\""));
        assert!(json.contains("\"record_type\": \"a\""));
        assert!(json.contains("\"dangling_cnames\""));
        assert!(json.contains("\"status\": \"nxdomain\""));
        assert!(json.contains("DNS-CNAME-DANGLING-INDICATOR"));
        assert!(json.contains("status=NXDOMAIN"));
        assert!(json.contains("\"outcome\": \"refused\""));
        assert!(json.contains("\"transferred_records_retained\": false"));
        assert!(json.contains("\"transferred_owner_names_scanned\": false"));
        assert!(json.contains("\"wildcard_dns\""));
        assert!(json.contains("\"answer_types\": ["));
        assert!(json.contains("\"probe_answers_scanned\": false"));
        assert!(json.contains("\"check\": \"dnssec_validation\""));

        let html = render_html(&report);
        assert!(html.contains("DNSSEC"));
        assert!(html.contains("Authoritative AXFR"));
        assert!(html.contains("Dangling CNAME indicators"));
        assert!(html.contains("&lt;alias.example.com&gt;"));
        assert!(html.contains("&lt;missing.example.net&gt;"));
        assert!(!html.contains("<alias.example.com>"));
        assert!(html.contains("DNS-CNAME-DANGLING-INDICATOR"));
        assert!(html.contains("status=NXDOMAIN"));
        assert!(html.contains("takeover feasibility were not tested"));
        assert!(html.contains("dnssec_validation"));
        assert!(html.contains("&lt;example.com&gt;"));
        assert!(html.contains("&lt;ns1.example.com&gt;"));
        assert!(html.contains("IPs per NS:</strong> at most 2"));
        assert!(html.contains("1/64"));
        assert!(html.contains("0/4096"));
        assert!(html.contains("48/2097152"));
        assert!(html.contains("neither retained nor scanned"));
        assert!(html.contains("Wildcard DNS detection"));
        assert!(html.contains("Probes attempted:</strong> 2/2"));
        assert!(html.contains("Answer types:</strong> A, CNAME"));
        assert!(html.contains("Probe answers were not scanned"));
        assert!(html.contains("&lt;wildcard error&gt;"));
        assert!(html.contains("&lt;wildcard limitation&gt;"));
        assert!(!html.contains("<wildcard error>"));
        assert!(html.contains("&lt;validation error&gt;"));
        assert!(html.contains("&lt;bounded scope&gt;"));
        assert!(!html.contains("<validation error>"));
    }

    #[test]
    fn http_to_https_redirect_does_not_claim_hsts_is_missing() {
        let mut report = report("example.com");
        report.http.push(HttpObservation {
            address: "127.0.0.1:80"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            url: "http://example.com/".to_owned(),
            final_url: Some("http://example.com/".to_owned()),
            status: Some(308),
            version: Some("HTTP/1.1".to_owned()),
            latency_ms: Some(12),
            redirects: vec![RedirectObservation {
                from: "http://example.com/".to_owned(),
                status: 308,
                to: "https://example.com/".to_owned(),
            }],
            headers: BTreeMap::new(),
            cookies: Vec::new(),
            title: None,
            body_bytes: 0,
            body_truncated: false,
            robots_txt: None,
            security_txt: None,
            sitemap_xml: None,
            error: None,
        });

        let terminal = render_terminal(&report);
        assert!(terminal.contains("http://example.com/ --308--> https://example.com/"));
        assert!(!terminal.contains("HSTS=missing"));

        let html = render_html(&report);
        assert!(html.contains("—308→"));
        assert!(html.contains("https://example.com/"));
        assert!(html.contains("HSTS:</strong> not applicable"));
    }
}
