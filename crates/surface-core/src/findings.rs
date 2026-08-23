//! Deterministic interpretation of observations into evidence-backed findings.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    DnsObservation, HostObservation, HttpObservation, PortState, ServiceKind, ServiceObservation,
    TlsObservation,
};

// Rust guideline compliant 2026-02-21

/// Finding severity ordered from informational to critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context without a security conclusion.
    Info,
    /// Limited security impact or hardening opportunity.
    Low,
    /// Material weakness requiring review.
    Medium,
    /// Strong evidence of significant exposure.
    High,
    /// Exceptional immediate-impact condition.
    Critical,
}

/// Broad finding domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Network exposure.
    Network,
    /// HTTP behavior or headers.
    Http,
    /// TLS identity or validity.
    Tls,
    /// Mail-domain DNS configuration.
    Mail,
}

/// Confidence in the interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    /// Context-dependent or weak evidence.
    Low,
    /// Direct observation with contextual uncertainty.
    Medium,
    /// Direct protocol evidence.
    High,
}

/// Concrete evidence supporting a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Observation location or field.
    pub location: String,
    /// Sanitized observed value.
    pub observed: String,
}

/// One deterministic, evidence-backed interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier.
    pub id: String,
    /// Concise title.
    pub title: String,
    /// Severity.
    pub severity: Severity,
    /// Finding domain.
    pub category: FindingCategory,
    /// Affected target.
    pub target: String,
    /// Precise contextual description.
    pub description: String,
    /// Supporting observations.
    pub evidence: Vec<Evidence>,
    /// Optional corrective guidance.
    pub remediation: Option<String>,
    /// Primary references.
    pub references: Vec<String>,
    /// Interpretation confidence.
    pub confidence: FindingConfidence,
}

/// Generates conservative findings from completed observations.
#[must_use]
pub fn generate_findings(
    target: &str,
    dns: Option<&DnsObservation>,
    hosts: &[HostObservation],
    services: &[ServiceObservation],
    http: &[HttpObservation],
    tls: &[TlsObservation],
    now: OffsetDateTime,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(dns) = dns {
        mail_findings(target, dns, &mut findings);
    }
    exposure_findings(target, hosts, services, &mut findings);
    http_findings(target, http, &mut findings);
    tls_findings(target, services, tls, now, &mut findings);
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.target.cmp(&right.target))
    });
    findings
}

fn mail_findings(target: &str, dns: &DnsObservation, findings: &mut Vec<Finding>) {
    if dns.mail.spf.records.len() > 1 {
        findings.push(finding(
            "MAIL-SPF-MULTIPLE",
            "Multiple SPF records observed",
            Severity::Medium,
            FindingCategory::Mail,
            target,
            "Multiple SPF records can cause SPF evaluation to return a permanent error.",
            "DNS TXT",
            &dns.mail.spf.records.join(" | "),
            Some("Publish exactly one SPF record."),
            FindingConfidence::High,
        ));
    }
    if let Some(dmarc) = dns.mail.dmarc.first() {
        if dmarc.policy.as_deref() == Some("none") {
            findings.push(finding(
                "MAIL-DMARC-MONITORING",
                "DMARC policy is monitoring-only",
                Severity::Low,
                FindingCategory::Mail,
                target,
                "The observed DMARC p=none policy requests reporting without receiver enforcement.",
                "_dmarc TXT",
                &dmarc.record,
                Some("After validating mail sources, consider an enforcement policy appropriate for the domain."),
                FindingConfidence::High,
            ));
        }
    }
}

fn exposure_findings(
    target: &str,
    hosts: &[HostObservation],
    services: &[ServiceObservation],
    findings: &mut Vec<Finding>,
) {
    const DATABASE_PORTS: &[u16] = &[
        1433, 1521, 2483, 2484, 3306, 5432, 6379, 7474, 7687, 8123, 9000, 9042, 9200, 11211, 27017,
        33060,
    ];
    for host in hosts {
        for port in host.ports.iter().filter(|port| {
            port.transport == crate::TransportProtocol::Tcp && port.state == PortState::Open
        }) {
            if DATABASE_PORTS.contains(&port.address.port()) {
                findings.push(finding(
                    "NET-DATABASE-EXPOSED",
                    "Database-like TCP service is reachable",
                    Severity::High,
                    FindingCategory::Network,
                    &port.address.to_string(),
                    "A TCP connection succeeded on a port commonly used by database or data-store software; the product was not inferred solely from the port.",
                    "TCP connect",
                    "open",
                    Some("Restrict network access unless this listener is intentionally exposed."),
                    FindingConfidence::Medium,
                ));
            }
        }
    }
    for service in services
        .iter()
        .filter(|service| service.service == ServiceKind::Ssh)
    {
        findings.push(finding(
            "NET-SSH-REACHABLE",
            "SSH service is externally reachable",
            Severity::Info,
            FindingCategory::Network,
            &service.address.to_string(),
            "Surface received an SSH identification banner from the endpoint.",
            "service banner",
            service.banner.as_deref().unwrap_or("SSH identification received"),
            Some("Confirm that access controls and authentication policy match operational requirements."),
            FindingConfidence::High,
        ));
    }
    for service in services.iter().filter(|service| {
        service.service == ServiceKind::Smtp
            && service.confidence == crate::DetectionConfidence::High
            && service
                .banner
                .as_deref()
                .is_some_and(|banner| banner.contains("250"))
            && !service.protocol_details.contains_key("starttls")
    }) {
        findings.push(finding(
            "MAIL-SMTP-STARTTLS-NOT-ADVERTISED",
            "SMTP service did not advertise STARTTLS",
            Severity::Medium,
            FindingCategory::Mail,
            &service.address.to_string(),
            "A bounded EHLO exchange completed, but the observed capability list did not advertise STARTTLS.",
            "SMTP EHLO capabilities",
            service.banner.as_deref().unwrap_or("EHLO response received"),
            Some("Review whether transport encryption should be offered on this SMTP endpoint."),
            FindingConfidence::High,
        ));
    }
    let _ = target;
}

fn http_findings(target: &str, observations: &[HttpObservation], findings: &mut Vec<Finding>) {
    for observation in observations
        .iter()
        .filter(|observation| observation.status.is_some())
    {
        let https = observation.url.starts_with("https://");
        let location = observation.final_url.as_deref().unwrap_or(&observation.url);
        let redirects_to_https = observation
            .redirects
            .iter()
            .any(|redirect| redirect.to.starts_with("https://"));
        if !https && !location.starts_with("https://") && !redirects_to_https {
            findings.push(finding(
                "HTTP-NO-HTTPS-REDIRECT",
                "HTTP endpoint did not redirect to HTTPS",
                Severity::Medium,
                FindingCategory::Http,
                target,
                "The observed HTTP request completed without a same-host redirect to HTTPS.",
                &observation.url,
                &format!("status {}", observation.status.unwrap_or_default()),
                Some("Redirect plaintext HTTP requests to an HTTPS endpoint when appropriate."),
                FindingConfidence::High,
            ));
        }
        if https
            && !observation
                .headers
                .contains_key("strict-transport-security")
        {
            findings.push(finding(
                "HTTP-HSTS-MISSING",
                "HSTS header missing",
                Severity::Medium,
                FindingCategory::Http,
                target,
                "The confirmed HTTPS endpoint returned no Strict-Transport-Security header.",
                &observation.url,
                &format!("status {}", observation.status.unwrap_or_default()),
                Some("Evaluate and deploy an appropriate Strict-Transport-Security policy."),
                FindingConfidence::High,
            ));
        }
        let redirects_to_http = observation
            .redirects
            .iter()
            .find(|redirect| redirect.to.starts_with("http://"));
        if https && redirects_to_http.is_some() {
            findings.push(finding(
                "HTTP-HTTPS-DOWNGRADE",
                "HTTPS redirects to HTTP",
                Severity::High,
                FindingCategory::Http,
                target,
                "The HTTPS endpoint redirected to a plaintext HTTP URL.",
                &observation.url,
                redirects_to_http.map_or(location, |redirect| redirect.to.as_str()),
                Some("Keep redirects on HTTPS."),
                FindingConfidence::High,
            ));
        }
        if observation.headers.contains_key("server")
            || observation.headers.contains_key("x-powered-by")
        {
            findings.push(finding(
                "HTTP-VERSION-DISCLOSURE",
                "Server implementation header disclosed",
                Severity::Info,
                FindingCategory::Http,
                target,
                "The endpoint returned Server or X-Powered-By metadata; this is informational and does not prove a vulnerability.",
                &observation.url,
                observation.headers.get("server").or_else(|| observation.headers.get("x-powered-by")).map_or("present", String::as_str),
                Some("Remove unnecessary product/version detail where operationally practical."),
                FindingConfidence::High,
            ));
        }
        if observation.security_txt == Some(false) {
            findings.push(finding(
                "HTTP-SECURITY-TXT-MISSING",
                "security.txt not found",
                Severity::Info,
                FindingCategory::Http,
                target,
                "The well-known security.txt path returned HTTP 404.",
                "/.well-known/security.txt",
                "not found",
                Some("Consider publishing RFC 9116 contact information."),
                FindingConfidence::High,
            ));
        }
    }
}

fn tls_findings(
    target: &str,
    services: &[ServiceObservation],
    observations: &[TlsObservation],
    now: OffsetDateTime,
    findings: &mut Vec<Finding>,
) {
    for observation in observations {
        let expected_tls = services.iter().any(|service| {
            service.address == observation.address
                && (service.service == ServiceKind::Https
                    || matches!(service.address.port(), 443 | 8443))
        });
        if expected_tls && !observation.handshake_succeeded {
            findings.push(finding(
                "TLS-VALIDATION-FAILED",
                "Validating TLS handshake failed",
                Severity::High,
                FindingCategory::Tls,
                target,
                "The expected TLS endpoint did not complete a certificate-validating handshake. The failure may involve trust, hostname, validity, or protocol configuration.",
                &observation.address.to_string(),
                observation.errors.first().map_or("handshake failed", String::as_str),
                Some("Inspect the certificate chain, identity, validity period, and TLS configuration."),
                FindingConfidence::Medium,
            ));
        }
        if let Some(valid_until) = observation.valid_until_unix {
            let remaining = valid_until - now.unix_timestamp();
            if remaining < 0 {
                findings.push(finding(
                    "TLS-CERT-EXPIRED",
                    "TLS certificate is expired",
                    Severity::High,
                    FindingCategory::Tls,
                    target,
                    "The observed leaf certificate validity end precedes the scan time.",
                    &observation.address.to_string(),
                    &format!("valid_until_unix={valid_until}"),
                    Some("Replace or renew the certificate."),
                    FindingConfidence::High,
                ));
            } else if remaining < 30 * 24 * 60 * 60 {
                findings.push(finding(
                    "TLS-CERT-EXPIRING",
                    "TLS certificate expires soon",
                    Severity::Low,
                    FindingCategory::Tls,
                    target,
                    "The observed leaf certificate expires within 30 days.",
                    &observation.address.to_string(),
                    &format!("remaining_days={}", remaining / 86_400),
                    Some("Renew the certificate before expiry."),
                    FindingConfidence::High,
                ));
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "finding fields remain explicit at each rule site"
)]
fn finding(
    id: &str,
    title: &str,
    severity: Severity,
    category: FindingCategory,
    target: &str,
    description: &str,
    location: &str,
    observed: &str,
    remediation: Option<&str>,
    confidence: FindingConfidence,
) -> Finding {
    Finding {
        id: id.to_owned(),
        title: title.to_owned(),
        severity,
        category,
        target: target.to_owned(),
        description: description.to_owned(),
        evidence: vec![Evidence {
            location: location.to_owned(),
            observed: observed.to_owned(),
        }],
        remediation: remediation.map(str::to_owned),
        references: Vec::new(),
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_findings, Severity};
    use crate::{
        AddressSource, DnsObservation, DnsRecord, MailObservation, ResolvedHost, SpfObservation,
    };

    #[test]
    fn multiple_spf_records_generate_evidence() {
        let dns = DnsObservation {
            queried_name: "example.com".to_owned(),
            records: vec![DnsRecord::Txt("v=spf1 -all".to_owned())],
            resolved_hosts: vec![ResolvedHost {
                hostname: Some("example.com".to_owned()),
                ip: "192.0.2.1"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}")),
                source: AddressSource::ARecord,
            }],
            mail: MailObservation {
                mx_present: false,
                spf: SpfObservation {
                    records: vec!["v=spf1 -all".to_owned(), "v=spf1 ~all".to_owned()],
                    terminal_policy: Some("-all".to_owned()),
                },
                dmarc: Vec::new(),
                mta_sts: Vec::new(),
                mta_sts_policy_available: None,
                tls_rpt: Vec::new(),
            },
            errors: Vec::new(),
        };
        let findings = generate_findings(
            "example.com",
            Some(&dns),
            &[],
            &[],
            &[],
            &[],
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(!findings[0].evidence.is_empty());
    }
}
