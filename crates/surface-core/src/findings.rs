//! Deterministic interpretation of observations into evidence-backed findings.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    DnsObservation, HostObservation, HstsState, HttpObservation, PortState, ServiceKind,
    ServiceObservation, TlsObservation,
};

// Rust guideline compliant 2026-02-21

/// RFC 3279 `rsaEncryption` public-key algorithm identifier.
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
/// RFC 3279 SHA-1 certificate signature algorithm identifiers.
const SHA1_SIGNATURE_OIDS: &[&str] = &[
    "1.2.840.113549.1.1.5",
    "1.2.840.10040.4.3",
    "1.2.840.10045.4.1",
];
const NIST_SP_800_131A_REV2: &str = "https://doi.org/10.6028/NIST.SP.800-131Ar2";
const RFC_3279: &str = "https://www.rfc-editor.org/rfc/rfc3279.html";
const RFC_8996: &str = "https://www.rfc-editor.org/rfc/rfc8996.html";
const RFC_4253: &str = "https://www.rfc-editor.org/rfc/rfc4253.html";
const RFC_9142: &str = "https://www.rfc-editor.org/rfc/rfc9142.html";
const RFC_8758: &str = "https://www.rfc-editor.org/rfc/rfc8758.html";
const RFC_6151: &str = "https://www.rfc-editor.org/rfc/rfc6151.html";

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
        dns_findings(target, dns, &mut findings);
        mail_findings(target, dns, &mut findings);
    }
    exposure_findings(target, hosts, services, &mut findings);
    http_findings(target, http, &mut findings);
    tls_findings(target, services, tls, now, &mut findings);
    let mut seen = BTreeSet::new();
    findings.retain(|finding| {
        let evidence = finding
            .evidence
            .iter()
            .map(|evidence| (evidence.location.clone(), evidence.observed.clone()))
            .collect::<Vec<_>>();
        seen.insert((finding.id.clone(), finding.target.clone(), evidence))
    });
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| {
                left.evidence
                    .iter()
                    .map(|evidence| (&evidence.location, &evidence.observed))
                    .cmp(
                        right
                            .evidence
                            .iter()
                            .map(|evidence| (&evidence.location, &evidence.observed)),
                    )
            })
    });
    findings
}

fn dns_findings(target: &str, dns: &DnsObservation, findings: &mut Vec<Finding>) {
    dangling_cname_findings(target, dns, findings);

    if let Some(wildcard) = dns
        .wildcard_dns
        .as_ref()
        .filter(|wildcard| wildcard.status == crate::WildcardDnsStatus::Detected)
    {
        let answer_types = wildcard
            .answer_types
            .iter()
            .map(|record_type| record_type.as_str())
            .collect::<Vec<_>>()
            .join(",");
        findings.push(finding(
            "DNS-WILDCARD-DETECTED",
            "Wildcard DNS answers detected",
            Severity::Info,
            FindingCategory::Network,
            target,
            "Two random child names returned identical non-empty DNS answer fingerprints. This is contextual routing evidence and is not automatically a vulnerability.",
            "Wildcard DNS detection",
            &format!(
                "probes_attempted={}; answer_types={}; fingerprints={}",
                wildcard.probes_attempted,
                if answer_types.is_empty() {
                    "none"
                } else {
                    &answer_types
                },
                wildcard.answer_fingerprints.len()
            ),
            None,
            FindingConfidence::High,
        ));
    }

    if let Some(axfr) = &dns.authoritative_axfr {
        let allowed = axfr
            .attempts
            .iter()
            .filter(|attempt| attempt.outcome == crate::AxfrOutcome::Allowed)
            .map(|attempt| {
                format!(
                    "{} ({}): complete, {} messages, {} records, {} bytes",
                    attempt.server,
                    attempt.endpoint,
                    attempt.messages,
                    attempt.records,
                    attempt.bytes
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        if !allowed.is_empty() {
            findings.push(finding(
                "DNS-AXFR-ALLOWED",
                "Authoritative zone transfer is allowed",
                Severity::High,
                FindingCategory::Network,
                target,
                "An authoritative server returned a complete SOA-delimited AXFR over TCP.",
                "Authoritative AXFR",
                &allowed,
                Some("Restrict AXFR to explicitly authorized secondary DNS servers."),
                FindingConfidence::High,
            ));
        }
    }

    let Some(dnssec) = dns
        .dnssec
        .as_ref()
        .filter(|dnssec| dnssec.status == crate::DnssecStatus::Bogus)
    else {
        return;
    };
    let observed = dnssec
        .checked_rrsets
        .iter()
        .filter(|rrset| rrset.status == crate::DnssecStatus::Bogus)
        .map(|rrset| format!("{} {}: bogus", rrset.name, rrset.record_type.as_str()))
        .collect::<Vec<_>>()
        .join(" | ");
    findings.push(finding(
        "DNS-DNSSEC-BOGUS",
        "DNSSEC validation is bogus",
        Severity::High,
        FindingCategory::Network,
        target,
        "Hickory Resolver cryptographically classified at least one selected primary-host RRset as bogus.",
        "DNSSEC validation",
        if observed.is_empty() {
            "aggregate DNSSEC status: bogus"
        } else {
            &observed
        },
        Some("Inspect the zone's DS, DNSKEY, and RRSIG chain and repair invalid or missing signed data."),
        FindingConfidence::High,
    ));
}

fn dangling_cname_findings(target: &str, dns: &DnsObservation, findings: &mut Vec<Finding>) {
    let mut reported_targets = std::collections::BTreeSet::new();
    for hop in &dns.cname_chain {
        let normalized_target = hop.to.to_ascii_lowercase();
        let directly_observed_nxdomain = dns.dangling_cnames.iter().any(|observation| {
            observation.status == crate::DanglingCnameStatus::NxDomain
                && observation.canonical_target.eq_ignore_ascii_case(&hop.to)
                && dns.cname_chain.iter().any(|observed_hop| {
                    observed_hop
                        .from
                        .eq_ignore_ascii_case(&observation.source_alias)
                        && observed_hop
                            .to
                            .eq_ignore_ascii_case(&observation.canonical_target)
                })
        });
        if !directly_observed_nxdomain || !reported_targets.insert(normalized_target) {
            continue;
        }
        findings.push(finding(
            "DNS-CNAME-DANGLING-INDICATOR",
            "Potential dangling CNAME",
            Severity::Medium,
            FindingCategory::Network,
            target,
            "A directly observed primary-target CNAME destination returned conclusive NXDOMAIN across the selected address queries. This is a potential dangling CNAME indicator; ownership, claimability, and takeover feasibility were not tested.",
            "Primary CNAME chain",
            &format!("{} -> {}; status=NXDOMAIN", hop.from, hop.to),
            Some("Review whether the CNAME destination is still required and controlled by the intended owner."),
            FindingConfidence::Medium,
        ));
    }
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
        if let Some(legacy) = ssh_legacy_finding(service) {
            findings.push(legacy);
        }
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

fn ssh_legacy_finding(service: &ServiceObservation) -> Option<Finding> {
    let Some(crate::SshPosture {
        outcome: crate::SshPostureOutcome::Complete { selections },
        ..
    }) = service.ssh.as_ref()
    else {
        return None;
    };
    let legacy = [
        (
            "ssh_kex",
            selections.kex.as_str(),
            "diffie-hellman-group14-sha1",
        ),
        (
            "ssh_kex",
            selections.kex.as_str(),
            "diffie-hellman-group1-sha1",
        ),
        (
            "ssh_host_key_algorithm",
            selections.host_key.as_str(),
            "ssh-rsa",
        ),
        (
            "ssh_host_key_algorithm",
            selections.host_key.as_str(),
            "ssh-dss",
        ),
        ("ssh_cipher_c2s", selections.cipher_c2s.as_str(), "3des-cbc"),
        ("ssh_cipher_c2s", selections.cipher_c2s.as_str(), "arcfour"),
        (
            "ssh_cipher_c2s",
            selections.cipher_c2s.as_str(),
            "arcfour128",
        ),
        (
            "ssh_cipher_c2s",
            selections.cipher_c2s.as_str(),
            "arcfour256",
        ),
        ("ssh_cipher_s2c", selections.cipher_s2c.as_str(), "3des-cbc"),
        ("ssh_cipher_s2c", selections.cipher_s2c.as_str(), "arcfour"),
        (
            "ssh_cipher_s2c",
            selections.cipher_s2c.as_str(),
            "arcfour128",
        ),
        (
            "ssh_cipher_s2c",
            selections.cipher_s2c.as_str(),
            "arcfour256",
        ),
        ("ssh_mac_c2s", selections.mac_c2s.as_str(), "hmac-sha1"),
        ("ssh_mac_c2s", selections.mac_c2s.as_str(), "hmac-md5"),
        ("ssh_mac_c2s", selections.mac_c2s.as_str(), "hmac-md5-96"),
        ("ssh_mac_s2c", selections.mac_s2c.as_str(), "hmac-sha1"),
        ("ssh_mac_s2c", selections.mac_s2c.as_str(), "hmac-md5"),
        ("ssh_mac_s2c", selections.mac_s2c.as_str(), "hmac-md5-96"),
    ]
    .into_iter()
    .filter(|(_, selected, legacy)| selected == legacy)
    .map(|(key, _, algorithm)| format!("{key}={algorithm}"))
    .collect::<Vec<_>>();
    (!legacy.is_empty()).then(|| {
        with_references(
            finding(
                "NET-SSH-LEGACY-ALGORITHM",
                "SSH KEXINIT inferred a legacy algorithm selection",
                Severity::Medium,
                FindingCategory::Network,
                &service.address.to_string(),
                "RFC 4253 client-first KEXINIT preference intersection inferred the listed legacy selection before any completed key exchange. Surface closed after KEXINIT, so no cryptographic negotiation completed, and this does not establish server preference.",
                "SSH KEXINIT client-first preference intersection",
                &legacy.join(", "),
                Some("Disable obsolete SSH algorithms after confirming required client compatibility."),
                FindingConfidence::Medium,
            ),
            &[
                RFC_4253,
                RFC_9142,
                RFC_8758,
                RFC_6151,
                NIST_SP_800_131A_REV2,
            ],
        )
    })
}

fn http_findings(target: &str, observations: &[HttpObservation], findings: &mut Vec<Finding>) {
    for observation in observations
        .iter()
        .filter(|observation| observation.status.is_some())
    {
        let https = observation.url.starts_with("https://");
        let location = observation.effective_url();
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
        if observation.hsts_state() == HstsState::Missing {
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
                "The expected TLS endpoint did not complete the certificate-validating handshake.",
                &observation.address.to_string(),
                observation.errors.first().map_or("handshake failed", String::as_str),
                Some("Inspect the certificate chain, identity, validity period, and TLS configuration."),
                FindingConfidence::Medium,
            ));
        }
        tls_weakness_findings(target, observation, findings);
        let scan_time = now.unix_timestamp();
        if let Some(valid_from) = observation.valid_from_unix
            && valid_from > scan_time
        {
            findings.push(finding(
                "TLS-CERT-NOT-YET-VALID",
                "TLS certificate is not yet valid",
                Severity::High,
                FindingCategory::Tls,
                target,
                "The observed leaf certificate validity start follows the scan time.",
                &observation.address.to_string(),
                &format!("valid_from_unix={valid_from}"),
                Some("Install a certificate whose validity period has started."),
                FindingConfidence::High,
            ));
        } else if let Some(valid_until) = observation.valid_until_unix {
            let remaining = valid_until - scan_time;
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
            } else if observation.handshake_succeeded && remaining < 30 * 24 * 60 * 60 {
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

fn tls_weakness_findings(target: &str, observation: &TlsObservation, findings: &mut Vec<Finding>) {
    if observation.public_key_algorithm.as_deref() == Some(RSA_ENCRYPTION_OID)
        && let Some(bits) = observation.public_key_bits
        && bits != 0
        && bits < 2048
    {
        findings.push(with_references(
            finding(
                "TLS-CERT-WEAK-RSA-KEY",
                "TLS leaf certificate uses a weak RSA key",
                Severity::Medium,
                FindingCategory::Tls,
                target,
                "The parsed leaf SubjectPublicKeyInfo uses the exact rsaEncryption OID and reports an RSA modulus smaller than 2048 bits.",
                &observation.address.to_string(),
                &format!("public_key_algorithm={RSA_ENCRYPTION_OID}, public_key_bits={bits}"),
                Some("Replace the leaf certificate with one using an RSA key of at least 2048 bits or an appropriate modern alternative."),
                FindingConfidence::High,
            ),
            &[NIST_SP_800_131A_REV2, RFC_3279],
        ));
    }
    if let Some(signature_algorithm) = observation.signature_algorithm.as_deref()
        && SHA1_SIGNATURE_OIDS.contains(&signature_algorithm)
    {
        findings.push(with_references(
            finding(
                "TLS-CERT-SHA1-SIGNATURE",
                "TLS leaf certificate uses a SHA-1 signature",
                Severity::Medium,
                FindingCategory::Tls,
                target,
                "The parsed leaf certificate signatureAlgorithm exactly identifies SHA-1 with RSA, DSA, or ECDSA.",
                &observation.address.to_string(),
                &format!("signature_algorithm={signature_algorithm}"),
                Some("Replace the leaf certificate with one signed using SHA-256 or stronger."),
                FindingConfidence::High,
            ),
            &[NIST_SP_800_131A_REV2, RFC_3279],
        ));
    }
    if let Some(protocol_version @ ("TLSv1_0" | "TLSv1_1")) =
        observation.protocol_version.as_deref()
    {
        findings.push(with_references(
            finding(
                "TLS-OBSOLETE-PROTOCOL",
                "TLS endpoint negotiated an obsolete protocol",
                Severity::Medium,
                FindingCategory::Tls,
                target,
                "The directly observed negotiated protocol version is TLS 1.0 or TLS 1.1, which RFC 8996 deprecates.",
                &observation.address.to_string(),
                &format!("protocol_version={protocol_version}"),
                Some("Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or later."),
                FindingConfidence::High,
            ),
            &[RFC_8996],
        ));
    }
}

fn with_references(mut finding: Finding, references: &[&str]) -> Finding {
    finding.references = references
        .iter()
        .map(|reference| (*reference).to_owned())
        .collect();
    finding
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
    use super::{FindingConfidence, Severity, generate_findings};
    use crate::{
        AddressSource, AuthoritativeAxfrObservation, AxfrAttempt, AxfrOutcome, CnameHop,
        DanglingCnameObservation, DanglingCnameStatus, DetectionConfidence, DnsObservation,
        DnsRecord, DnssecObservation, DnssecRecordType, DnssecRrsetObservation, DnssecStatus,
        HttpObservation, MailObservation, PartialSshAlgorithmSelections, ResolvedHost, ServiceKind,
        ServiceObservation, SpfObservation, SshAlgorithmSelections, SshPosture, SshPostureOutcome,
        TlsObservation, TransportProtocol, WildcardDnsObservation, WildcardDnsRecordType,
        WildcardDnsStatus,
    };

    fn rejected_tls_observation() -> TlsObservation {
        TlsObservation {
            address: "127.0.0.1:443"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            server_name: "localhost".to_owned(),
            handshake_succeeded: false,
            certificate_trusted: None,
            hostname_matches: None,
            protocol_version: None,
            cipher_suite: None,
            alpn: None,
            certificate_chain_length: Some(1),
            leaf_certificate_sha256: Some("00".repeat(32)),
            subject: Some("CN=localhost".to_owned()),
            issuer: Some("CN=fixture issuer".to_owned()),
            serial_number: Some("01".to_owned()),
            valid_from_unix: None,
            valid_until_unix: None,
            subject_alt_names: vec!["localhost".to_owned()],
            subject_alt_names_truncated: false,
            public_key_algorithm: None,
            public_key_bits: None,
            signature_algorithm: None,
            errors: vec!["certificate validation failed".to_owned()],
        }
    }

    fn ssh_service(ssh: Option<SshPosture>) -> ServiceObservation {
        ServiceObservation {
            transport: TransportProtocol::Tcp,
            address: "127.0.0.1:22"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            service: ServiceKind::Ssh,
            confidence: DetectionConfidence::High,
            banner: Some("SSH-2.0-OpenSSH_7.2 CVE-2099-0001".to_owned()),
            protocol_details: std::collections::BTreeMap::new(),
            ssh,
        }
    }

    fn ssh_selections(field: &str, algorithm: &str) -> SshAlgorithmSelections {
        let mut selections = SshAlgorithmSelections {
            kex: "curve25519-sha256".to_owned(),
            host_key: "ssh-ed25519".to_owned(),
            cipher_c2s: "aes256-ctr".to_owned(),
            cipher_s2c: "aes256-ctr".to_owned(),
            mac_c2s: "hmac-sha2-512".to_owned(),
            mac_s2c: "hmac-sha2-512".to_owned(),
        };
        match field {
            "ssh_kex" => selections.kex = algorithm.to_owned(),
            "ssh_host_key_algorithm" => selections.host_key = algorithm.to_owned(),
            "ssh_cipher_c2s" => selections.cipher_c2s = algorithm.to_owned(),
            "ssh_cipher_s2c" => selections.cipher_s2c = algorithm.to_owned(),
            "ssh_mac_c2s" => selections.mac_c2s = algorithm.to_owned(),
            "ssh_mac_s2c" => selections.mac_s2c = algorithm.to_owned(),
            _ => panic!("unknown SSH selection field"),
        }
        selections
    }

    fn complete_ssh(field: &str, algorithm: &str) -> SshPosture {
        SshPosture {
            identification: None,
            outcome: SshPostureOutcome::Complete {
                selections: ssh_selections(field, algorithm),
            },
        }
    }

    #[test]
    fn multiple_spf_records_generate_evidence() {
        let dns = DnsObservation {
            queried_name: "example.com".to_owned(),
            records: vec![DnsRecord::Txt("v=spf1 -all".to_owned())],
            cname_chain: Vec::new(),
            dangling_cnames: Vec::new(),
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
            dnssec: None,
            authoritative_axfr: None,
            wildcard_dns: None,
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

    #[test]
    fn final_https_response_without_hsts_generates_finding() {
        let observation = HttpObservation {
            address: "127.0.0.1:80"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            url: "http://example.com/".to_owned(),
            final_url: Some("https://example.com/".to_owned()),
            status: Some(200),
            version: Some("HTTP/1.1".to_owned()),
            latency_ms: Some(1),
            redirects: Vec::new(),
            headers: std::collections::BTreeMap::new(),
            cookies: Vec::new(),
            title: None,
            body_bytes: 0,
            body_truncated: false,
            robots_txt: None,
            security_txt: None,
            sitemap_xml: None,
            error: None,
        };

        let findings = generate_findings(
            "example.com",
            None,
            &[],
            &[],
            &[observation],
            &[],
            time::OffsetDateTime::UNIX_EPOCH,
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "HTTP-HSTS-MISSING")
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture proves wildcard and dangling-CNAME finding exclusions"
    )]
    fn only_detected_wildcard_dns_generates_an_info_finding() {
        let mut dns = DnsObservation {
            queried_name: "example.com".to_owned(),
            records: Vec::new(),
            cname_chain: Vec::new(),
            dangling_cnames: Vec::new(),
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
            dnssec: None,
            authoritative_axfr: None,
            wildcard_dns: Some(WildcardDnsObservation {
                status: WildcardDnsStatus::Detected,
                probes_attempted: 2,
                answer_types: vec![WildcardDnsRecordType::A],
                answer_fingerprints: vec!["sha256:bounded".to_owned()],
                ..WildcardDnsObservation::default()
            }),
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
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "DNS-WILDCARD-DETECTED");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].confidence, super::FindingConfidence::High);
        assert!(
            findings[0]
                .description
                .contains("not automatically a vulnerability")
        );

        for status in [
            WildcardDnsStatus::NotDetected,
            WildcardDnsStatus::Indeterminate,
            WildcardDnsStatus::NotApplicable,
        ] {
            dns.wildcard_dns
                .as_mut()
                .expect("wildcard observation")
                .status = status;
            assert!(
                generate_findings(
                    "example.com",
                    Some(&dns),
                    &[],
                    &[],
                    &[],
                    &[],
                    time::OffsetDateTime::UNIX_EPOCH,
                )
                .is_empty()
            );
        }

        dns.wildcard_dns = None;
        dns.cname_chain = vec![CnameHop {
            from: "example.com".to_owned(),
            to: "missing.example".to_owned(),
        }];
        dns.dangling_cnames = vec![DanglingCnameObservation {
            source_alias: "example.com".to_owned(),
            canonical_target: "missing.example".to_owned(),
            status: DanglingCnameStatus::NxDomain,
            ..DanglingCnameObservation::default()
        }];
        let findings = generate_findings(
            "example.com",
            Some(&dns),
            &[],
            &[],
            &[],
            &[],
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "DNS-CNAME-DANGLING-INDICATOR");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, super::FindingConfidence::Medium);
        assert_eq!(
            findings[0].evidence[0].observed,
            "example.com -> missing.example; status=NXDOMAIN"
        );
        assert!(findings[0].description.contains("potential dangling CNAME"));
        assert!(findings[0].description.contains("were not tested"));

        dns.cname_chain.push(CnameHop {
            from: "missing.example".to_owned(),
            to: "MISSING.EXAMPLE".to_owned(),
        });
        dns.dangling_cnames.push(DanglingCnameObservation {
            source_alias: "missing.example".to_owned(),
            canonical_target: "MISSING.EXAMPLE".to_owned(),
            status: DanglingCnameStatus::NxDomain,
            ..DanglingCnameObservation::default()
        });
        let duplicate_findings = generate_findings(
            "example.com",
            Some(&dns),
            &[],
            &[],
            &[],
            &[],
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(duplicate_findings.len(), 1);
        assert_eq!(
            duplicate_findings[0].evidence[0].observed,
            "example.com -> missing.example; status=NXDOMAIN"
        );
        dns.cname_chain.pop();
        dns.dangling_cnames.pop();

        for status in [
            DanglingCnameStatus::Resolved,
            DanglingCnameStatus::NoAddress,
            DanglingCnameStatus::Indeterminate,
        ] {
            dns.dangling_cnames[0].status = status;
            assert!(
                generate_findings(
                    "example.com",
                    Some(&dns),
                    &[],
                    &[],
                    &[],
                    &[],
                    time::OffsetDateTime::UNIX_EPOCH,
                )
                .is_empty()
            );
        }
        dns.dangling_cnames[0].status = DanglingCnameStatus::NxDomain;
        dns.dangling_cnames[0].canonical_target = "not-observed.example".to_owned();
        assert!(
            generate_findings(
                "example.com",
                Some(&dns),
                &[],
                &[],
                &[],
                &[],
                time::OffsetDateTime::UNIX_EPOCH,
            )
            .is_empty()
        );
    }

    #[test]
    fn only_complete_allowed_axfr_generates_a_finding() {
        let mut dns = DnsObservation {
            queried_name: "example.com".to_owned(),
            records: Vec::new(),
            cname_chain: Vec::new(),
            dangling_cnames: Vec::new(),
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
            dnssec: None,
            authoritative_axfr: Some(AuthoritativeAxfrObservation {
                zone: "example.com".to_owned(),
                nameservers: vec!["ns1.example.com".to_owned()],
                attempts: vec![AxfrAttempt {
                    server: "ns1.example.com".to_owned(),
                    endpoint: "192.0.2.53:53"
                        .parse()
                        .unwrap_or_else(|error| panic!("{error}")),
                    outcome: AxfrOutcome::Allowed,
                    response_code: Some("NoError".to_owned()),
                    messages: 2,
                    records: 3,
                    bytes: 256,
                    error: None,
                }],
                ..AuthoritativeAxfrObservation::default()
            }),
            wildcard_dns: None,
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
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "DNS-AXFR-ALLOWED");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, super::FindingConfidence::High);
        assert_eq!(findings[0].target, "example.com");

        for outcome in [
            AxfrOutcome::Refused,
            AxfrOutcome::NotAuthoritative,
            AxfrOutcome::Incomplete,
            AxfrOutcome::Unreachable,
            AxfrOutcome::Timeout,
            AxfrOutcome::Cancelled,
            AxfrOutcome::LimitExceeded,
        ] {
            dns.authoritative_axfr
                .as_mut()
                .expect("AXFR observation")
                .attempts[0]
                .outcome = outcome;
            assert!(
                generate_findings(
                    "example.com",
                    Some(&dns),
                    &[],
                    &[],
                    &[],
                    &[],
                    time::OffsetDateTime::UNIX_EPOCH,
                )
                .is_empty(),
                "unexpected finding for {outcome:?}"
            );
        }
    }

    #[test]
    fn ssh_legacy_finding_requires_an_exact_completed_inferred_selection() {
        let legacy_cases = [
            ("ssh_kex", "diffie-hellman-group14-sha1"),
            ("ssh_kex", "diffie-hellman-group1-sha1"),
            ("ssh_host_key_algorithm", "ssh-rsa"),
            ("ssh_host_key_algorithm", "ssh-dss"),
            ("ssh_cipher_c2s", "3des-cbc"),
            ("ssh_cipher_c2s", "arcfour"),
            ("ssh_cipher_c2s", "arcfour128"),
            ("ssh_cipher_c2s", "arcfour256"),
            ("ssh_cipher_s2c", "3des-cbc"),
            ("ssh_cipher_s2c", "arcfour"),
            ("ssh_cipher_s2c", "arcfour128"),
            ("ssh_cipher_s2c", "arcfour256"),
            ("ssh_mac_c2s", "hmac-sha1"),
            ("ssh_mac_c2s", "hmac-md5"),
            ("ssh_mac_c2s", "hmac-md5-96"),
            ("ssh_mac_s2c", "hmac-sha1"),
            ("ssh_mac_s2c", "hmac-md5"),
            ("ssh_mac_s2c", "hmac-md5-96"),
        ];
        for (field, algorithm) in legacy_cases {
            let service = ssh_service(Some(complete_ssh(field, algorithm)));
            let findings = generate_findings(
                "localhost",
                None,
                &[],
                std::slice::from_ref(&service),
                &[],
                &[],
                time::OffsetDateTime::UNIX_EPOCH,
            );
            let legacy = findings
                .iter()
                .find(|finding| finding.id == "NET-SSH-LEGACY-ALGORITHM")
                .unwrap_or_else(|| panic!("missing legacy finding for {field}={algorithm}"));
            assert_eq!(legacy.severity, Severity::Medium);
            assert_eq!(legacy.confidence, FindingConfidence::Medium);
            assert_eq!(legacy.evidence[0].observed, format!("{field}={algorithm}"));
            assert!(
                legacy
                    .description
                    .contains("before any completed key exchange")
            );
            assert!(
                legacy
                    .description
                    .contains("does not establish server preference")
            );
            assert!(
                legacy
                    .references
                    .iter()
                    .any(|reference| reference.contains("9142"))
            );
            assert!(findings.iter().all(|finding| !finding.id.contains("CVE")));
        }
    }

    #[test]
    fn ssh_legacy_finding_rejects_near_advertised_and_incomplete_evidence() {
        let near_matches = [
            ("ssh_kex", "diffie-hellman-group1-sha1@vendor"),
            ("ssh_host_key_algorithm", "ssh-dss-cert-v01@openssh.com"),
            ("ssh_cipher_c2s", "arcfour128x"),
            ("ssh_mac_s2c", "hmac-md5-etm@openssh.com"),
        ];
        for (field, algorithm) in near_matches {
            let service = ssh_service(Some(complete_ssh(field, algorithm)));
            let findings = generate_findings(
                "localhost",
                None,
                &[],
                std::slice::from_ref(&service),
                &[],
                &[],
                time::OffsetDateTime::UNIX_EPOCH,
            );
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.id != "NET-SSH-LEGACY-ALGORITHM")
            );
        }

        let negatives = [
            Some(complete_ssh("ssh_kex", "curve25519-sha256")),
            Some(SshPosture {
                identification: None,
                outcome: SshPostureOutcome::Partial {
                    selections: PartialSshAlgorithmSelections {
                        kex: Some("diffie-hellman-group1-sha1".to_owned()),
                        ..PartialSshAlgorithmSelections::default()
                    },
                    reason: "no common required algorithm: host_key".to_owned(),
                },
            }),
            None,
        ];
        for posture in negatives {
            let service = ssh_service(posture);
            let findings = generate_findings(
                "localhost",
                None,
                &[],
                std::slice::from_ref(&service),
                &[],
                &[],
                time::OffsetDateTime::UNIX_EPOCH,
            );
            assert_eq!(
                findings
                    .iter()
                    .map(|finding| finding.id.as_str())
                    .collect::<Vec<_>>(),
                ["NET-SSH-REACHABLE"]
            );
        }
    }

    #[test]
    fn tls_weakness_findings_require_exact_direct_evidence() {
        let findings_for = |observations: &[TlsObservation]| {
            generate_findings(
                "localhost",
                None,
                &[],
                &[],
                &[],
                observations,
                time::OffsetDateTime::UNIX_EPOCH,
            )
        };

        for bits in [1, 1024, 2047] {
            let mut observation = rejected_tls_observation();
            observation.public_key_algorithm = Some("1.2.840.113549.1.1.1".to_owned());
            observation.public_key_bits = Some(bits);
            let findings = findings_for(std::slice::from_ref(&observation));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, "TLS-CERT-WEAK-RSA-KEY");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].confidence, FindingConfidence::High);
            assert_eq!(
                findings[0].evidence[0].observed,
                format!("public_key_algorithm=1.2.840.113549.1.1.1, public_key_bits={bits}")
            );
        }
        for (algorithm, bits) in [
            (Some("1.2.840.113549.1.1.1"), None),
            (Some("1.2.840.113549.1.1.1"), Some(0)),
            (Some("1.2.840.113549.1.1.1"), Some(2048)),
            (Some("1.2.840.113549.1.1.1"), Some(4096)),
            (Some("1.2.840.113549.1.1.10"), Some(1024)),
            (Some("1.2.840.10045.2.1"), Some(256)),
            (None, Some(1024)),
        ] {
            let mut observation = rejected_tls_observation();
            observation.public_key_algorithm = algorithm.map(str::to_owned);
            observation.public_key_bits = bits;
            assert!(findings_for(&[observation]).is_empty());
        }

        for oid in [
            "1.2.840.113549.1.1.5",
            "1.2.840.10040.4.3",
            "1.2.840.10045.4.1",
        ] {
            let mut observation = rejected_tls_observation();
            observation.signature_algorithm = Some(oid.to_owned());
            let findings = findings_for(&[observation]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, "TLS-CERT-SHA1-SIGNATURE");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].confidence, FindingConfidence::High);
            assert_eq!(
                findings[0].evidence[0].observed,
                format!("signature_algorithm={oid}")
            );
        }
        for oid in [
            "1.2.840.113549.1.1.5.1",
            "1.2.840.10040.4.30",
            "1.2.840.10045.4.10",
            "1.2.840.10045.4.3.2",
            "sha1WithRSAEncryption",
            "",
        ] {
            let mut observation = rejected_tls_observation();
            observation.signature_algorithm = Some(oid.to_owned());
            assert!(findings_for(&[observation]).is_empty());
        }

        for protocol in ["TLSv1_0", "TLSv1_1"] {
            let mut json = serde_json::to_value(rejected_tls_observation())
                .unwrap_or_else(|error| panic!("{error}"));
            json["protocol_version"] = serde_json::Value::String(protocol.to_owned());
            let imported: TlsObservation =
                serde_json::from_value(json).unwrap_or_else(|error| panic!("{error}"));
            let findings = findings_for(&[imported]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, "TLS-OBSOLETE-PROTOCOL");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].confidence, FindingConfidence::High);
            assert_eq!(
                findings[0].evidence[0].observed,
                format!("protocol_version={protocol}")
            );
        }
        for protocol in ["TLSv1_0 ", "tlsv1_0", "TLSv1.0", "TLSv1_2", "TLSv1_3", ""] {
            let mut observation = rejected_tls_observation();
            observation.protocol_version = Some(protocol.to_owned());
            assert!(findings_for(&[observation]).is_empty());
        }
    }

    #[test]
    fn tls_weakness_findings_are_ordered_and_exactly_deduplicated() {
        let mut observation = rejected_tls_observation();
        observation.public_key_algorithm = Some("1.2.840.113549.1.1.1".to_owned());
        observation.public_key_bits = Some(1024);
        observation.signature_algorithm = Some("1.2.840.113549.1.1.5".to_owned());
        observation.protocol_version = Some("TLSv1_0".to_owned());
        let findings = generate_findings(
            "localhost",
            None,
            &[],
            &[],
            &[],
            &[observation.clone(), observation],
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            [
                "TLS-CERT-SHA1-SIGNATURE",
                "TLS-CERT-WEAK-RSA-KEY",
                "TLS-OBSOLETE-PROTOCOL",
            ]
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.confidence == FindingConfidence::High)
        );
    }

    #[test]
    fn failed_tls_validation_validity_findings_are_mutually_exclusive() {
        let address = "127.0.0.1:443"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        let service = ServiceObservation {
            transport: TransportProtocol::Tcp,
            address,
            service: ServiceKind::Https,
            confidence: DetectionConfidence::High,
            banner: None,
            protocol_details: std::collections::BTreeMap::new(),
            ssh: None,
        };
        let generic = TlsObservation {
            address,
            server_name: "localhost".to_owned(),
            handshake_succeeded: false,
            certificate_trusted: None,
            hostname_matches: None,
            protocol_version: None,
            cipher_suite: None,
            alpn: None,
            certificate_chain_length: Some(1),
            leaf_certificate_sha256: Some("00".repeat(32)),
            subject: Some("CN=localhost".to_owned()),
            issuer: Some("CN=localhost".to_owned()),
            serial_number: Some("01".to_owned()),
            valid_from_unix: None,
            valid_until_unix: None,
            subject_alt_names: vec!["localhost".to_owned()],
            subject_alt_names_truncated: false,
            public_key_algorithm: Some("1.2.840.10045.2.1".to_owned()),
            public_key_bits: Some(256),
            signature_algorithm: Some("1.2.840.10045.4.3.2".to_owned()),
            errors: vec!["certificate validation failed".to_owned()],
        };

        let generic_findings = generate_findings(
            "localhost",
            None,
            &[],
            std::slice::from_ref(&service),
            &[],
            std::slice::from_ref(&generic),
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(generic_findings.len(), 1);
        assert_eq!(generic_findings[0].id, "TLS-VALIDATION-FAILED");
        assert!(!generic_findings[0].description.contains("trust"));
        assert!(!generic_findings[0].description.contains("hostname"));

        let mut expired = generic.clone();
        expired.valid_from_unix = Some(-100);
        expired.valid_until_unix = Some(-1);
        let expired_findings = generate_findings(
            "localhost",
            None,
            &[],
            std::slice::from_ref(&service),
            &[],
            std::slice::from_ref(&expired),
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(
            expired_findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            ["TLS-CERT-EXPIRED", "TLS-VALIDATION-FAILED"]
        );

        for valid_until in [-1, 2_592_000] {
            let mut not_yet_valid = generic.clone();
            not_yet_valid.valid_from_unix = Some(1);
            not_yet_valid.valid_until_unix = Some(valid_until);
            let future_findings = generate_findings(
                "localhost",
                None,
                &[],
                std::slice::from_ref(&service),
                &[],
                std::slice::from_ref(&not_yet_valid),
                time::OffsetDateTime::UNIX_EPOCH,
            );
            assert_eq!(
                future_findings
                    .iter()
                    .map(|finding| finding.id.as_str())
                    .collect::<Vec<_>>(),
                ["TLS-CERT-NOT-YET-VALID", "TLS-VALIDATION-FAILED"]
            );
        }
    }

    #[test]
    fn bogus_dnssec_generates_one_high_confidence_finding() {
        let dns = DnsObservation {
            queried_name: "example.com".to_owned(),
            records: Vec::new(),
            cname_chain: Vec::new(),
            dangling_cnames: Vec::new(),
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
                status: DnssecStatus::Bogus,
                checked_rrsets: vec![DnssecRrsetObservation {
                    name: "example.com".to_owned(),
                    record_type: DnssecRecordType::A,
                    status: DnssecStatus::Bogus,
                }],
                errors: Vec::new(),
                limitations: Vec::new(),
            }),
            authoritative_axfr: None,
            wildcard_dns: None,
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

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "DNS-DNSSEC-BOGUS");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, super::FindingConfidence::High);

        for status in [
            DnssecStatus::Secure,
            DnssecStatus::Insecure,
            DnssecStatus::Indeterminate,
            DnssecStatus::NotApplicable,
        ] {
            let mut non_bogus_dns = dns.clone();
            let dnssec = non_bogus_dns.dnssec.as_mut().expect("DNSSEC observation");
            dnssec.status = status;
            dnssec.checked_rrsets[0].status = status;
            assert!(
                generate_findings(
                    "example.com",
                    Some(&non_bogus_dns),
                    &[],
                    &[],
                    &[],
                    &[],
                    time::OffsetDateTime::UNIX_EPOCH,
                )
                .is_empty()
            );
        }
    }
}
