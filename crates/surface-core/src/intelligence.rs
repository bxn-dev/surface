use std::{collections::BTreeSet, fmt::Write as _, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DnsObservation, ScanReport, analyze_dns, lookup_txt, normalize_target};

const MAX_SUBDOMAINS: usize = 32;
const MAX_SELECTORS: usize = 32;
const MAX_BUNDLE_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IntelligenceObservation {
    pub subdomains: Vec<SubdomainObservation>,
    pub dkim: Vec<DkimObservation>,
    pub networks: Vec<NetworkMetadata>,
    pub cve_candidates: Vec<CveCandidate>,
    pub bundle_version: Option<String>,
    pub complete: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubdomainObservation {
    pub name: String,
    pub dns: Option<DnsObservation>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimObservation {
    pub selector: String,
    pub records: usize,
    pub version: Option<String>,
    pub key_type: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub revoked: bool,
    pub malformed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMetadata {
    pub address: IpAddr,
    pub prefix: String,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveCandidate {
    pub cve_id: String,
    pub product: String,
    pub version: String,
    pub severity: String,
    pub advisory_url: String,
    pub source: String,
    pub confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelligenceBundle {
    pub schema_version: String,
    pub source: String,
    pub source_timestamp: i64,
    #[serde(default)]
    pub networks: Vec<NetworkEntry>,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnerabilityEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEntry {
    pub prefix: String,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityEntry {
    pub product: String,
    pub version: String,
    pub cve_id: String,
    pub severity: String,
    pub advisory_url: String,
}

/// Parses and validates a bounded offline intelligence bundle.
///
/// # Errors
///
/// Returns an error for unsupported schemas, excessive entries, or malformed bounded fields.
pub fn parse_bundle(json: &[u8]) -> Result<IntelligenceBundle, String> {
    if json.len() > 16 * 1024 * 1024 {
        return Err("intelligence bundle exceeds 16 MiB".to_owned());
    }
    let mut bundle: IntelligenceBundle = serde_json::from_slice(json)
        .map_err(|error| format!("invalid intelligence bundle: {error}"))?;
    if bundle.schema_version != "1.0" {
        return Err("unsupported intelligence bundle schema".to_owned());
    }
    if bundle
        .networks
        .len()
        .saturating_add(bundle.vulnerabilities.len())
        > MAX_BUNDLE_ENTRIES
    {
        return Err("intelligence bundle has too many entries".to_owned());
    }
    for entry in &bundle.networks {
        parse_prefix(&entry.prefix)?;
        bounded(entry.organization.as_ref(), 512)?;
        bounded(entry.country.as_ref(), 8)?;
    }
    for entry in &bundle.vulnerabilities {
        if !valid_cve(&entry.cve_id) || !entry.advisory_url.starts_with("https://") {
            return Err("intelligence bundle contains an invalid advisory".to_owned());
        }
        for value in [
            &entry.product,
            &entry.version,
            &entry.severity,
            &entry.advisory_url,
        ] {
            if value.is_empty() || value.len() > 1_024 {
                return Err("intelligence bundle contains invalid text".to_owned());
            }
        }
    }
    bundle
        .networks
        .sort_by(|left, right| left.prefix.cmp(&right.prefix));
    bundle.vulnerabilities.sort_by(|left, right| {
        left.cve_id
            .cmp(&right.cve_id)
            .then(left.product.cmp(&right.product))
            .then(left.version.cmp(&right.version))
    });
    Ok(bundle)
}

/// Collects only explicitly supplied passive DNS/DKIM observations and offline correlations.
///
/// # Errors
///
/// Returns an error when supplied names/selectors violate scope or count limits.
pub async fn analyze_intelligence(
    report: &ScanReport,
    subdomains: &[String],
    selectors: &[String],
    bundle: Option<&IntelligenceBundle>,
    timeout: Duration,
) -> Result<IntelligenceObservation, String> {
    let primary = report
        .target
        .hostname
        .as_deref()
        .ok_or_else(|| "intelligence inputs require a domain target".to_owned())?;
    if subdomains.len() > MAX_SUBDOMAINS || selectors.len() > MAX_SELECTORS {
        return Err("too many supplied intelligence inputs".to_owned());
    }
    let mut observation = IntelligenceObservation {
        complete: true,
        bundle_version: bundle.map(|value| value.schema_version.clone()),
        ..IntelligenceObservation::default()
    };
    let mut names = BTreeSet::new();
    for input in subdomains {
        let target =
            normalize_target(input).map_err(|_| "invalid supplied subdomain".to_owned())?;
        let name = target
            .hostname
            .ok_or_else(|| "supplied subdomain must be a hostname".to_owned())?;
        if name == primary || !name.ends_with(&format!(".{primary}")) || !names.insert(name.clone())
        {
            return Err(
                "supplied subdomain is outside the primary domain or duplicated".to_owned(),
            );
        }
        match analyze_dns(
            &normalize_target(&name).map_err(|_| "invalid supplied subdomain".to_owned())?,
            timeout,
            false,
            false,
        )
        .await
        {
            Ok(dns) => observation.subdomains.push(SubdomainObservation {
                name,
                dns: Some(dns),
                error: None,
            }),
            Err(error) => {
                observation.complete = false;
                observation.subdomains.push(SubdomainObservation {
                    name,
                    dns: None,
                    error: Some(error),
                });
            }
        }
    }
    for selector in selectors {
        validate_selector(selector)?;
        let records = lookup_txt(&format!("{selector}._domainkey.{primary}"), timeout)
            .await
            .unwrap_or_default();
        observation.dkim.push(parse_dkim(selector, &records));
    }
    if let Some(bundle) = bundle {
        observation.networks = correlate_networks(report, bundle);
        observation.cve_candidates = correlate_cves(report, bundle);
    }
    observation
        .subdomains
        .sort_by(|left, right| left.name.cmp(&right.name));
    observation
        .dkim
        .sort_by(|left, right| left.selector.cmp(&right.selector));
    Ok(observation)
}

fn parse_dkim(selector: &str, records: &[String]) -> DkimObservation {
    let joined = records.first().cloned().unwrap_or_default();
    let tags = joined
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    let key = tags.get("p").copied();
    DkimObservation {
        selector: selector.to_owned(),
        records: records.len(),
        version: tags.get("v").map(|value| (*value).to_owned()),
        key_type: tags.get("k").map(|value| (*value).to_owned()),
        public_key_fingerprint: key
            .filter(|value| !value.is_empty())
            .map(|value| format!("sha256:{}", hex(&Sha256::digest(value.as_bytes())))),
        revoked: key == Some(""),
        malformed: records.len() > 1
            || (!joined.is_empty() && (tags.get("v") != Some(&"DKIM1") || key.is_none())),
    }
}

fn correlate_networks(report: &ScanReport, bundle: &IntelligenceBundle) -> Vec<NetworkMetadata> {
    let mut output = Vec::new();
    for address in report.hosts.iter().map(|host| host.ip) {
        let best = bundle
            .networks
            .iter()
            .filter_map(|entry| {
                parse_prefix(&entry.prefix)
                    .ok()
                    .map(|prefix| (entry, prefix))
            })
            .filter(|(_, prefix)| prefix.contains(address))
            .max_by_key(|(_, prefix)| prefix.length);
        if let Some((entry, _)) = best {
            output.push(NetworkMetadata {
                address,
                prefix: entry.prefix.clone(),
                asn: entry.asn,
                organization: entry.organization.clone(),
                country: entry.country.clone(),
            });
        }
    }
    output.sort_by_key(|entry| entry.address);
    output
}

fn correlate_cves(report: &ScanReport, bundle: &IntelligenceBundle) -> Vec<CveCandidate> {
    let mut products = BTreeSet::new();
    for service in &report.services {
        if let Some(banner) = &service.banner {
            if let Some(rest) = banner.strip_prefix("SSH-2.0-OpenSSH_") {
                let version = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or(rest)
                    .replace('p', ".");
                products.insert(("openssh".to_owned(), version));
            }
        }
    }
    let mut output = bundle
        .vulnerabilities
        .iter()
        .filter(|entry| {
            products.contains(&(entry.product.to_ascii_lowercase(), entry.version.clone()))
        })
        .map(|entry| CveCandidate {
            cve_id: entry.cve_id.clone(),
            product: entry.product.clone(),
            version: entry.version.clone(),
            severity: entry.severity.clone(),
            advisory_url: entry.advisory_url.clone(),
            source: bundle.source.clone(),
            confidence: "candidate".to_owned(),
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| {
        left.cve_id
            .cmp(&right.cve_id)
            .then(left.product.cmp(&right.product))
    });
    output
}

#[derive(Clone, Copy)]
struct Prefix {
    network: IpAddr,
    length: u8,
}
impl Prefix {
    fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.length == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.length)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.length == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.length)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}
fn parse_prefix(value: &str) -> Result<Prefix, String> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| "network prefix is invalid".to_owned())?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| "network prefix is invalid".to_owned())?;
    let length = length
        .parse::<u8>()
        .map_err(|_| "network prefix is invalid".to_owned())?;
    if length > if address.is_ipv4() { 32 } else { 128 } {
        return Err("network prefix is invalid".to_owned());
    }
    Ok(Prefix {
        network: address,
        length,
    })
}
fn validate_selector(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid DKIM selector".to_owned());
    }
    Ok(())
}
fn bounded(value: Option<&String>, max: usize) -> Result<(), String> {
    if value.is_some_and(|value| value.len() > max) {
        Err("intelligence field is oversized".to_owned())
    } else {
        Ok(())
    }
}
fn valid_cve(value: &str) -> bool {
    value.starts_with("CVE-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use crate::{
        DetectionConfidence, HostObservation, PortObservation, PortState, ScanConfiguration,
        ScanReport, ServiceKind, ServiceObservation, normalize_target,
    };

    use super::{analyze_intelligence, correlate_cves, correlate_networks, parse_bundle};

    fn report() -> ScanReport {
        let mut report = ScanReport::not_started(
            normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![22],
                concurrency: 1,
                connect_timeout_ms: 100,
                request_timeout_ms: 100,
                global_timeout_ms: 1_000,
                ipv4_only: false,
                ipv6_only: false,
                authorization_acknowledged: true,
            },
        );
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 22);
        report.hosts.push(HostObservation {
            ip: address.ip(),
            ports: vec![PortObservation {
                address,
                state: PortState::Open,
                latency_ms: None,
                error: None,
            }],
        });
        report.services.push(ServiceObservation {
            address,
            service: ServiceKind::Ssh,
            confidence: DetectionConfidence::High,
            banner: Some("SSH-2.0-OpenSSH_9.3p1".to_owned()),
            protocol_details: BTreeMap::default(),
        });
        report
    }

    #[test]
    fn offline_bundle_uses_longest_prefix_and_exact_version() {
        let bundle = parse_bundle(br#"{
          "schema_version":"1.0","source":"fixture","source_timestamp":1,
          "networks":[
            {"prefix":"8.0.0.0/8","asn":1,"organization":"broad","country":"US"},
            {"prefix":"8.8.8.0/24","asn":2,"organization":"specific","country":"US"}
          ],
          "vulnerabilities":[
            {"product":"openssh","version":"9.3.1","cve_id":"CVE-2024-0001","severity":"high","advisory_url":"https://example.invalid/CVE-2024-0001"}
          ]
        }"#).unwrap_or_else(|error| panic!("{error}"));
        let report = report();
        let networks = correlate_networks(&report, &bundle);
        assert_eq!(networks.first().and_then(|value| value.asn), Some(2));
        assert_eq!(correlate_cves(&report, &bundle).len(), 1);
    }

    #[tokio::test]
    async fn supplied_subdomain_scope_fails_before_dns() {
        let error = analyze_intelligence(
            &report(),
            &["example.com.evil.invalid".to_owned()],
            &[],
            None,
            std::time::Duration::from_millis(10),
        )
        .await
        .expect_err("sibling must fail");
        assert!(error.contains("outside"));
    }
}
