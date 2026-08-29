use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    net::IpAddr,
    time::Duration,
};

use futures::StreamExt;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DnsObservation, ScanReport, analyze_dns, lookup_txt, normalize_target};

const MAX_SUBDOMAINS: usize = 32;
const MAX_SELECTORS: usize = 32;
const MAX_BUNDLE_ENTRIES: usize = 100_000;
const MAX_RELATED_DOMAINS: usize = 300;
const MAX_REVERSE_NS_RESPONSE_BYTES: usize = 1_048_576;
const REVERSE_NS_ENDPOINT: &str = "https://reverse-ns.whoisxmlapi.com/api/v1";
const MAX_CT_PAGES: usize = 3;
const MAX_CT_CANDIDATES: usize = 1_000;
const MAX_CT_RESPONSE_BYTES: usize = 1_048_576;
const CERTSPOTTER_ENDPOINT: &str = "https://api.certspotter.com/v1/issuances";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IntelligenceObservation {
    pub subdomains: Vec<SubdomainObservation>,
    pub dkim: Vec<DkimObservation>,
    pub networks: Vec<NetworkMetadata>,
    pub cve_candidates: Vec<CveCandidate>,
    pub bundle_version: Option<String>,
    #[serde(default)]
    pub related_domains: Option<RelatedDomainsObservation>,
    #[serde(default)]
    pub certificate_transparency: Option<CertificateTransparencyObservation>,
    pub complete: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubdomainObservation {
    pub name: String,
    pub dns: Option<DnsObservation>,
    pub error: Option<String>,
}

/// Passive domains sharing the exact observed nameserver pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedDomainsObservation {
    pub nameservers: Vec<String>,
    pub provider: Option<String>,
    pub candidates: Vec<RelatedDomainCandidate>,
    pub complete: bool,
    pub errors: Vec<String>,
}

/// Passive infrastructure-correlation candidate, not an ownership assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedDomainCandidate {
    pub name: String,
    pub matched_nameservers: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<String>,
}

/// Passive hostname candidates found in Certificate Transparency logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateTransparencyObservation {
    pub source: String,
    pub candidates: Vec<CertificateTransparencyCandidate>,
    pub issuance_count: usize,
    pub pages_fetched: usize,
    pub complete: bool,
    pub errors: Vec<String>,
}

/// A certificate DNS name; Surface does not automatically scan it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateTransparencyCandidate {
    pub name: String,
    pub wildcard: bool,
    pub issuance_count: usize,
}

#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReverseNsResponse {
    #[serde(default)]
    result: Vec<ReverseNsEntry>,
}

#[derive(Debug, Deserialize)]
struct ReverseNsEntry {
    name: String,
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

/// Finds bounded passive hostname candidates in Certificate Transparency logs.
///
/// Returned names are evidence only and are never scanned automatically.
///
/// # Errors
///
/// Returns an error when the target is not a hostname or `CertSpotter` is unavailable.
pub async fn analyze_certificate_transparency(
    report: &ScanReport,
    api_key: Option<&str>,
    request_timeout: Duration,
) -> Result<CertificateTransparencyObservation, String> {
    analyze_certificate_transparency_at(report, api_key, request_timeout, CERTSPOTTER_ENDPOINT)
        .await
}

async fn analyze_certificate_transparency_at(
    report: &ScanReport,
    api_key: Option<&str>,
    request_timeout: Duration,
    endpoint: &str,
) -> Result<CertificateTransparencyObservation, String> {
    let primary = report.target.hostname.as_deref().ok_or_else(|| {
        "certificate transparency discovery requires a hostname target".to_owned()
    })?;
    let client = Client::builder()
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("surface/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| "could not initialize certificate transparency client".to_owned())?;
    let mut issuances = Vec::new();
    let mut after = None;
    let mut complete = false;
    let mut pages_fetched = 0;
    for _ in 0..MAX_CT_PAGES {
        let page =
            fetch_certspotter_page(&client, endpoint, primary, api_key, after.as_deref()).await?;
        pages_fetched += 1;
        if page.is_empty() {
            complete = true;
            break;
        }
        after = page.last().map(|issuance| issuance.id.clone());
        if after.as_deref().is_none_or(str::is_empty) {
            return Err("certificate transparency response lacked a pagination ID".to_owned());
        }
        issuances.extend(page);
    }
    let issuance_count = issuances.len();
    let (candidates, candidates_truncated) = ct_candidates(primary, &issuances);
    let mut errors = Vec::new();
    if !complete {
        errors.push(format!(
            "certificate transparency pagination stopped after {MAX_CT_PAGES} pages"
        ));
    }
    if candidates_truncated {
        complete = false;
        errors.push(format!(
            "certificate transparency candidates were truncated at {MAX_CT_CANDIDATES} names"
        ));
    }
    Ok(CertificateTransparencyObservation {
        source: "CertSpotter".to_owned(),
        candidates,
        issuance_count,
        pages_fetched,
        complete,
        errors,
    })
}

async fn fetch_certspotter_page(
    client: &Client,
    endpoint: &str,
    domain: &str,
    api_key: Option<&str>,
    after: Option<&str>,
) -> Result<Vec<CertSpotterIssuance>, String> {
    let mut url = Url::parse(endpoint).map_err(|_| "invalid CertSpotter endpoint".to_owned())?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("domain", domain)
            .append_pair("include_subdomains", "true")
            .append_pair("match_wildcards", "true")
            .append_pair("expand", "dns_names");
        if let Some(after) = after {
            query.append_pair("after", after);
        }
    }
    let mut request = client.get(url);
    if let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) {
        request = request.bearer_auth(api_key);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "certificate transparency request failed".to_owned())?;
    if !response.status().is_success() {
        return Err(format!(
            "certificate transparency service returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "certificate transparency response failed".to_owned())?;
        if body.len().saturating_add(chunk.len()) > MAX_CT_RESPONSE_BYTES {
            return Err("certificate transparency response exceeded 1 MiB".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| "certificate transparency response was invalid".to_owned())
}

fn ct_candidates(
    primary: &str,
    issuances: &[CertSpotterIssuance],
) -> (Vec<CertificateTransparencyCandidate>, bool) {
    let suffix = format!(".{primary}");
    let mut counts = BTreeMap::<(String, bool), usize>::new();
    for raw_name in issuances.iter().flat_map(|issuance| &issuance.dns_names) {
        let raw_name = raw_name.trim().trim_end_matches('.').to_ascii_lowercase();
        let (wildcard, bare_name) = raw_name
            .strip_prefix("*.")
            .map_or((false, raw_name.as_str()), |name| (true, name));
        let Some(name) = normalize_target(bare_name)
            .ok()
            .and_then(|target| target.hostname)
        else {
            continue;
        };
        if (!wildcard && name == primary) || (name != primary && !name.ends_with(&suffix)) {
            continue;
        }
        let display_name = if wildcard { format!("*.{name}") } else { name };
        *counts.entry((display_name, wildcard)).or_default() += 1;
    }
    let truncated = counts.len() > MAX_CT_CANDIDATES;
    let candidates = counts
        .into_iter()
        .take(MAX_CT_CANDIDATES)
        .map(
            |((name, wildcard), issuance_count)| CertificateTransparencyCandidate {
                name,
                wildcard,
                issuance_count,
            },
        )
        .collect();
    (candidates, truncated)
}

/// Correlates domains sharing the exact observed nameserver pair.
///
/// This is passive infrastructure evidence and never an ownership assertion.
///
/// # Errors
///
/// Returns an error when the target lacks exactly two nameservers or configuration is invalid.
pub async fn analyze_related_domains(
    report: &ScanReport,
    api_key: &str,
    request_timeout: Duration,
) -> Result<RelatedDomainsObservation, String> {
    analyze_related_domains_at(report, api_key, request_timeout, REVERSE_NS_ENDPOINT).await
}

async fn analyze_related_domains_at(
    report: &ScanReport,
    api_key: &str,
    request_timeout: Duration,
    endpoint: &str,
) -> Result<RelatedDomainsObservation, String> {
    if api_key.trim().is_empty() {
        return Err("SURFACE_WHOISXML_API_KEY is empty".to_owned());
    }
    let primary = report
        .target
        .hostname
        .as_deref()
        .ok_or_else(|| "related-domain discovery requires a hostname target".to_owned())?;
    let nameservers = report
        .dns
        .as_ref()
        .into_iter()
        .flat_map(|dns| &dns.records)
        .filter_map(|record| match record {
            crate::DnsRecord::Ns(name) => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if nameservers.len() != 2 {
        return Err(
            "related-domain discovery requires exactly two observed nameservers".to_owned(),
        );
    }

    let client = Client::builder()
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "could not initialize reverse-NS client".to_owned())?;
    let (left, right) = tokio::join!(
        fetch_reverse_ns(&client, endpoint, api_key, &nameservers[0]),
        fetch_reverse_ns(&client, endpoint, api_key, &nameservers[1])
    );
    let mut observation = RelatedDomainsObservation {
        nameservers: nameservers.clone(),
        provider: identify_nameserver_provider(&nameservers),
        candidates: Vec::new(),
        complete: true,
        errors: Vec::new(),
    };
    let ((left, left_truncated), (right, right_truncated)) = match (left, right) {
        (Ok(left), Ok(right)) => (left, right),
        (left, right) => {
            observation.complete = false;
            if let Err(error) = left {
                observation.errors.push(error);
            }
            if let Err(error) = right {
                observation.errors.push(error);
            }
            return Ok(observation);
        }
    };
    if left_truncated || right_truncated {
        observation.complete = false;
        observation
            .errors
            .push("reverse-NS results were truncated at 300 domains per nameserver".to_owned());
    }
    observation.candidates = related_candidates(primary, &nameservers, &left, &right);
    Ok(observation)
}

async fn fetch_reverse_ns(
    client: &Client,
    endpoint: &str,
    api_key: &str,
    nameserver: &str,
) -> Result<(BTreeSet<String>, bool), String> {
    let mut url = Url::parse(endpoint).map_err(|_| "invalid reverse-NS endpoint".to_owned())?;
    url.query_pairs_mut()
        .append_pair("apiKey", api_key)
        .append_pair("ns", nameserver)
        .append_pair("outputFormat", "JSON");
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "reverse-NS request failed".to_owned())?;
    if !response.status().is_success() {
        return Err("reverse-NS service returned an error".to_owned());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "reverse-NS response failed".to_owned())?;
        if body.len().saturating_add(chunk.len()) > MAX_REVERSE_NS_RESPONSE_BYTES {
            return Err("reverse-NS response exceeded 1 MiB".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    let response: ReverseNsResponse =
        serde_json::from_slice(&body).map_err(|_| "reverse-NS response was invalid".to_owned())?;
    let truncated = response.result.len() >= MAX_RELATED_DOMAINS;
    let names = response
        .result
        .into_iter()
        .take(MAX_RELATED_DOMAINS)
        .filter_map(|entry| {
            normalize_target(&entry.name)
                .ok()
                .and_then(|target| target.hostname)
        })
        .collect();
    Ok((names, truncated))
}

fn related_candidates(
    primary: &str,
    nameservers: &[String],
    left: &BTreeSet<String>,
    right: &BTreeSet<String>,
) -> Vec<RelatedDomainCandidate> {
    left.intersection(right)
        .filter(|name| name.as_str() != primary)
        .take(MAX_RELATED_DOMAINS)
        .map(|name| RelatedDomainCandidate {
            name: name.clone(),
            matched_nameservers: nameservers.to_vec(),
            confidence: "medium".to_owned(),
            evidence: vec![
                "Exact nameserver-pair match in passive reverse-NS data".to_owned(),
                "Shared DNS infrastructure does not prove common ownership".to_owned(),
            ],
        })
        .collect()
}

fn identify_nameserver_provider(nameservers: &[String]) -> Option<String> {
    let providers = [
        ("cloudflare.com", "Cloudflare"),
        ("domaincontrol.com", "GoDaddy"),
        ("googledomains.com", "Google Cloud DNS"),
        ("dns-parking.com", "Hostinger"),
    ];
    providers.iter().find_map(|(suffix, provider)| {
        nameservers
            .iter()
            .all(|nameserver| nameserver == suffix || nameserver.ends_with(&format!(".{suffix}")))
            .then(|| (*provider).to_owned())
    })
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
        collections::{BTreeMap, BTreeSet},
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use reqwest::Client;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use crate::{
        DetectionConfidence, HostObservation, PortObservation, PortState, ScanConfiguration,
        ScanReport, ServiceKind, ServiceObservation, TransportProtocol, normalize_target,
    };

    use super::{
        CertSpotterIssuance, MAX_CT_RESPONSE_BYTES, analyze_certificate_transparency_at,
        analyze_intelligence, correlate_cves, correlate_networks, ct_candidates,
        fetch_certspotter_page, identify_nameserver_provider, parse_bundle, related_candidates,
    };

    async fn mock_http_response(
        status: &str,
        extra_headers: &str,
        body: Vec<u8>,
    ) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let status = status.to_owned();
        let extra_headers = extra_headers.to_owned();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1_024];
            while request.len() < 16 * 1_024 {
                let read = socket
                    .read(&mut chunk)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n",
                body.len()
            );
            let _ = socket.write_all(headers.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            String::from_utf8_lossy(&request).into_owned()
        });
        (format!("http://{address}/v1/issuances"), task)
    }

    fn report() -> ScanReport {
        let mut report = ScanReport::not_started(
            normalize_target("example.com").unwrap_or_else(|error| panic!("{error}")),
            ScanConfiguration {
                ports: vec![22],
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
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 22);
        report.hosts.push(HostObservation {
            ip: address.ip(),
            ports: vec![PortObservation {
                transport: TransportProtocol::Tcp,
                address,
                state: PortState::Open,
                latency_ms: None,
                error: None,
            }],
        });
        report.services.push(ServiceObservation {
            transport: TransportProtocol::Tcp,
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
    async fn certspotter_request_uses_bearer_and_pagination_cursor() {
        let (endpoint, request) = mock_http_response(
            "200 OK",
            "Content-Type: application/json\r\n",
            br#"[{"id":"next","dns_names":["api.example.com"]}]"#.to_vec(),
        )
        .await;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|error| panic!("{error}"));

        let page = fetch_certspotter_page(
            &client,
            &endpoint,
            "example.com",
            Some("secret"),
            Some("cursor-1"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let request = request.await.unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(page.len(), 1);
        assert!(request.contains("domain=example.com"));
        assert!(request.contains("after=cursor-1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer secret\r\n")
        );
    }

    #[tokio::test]
    async fn certspotter_rejects_redirects_and_oversized_responses() {
        let (redirect_target, target_task) = mock_http_response(
            "200 OK",
            "Content-Type: application/json\r\n",
            b"[]".to_vec(),
        )
        .await;
        let (redirect, redirect_task) = mock_http_response(
            "302 Found",
            &format!("Location: {redirect_target}\r\n"),
            Vec::new(),
        )
        .await;
        let error = analyze_certificate_transparency_at(
            &report(),
            Some("secret"),
            std::time::Duration::from_secs(1),
            &redirect,
        )
        .await
        .expect_err("redirect must not be followed");
        assert!(error.contains("HTTP 302"));
        let _ = redirect_task.await;
        target_task.abort();

        let (oversized, oversized_task) = mock_http_response(
            "200 OK",
            "Content-Type: application/json\r\n",
            vec![b' '; MAX_CT_RESPONSE_BYTES + 1],
        )
        .await;
        let client = Client::new();
        let error = fetch_certspotter_page(&client, &oversized, "example.com", None, None)
            .await
            .expect_err("oversized response must fail");
        assert!(error.contains("exceeded 1 MiB"));
        let _ = oversized_task.await;
    }

    #[tokio::test]
    async fn certspotter_reports_http_and_malformed_response_errors() {
        let client = Client::new();
        let (rate_limited, rate_task) =
            mock_http_response("429 Too Many Requests", "", Vec::new()).await;
        let error = fetch_certspotter_page(&client, &rate_limited, "example.com", None, None)
            .await
            .expect_err("HTTP error must fail");
        assert!(error.contains("HTTP 429"));
        let _ = rate_task.await;

        let (malformed, malformed_task) =
            mock_http_response("200 OK", "", b"not-json".to_vec()).await;
        let error = fetch_certspotter_page(&client, &malformed, "example.com", None, None)
            .await
            .expect_err("malformed JSON must fail");
        assert!(error.contains("response was invalid"));
        let _ = malformed_task.await;
    }

    #[test]
    fn certificate_transparency_candidates_are_scoped_and_deduplicated() {
        let issuances = vec![
            CertSpotterIssuance {
                id: "1".to_owned(),
                dns_names: vec![
                    "example.com".to_owned(),
                    "api.example.com".to_owned(),
                    "*.example.com".to_owned(),
                    "outside.test".to_owned(),
                ],
            },
            CertSpotterIssuance {
                id: "2".to_owned(),
                dns_names: vec!["API.EXAMPLE.COM.".to_owned()],
            },
        ];

        let (candidates, truncated) = ct_candidates("example.com", &issuances);

        assert!(!truncated);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].name, "*.example.com");
        assert!(candidates[0].wildcard);
        assert_eq!(candidates[1].name, "api.example.com");
        assert_eq!(candidates[1].issuance_count, 2);
    }

    #[test]
    fn related_domains_require_both_nameservers_and_do_not_assert_ownership() {
        let nameservers = vec![
            "alice.ns.cloudflare.com".to_owned(),
            "bob.ns.cloudflare.com".to_owned(),
        ];
        assert_eq!(
            identify_nameserver_provider(&nameservers).as_deref(),
            Some("Cloudflare")
        );
        let left = BTreeSet::from([
            "example.com".to_owned(),
            "related.example".to_owned(),
            "left-only.example".to_owned(),
        ]);
        let right = BTreeSet::from([
            "example.com".to_owned(),
            "related.example".to_owned(),
            "right-only.example".to_owned(),
        ]);
        let candidates = related_candidates("example.com", &nameservers, &left, &right);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "related.example");
        assert!(
            candidates[0]
                .evidence
                .iter()
                .any(|item| item.contains("does not prove"))
        );
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
