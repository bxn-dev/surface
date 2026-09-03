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
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::{
    DnsObservation, ScanReport, ScanStatus, SkippedCheck, analyze_dns, lookup_txt,
    normalize_target,
    passive_http::{FetchError, PinnedClients, get_bounded, is_public_destination},
};

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

// RDAP limits bound fan-out, memory, recursion, and retained administrative data.
const MAX_RDAP_ADDRESSES: usize = 8;
const MAX_RDAP_CONCURRENCY: usize = 4;
const MAX_BOOTSTRAP_BYTES: usize = 64 * 1_024;
const MAX_RDAP_RESPONSE_BYTES: usize = 256 * 1_024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_BOOTSTRAP_SERVICES: usize = 64;
const MAX_BOOTSTRAP_PREFIXES: usize = 1_024;
const MAX_BOOTSTRAP_ALTERNATES: usize = 8;
const MAX_BOOTSTRAP_STRING_BYTES: usize = 512;
const MAX_RDAP_STATUSES: usize = 16;
const MAX_RDAP_STATUS_BYTES: usize = 64;
const MAX_RDAP_HANDLE_BYTES: usize = 256;
const MAX_RDAP_NAME_BYTES: usize = 256;
const MAX_RDAP_TYPE_BYTES: usize = 128;
const MAX_RDAP_COUNTRY_BYTES: usize = 2;
const IANA_IPV4_BOOTSTRAP: &str = "https://data.iana.org/rdap/ipv4.json";
const IANA_IPV6_BOOTSTRAP: &str = "https://data.iana.org/rdap/ipv6.json";

// RIPEstat bounds limit fan-out, retained ambiguity, and untrusted response data.
const MAX_BGP_ADDRESSES: usize = 8;
const MAX_BGP_CONCURRENCY: usize = 4;
const MAX_BGP_RESPONSE_BYTES: usize = 128 * 1_024;
const MAX_BGP_ORIGIN_ASNS: usize = 4;
const RIPESTAT_NETWORK_INFO: &str = "https://stat.ripe.net/data/network-info/data.json";
const RIPESTAT_SOURCE: &str = "RIPE RIS via RIPEstat";
const RIPESTAT_OBSERVER_LIMITATION: &str =
    "RIPE RIS is observer-dependent and network-info uses eight-hour data dumps";

#[derive(Debug, Clone, Copy)]
struct AllowedRdapBase {
    scheme: &'static str,
    host: &'static str,
    port: Option<u16>,
    base_path: &'static str,
    registry: &'static str,
}

const OFFICIAL_RDAP_BASES: &[AllowedRdapBase] = &[
    AllowedRdapBase {
        scheme: "https",
        host: "rdap.arin.net",
        port: None,
        base_path: "/registry/",
        registry: "ARIN",
    },
    AllowedRdapBase {
        scheme: "https",
        host: "rdap.db.ripe.net",
        port: None,
        base_path: "/",
        registry: "RIPE NCC",
    },
    AllowedRdapBase {
        scheme: "https",
        host: "rdap.apnic.net",
        port: None,
        base_path: "/",
        registry: "APNIC",
    },
    AllowedRdapBase {
        scheme: "https",
        host: "rdap.lacnic.net",
        port: None,
        base_path: "/rdap/",
        registry: "LACNIC",
    },
    AllowedRdapBase {
        scheme: "https",
        host: "rdap.afrinic.net",
        port: None,
        base_path: "/rdap/",
        registry: "AFRINIC",
    },
];

#[derive(Clone, Copy)]
struct RdapConfig<'a> {
    ipv4_bootstrap: &'a str,
    ipv6_bootstrap: &'a str,
    allowed_bases: &'a [AllowedRdapBase],
}

const PRODUCTION_RDAP_CONFIG: RdapConfig<'static> = RdapConfig {
    ipv4_bootstrap: IANA_IPV4_BOOTSTRAP,
    ipv6_bootstrap: IANA_IPV6_BOOTSTRAP,
    allowed_bases: OFFICIAL_RDAP_BASES,
};

#[derive(Clone, Copy)]
struct BgpConfig<'a> {
    endpoint: &'a str,
    scheme: &'a str,
    host: &'a str,
    port: Option<u16>,
    path: &'a str,
}

const PRODUCTION_BGP_CONFIG: BgpConfig<'static> = BgpConfig {
    endpoint: RIPESTAT_NETWORK_INFO,
    scheme: "https",
    host: "stat.ripe.net",
    port: None,
    path: "/data/network-info/data.json",
};

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
    /// Administrative IP-allocation evidence from authoritative RDAP registries.
    #[serde(default)]
    pub network_registrations: Vec<NetworkRegistrationObservation>,
    /// Observer-based routed-prefix and origin-ASN evidence from RIPE RIS.
    #[serde(default)]
    pub bgp_routes: Vec<BgpRouteObservation>,
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

/// Authoritative administrative registration evidence for one primary DNS address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRegistrationObservation {
    /// Canonical address queried once through RDAP.
    pub address: IpAddr,
    /// Stable evidence source identifier.
    pub source: String,
    /// Authoritative regional registry selected by IANA bootstrap data.
    pub registry: String,
    /// Registry-unique network handle when supplied.
    pub handle: Option<String>,
    /// Registration holder-assigned network name when supplied.
    pub name: Option<String>,
    /// Registry-specific administrative network classification.
    pub network_type: Option<String>,
    /// Registered range start when supplied with a coherent end.
    pub start_address: Option<IpAddr>,
    /// Registered range end when supplied with a coherent start.
    pub end_address: Option<IpAddr>,
    /// Registration country code; this is not geolocation evidence.
    pub registration_country: Option<String>,
    /// Bounded registry statuses.
    pub statuses: Vec<String>,
}

/// Observer-based route and origin evidence for one primary DNS address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpRouteObservation {
    /// Canonical address queried once through `RIPEstat`.
    pub address: IpAddr,
    /// Routed prefix reported by `network-info`, or none when no route was observed.
    pub prefix: Option<String>,
    /// Sorted unique observed origin ASNs; no canonical origin is selected.
    pub origin_asns: Vec<u32>,
    /// Stable evidence source identifier.
    pub source: String,
    /// Whether the successful response was retained coherently without local truncation.
    ///
    /// This does not claim globally complete routing visibility or attribution.
    pub complete: bool,
    /// Bounded caveats about observer coverage, conflicts, or truncation.
    pub limitations: Vec<String>,
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

#[derive(Debug, Deserialize)]
struct RdapBootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Deserialize)]
struct RdapNetworkResponse {
    #[serde(rename = "objectClassName")]
    object_class_name: Option<String>,
    handle: Option<String>,
    name: Option<String>,
    #[serde(rename = "type")]
    network_type: Option<String>,
    #[serde(rename = "startAddress")]
    start_address: Option<String>,
    #[serde(rename = "endAddress")]
    end_address: Option<String>,
    country: Option<String>,
    #[serde(default)]
    status: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RipeStatEnvelope {
    status: String,
    status_code: u16,
    data_call_name: String,
    data_call_status: String,
    version: String,
    data: RipeStatNetworkInfo,
}

#[derive(Debug, Deserialize)]
struct RipeStatNetworkInfo {
    asns: Vec<String>,
    prefix: String,
}

#[derive(Debug, Clone)]
struct BootstrapEntry {
    prefix: Prefix,
    endpoint: Option<ApprovedRdapBase>,
}

#[derive(Debug, Clone)]
struct ApprovedRdapBase {
    url: Url,
    policy: AllowedRdapBase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdapStop {
    Cancelled,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BgpStop {
    Cancelled,
    Deadline,
}

/// Collects bounded authoritative administrative registration evidence.
///
/// Only eligible addresses already present in primary DNS results are queried. Returned ranges,
/// links, and entities never become scan targets or inputs to other intelligence checks.
pub async fn analyze_network_registrations(
    report: &mut ScanReport,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) {
    analyze_network_registrations_with(
        report,
        request_timeout,
        deadline,
        cancellation,
        PRODUCTION_RDAP_CONFIG,
        PinnedClients::new(request_timeout),
    )
    .await;
}

#[expect(
    clippy::too_many_lines,
    reason = "bounded RDAP orchestration keeps one shared deadline and lifecycle transition"
)]
async fn analyze_network_registrations_with(
    report: &mut ScanReport,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    config: RdapConfig<'_>,
    mut clients: PinnedClients,
) {
    let (addresses, truncated) = eligible_rdap_addresses(report);
    if addresses.is_empty() {
        record_network_registration_skip(
            report,
            "no eligible external address in primary DNS results",
        );
        return;
    }

    let mut failures = BTreeSet::new();
    if truncated {
        failures.insert("address limit reached");
    }
    let mut ipv4_entries = None;
    let mut ipv6_entries = None;
    for (ipv6, endpoint) in [
        (false, config.ipv4_bootstrap),
        (true, config.ipv6_bootstrap),
    ] {
        if !addresses.iter().any(|address| address.is_ipv6() == ipv6) {
            continue;
        }
        let Ok(url) = Url::parse(endpoint) else {
            failures.insert("bootstrap endpoint was invalid");
            continue;
        };
        let body = match async {
            let client = clients.client_for(&url, deadline, cancellation).await?;
            get_bounded(
                &client,
                url,
                MAX_BOOTSTRAP_BYTES,
                request_timeout,
                deadline,
                cancellation,
            )
            .await
        }
        .await
        {
            Ok(body) => body,
            Err(FetchError::Cancelled) => {
                finish_network_registrations(
                    report,
                    Vec::new(),
                    failures,
                    Some(RdapStop::Cancelled),
                );
                return;
            }
            Err(FetchError::Deadline) => {
                finish_network_registrations(
                    report,
                    Vec::new(),
                    failures,
                    Some(RdapStop::Deadline),
                );
                return;
            }
            Err(error) => {
                failures.insert(bootstrap_fetch_reason(error));
                continue;
            }
        };
        match parse_bootstrap(&body, ipv6, config.allowed_bases) {
            Ok(entries) if ipv6 => ipv6_entries = Some(entries),
            Ok(entries) => ipv4_entries = Some(entries),
            Err(reason) => {
                failures.insert(reason);
            }
        }
    }

    let mut requests = Vec::new();
    for address in addresses {
        let entries = if address.is_ipv4() {
            ipv4_entries.as_deref()
        } else {
            ipv6_entries.as_deref()
        };
        let Some(entries) = entries else {
            failures.insert("bootstrap data unavailable for an address family");
            continue;
        };
        let Some(endpoint) = longest_bootstrap_endpoint(address, entries) else {
            failures.insert("bootstrap had no approved authoritative endpoint");
            continue;
        };
        match construct_rdap_url(&endpoint, address) {
            Ok(url) => match clients.client_for(&url, deadline, cancellation).await {
                Ok(client) => requests.push((address, endpoint.policy.registry, url, client)),
                Err(FetchError::Cancelled) => {
                    finish_network_registrations(
                        report,
                        Vec::new(),
                        failures,
                        Some(RdapStop::Cancelled),
                    );
                    return;
                }
                Err(FetchError::Deadline) => {
                    finish_network_registrations(
                        report,
                        Vec::new(),
                        failures,
                        Some(RdapStop::Deadline),
                    );
                    return;
                }
                Err(error) => {
                    failures.insert(rdap_fetch_reason(error));
                }
            },
            Err(reason) => {
                failures.insert(reason);
            }
        }
    }

    let lookups = futures::stream::iter(requests.into_iter().map(
        |(address, registry, url, client)| async move {
            let response = get_bounded(
                &client,
                url,
                MAX_RDAP_RESPONSE_BYTES,
                request_timeout,
                deadline,
                cancellation,
            )
            .await;
            (address, registry, response)
        },
    ))
    .buffer_unordered(MAX_RDAP_CONCURRENCY);
    futures::pin_mut!(lookups);

    let mut observations = Vec::new();
    let mut stop = None;
    while let Some((address, registry, response)) = lookups.next().await {
        match response {
            Ok(body) => match parse_rdap_response(&body, address, registry) {
                Ok(observation) => observations.push(observation),
                Err(reason) => {
                    failures.insert(reason);
                }
            },
            Err(FetchError::Cancelled) => {
                stop = Some(RdapStop::Cancelled);
                break;
            }
            Err(FetchError::Deadline) => {
                stop = Some(RdapStop::Deadline);
                break;
            }
            Err(error) => {
                failures.insert(rdap_fetch_reason(error));
            }
        }
    }
    finish_network_registrations(report, observations, failures, stop);
}

fn eligible_rdap_addresses(report: &ScanReport) -> (Vec<IpAddr>, bool) {
    eligible_primary_addresses(report, MAX_RDAP_ADDRESSES)
}

fn eligible_bgp_addresses(report: &ScanReport) -> (Vec<IpAddr>, bool) {
    eligible_primary_addresses(report, MAX_BGP_ADDRESSES)
}

fn eligible_primary_addresses(report: &ScanReport, maximum: usize) -> (Vec<IpAddr>, bool) {
    let mut addresses = report
        .dns
        .iter()
        .flat_map(|dns| dns.resolved_hosts.iter())
        .filter_map(|host| canonical_external_address(host.ip))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let truncated = addresses.len() > maximum;
    addresses.truncate(maximum);
    (addresses, truncated)
}

fn canonical_external_address(address: IpAddr) -> Option<IpAddr> {
    is_public_destination(address).then_some(address)
}

/// Collects bounded observer-based BGP prefix and origin evidence.
///
/// Only eligible addresses already present in primary DNS results are queried. Returned prefixes
/// and ASNs never become scan targets or inputs to other intelligence checks.
pub async fn analyze_bgp_routes(
    report: &mut ScanReport,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) {
    let (config, clients) = production_bgp_request_configuration(request_timeout);
    analyze_bgp_routes_with(
        report,
        request_timeout,
        deadline,
        cancellation,
        config,
        clients,
    )
    .await;
}

fn production_bgp_request_configuration(
    request_timeout: Duration,
) -> (BgpConfig<'static>, PinnedClients) {
    (PRODUCTION_BGP_CONFIG, PinnedClients::new(request_timeout))
}

async fn analyze_bgp_routes_with(
    report: &mut ScanReport,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    config: BgpConfig<'_>,
    mut clients: PinnedClients,
) {
    let (addresses, truncated) = eligible_bgp_addresses(report);
    if addresses.is_empty() {
        record_bgp_skip(
            report,
            "no eligible external address in primary DNS results",
        );
        return;
    }

    let mut failures = BTreeSet::new();
    if truncated {
        failures.insert("address limit reached");
    }
    let mut requests = Vec::new();
    for address in addresses {
        match construct_bgp_url(config, address) {
            Ok(url) => requests.push((address, url)),
            Err(reason) => {
                failures.insert(reason);
            }
        }
    }
    let Some((_, first_url)) = requests.first() else {
        finish_bgp_routes(report, Vec::new(), failures, None);
        return;
    };
    let client = match clients.client_for(first_url, deadline, cancellation).await {
        Ok(client) => client,
        Err(FetchError::Cancelled) => {
            finish_bgp_routes(report, Vec::new(), failures, Some(BgpStop::Cancelled));
            return;
        }
        Err(FetchError::Deadline) => {
            finish_bgp_routes(report, Vec::new(), failures, Some(BgpStop::Deadline));
            return;
        }
        Err(error) => {
            failures.insert(bgp_fetch_reason(error));
            finish_bgp_routes(report, Vec::new(), failures, None);
            return;
        }
    };

    let lookups = futures::stream::iter(requests.into_iter().map(|(address, url)| {
        let client = client.clone();
        async move {
            let response = get_bounded(
                &client,
                url,
                MAX_BGP_RESPONSE_BYTES,
                request_timeout,
                deadline,
                cancellation,
            )
            .await;
            (address, response)
        }
    }))
    .buffer_unordered(MAX_BGP_CONCURRENCY);
    futures::pin_mut!(lookups);

    let mut observations = Vec::new();
    let mut stop = None;
    while let Some((address, response)) = lookups.next().await {
        match response {
            Ok(body) => match parse_bgp_response(&body, address) {
                Ok(observation) => {
                    if !observation.complete {
                        failures.insert("RIPEstat returned incomplete BGP evidence");
                    }
                    observations.push(observation);
                }
                Err(reason) => {
                    failures.insert(reason);
                }
            },
            Err(FetchError::Cancelled) => {
                stop = Some(BgpStop::Cancelled);
                break;
            }
            Err(FetchError::Deadline) => {
                stop = Some(BgpStop::Deadline);
                break;
            }
            Err(error) => {
                failures.insert(bgp_fetch_reason(error));
            }
        }
    }
    finish_bgp_routes(report, observations, failures, stop);
}

fn construct_bgp_url(config: BgpConfig<'_>, address: IpAddr) -> Result<Url, &'static str> {
    let mut url = Url::parse(config.endpoint).map_err(|_| "RIPEstat endpoint was invalid")?;
    if !bgp_url_matches_policy(&url, config, false) {
        return Err("RIPEstat endpoint failed validation");
    }
    url.query_pairs_mut()
        .append_pair("resource", &address.to_string());
    if !bgp_url_matches_policy(&url, config, true)
        || url.query_pairs().collect::<Vec<_>>()
            != [(
                std::borrow::Cow::Borrowed("resource"),
                std::borrow::Cow::Owned(address.to_string()),
            )]
    {
        return Err("constructed RIPEstat endpoint failed validation");
    }
    Ok(url)
}

fn bgp_url_matches_policy(url: &Url, config: BgpConfig<'_>, query: bool) -> bool {
    let port_matches = match config.port {
        Some(port) => url.port() == Some(port),
        None => url.port().is_none(),
    };
    url.scheme() == config.scheme
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str() == Some(config.host)
        && port_matches
        && url.path() == config.path
        && url.fragment().is_none()
        && (query == url.query().is_some())
}

fn parse_bgp_response(body: &[u8], address: IpAddr) -> Result<BgpRouteObservation, &'static str> {
    validate_json_depth(body).map_err(|()| "RIPEstat JSON exceeded nesting limit")?;
    let response: RipeStatEnvelope =
        serde_json::from_slice(body).map_err(|_| "RIPEstat response was invalid")?;
    let valid_version = response
        .version
        .split_once('.')
        .is_some_and(|(major, minor)| major == "1" && minor.parse::<u16>().is_ok());
    if response.status != "ok"
        || response.status_code != 200
        || response.data_call_name != "network-info"
        || response.data_call_status != "supported"
        || !valid_version
    {
        return Err("RIPEstat response envelope was not successful");
    }

    let mut origin_asns = response
        .data
        .asns
        .iter()
        .map(|value| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("RIPEstat response contained an invalid origin ASN");
            }
            let asn = value
                .parse::<u32>()
                .map_err(|_| "RIPEstat response contained an invalid origin ASN")?;
            if asn == 0 || value != &asn.to_string() {
                return Err("RIPEstat response contained an invalid origin ASN");
            }
            Ok(asn)
        })
        .collect::<Result<Vec<_>, _>>()?;
    origin_asns.sort_unstable();
    origin_asns.dedup();

    let mut limitations = vec![RIPESTAT_OBSERVER_LIMITATION.to_owned()];
    if response.data.prefix.is_empty() {
        if origin_asns.is_empty() {
            return Ok(BgpRouteObservation {
                address,
                prefix: None,
                origin_asns,
                source: RIPESTAT_SOURCE.to_owned(),
                complete: true,
                limitations,
            });
        }
        limitations.push(
            "RIPEstat returned origin ASNs without a routed prefix; attribution was discarded"
                .to_owned(),
        );
        return Ok(BgpRouteObservation {
            address,
            prefix: None,
            origin_asns: Vec::new(),
            source: RIPESTAT_SOURCE.to_owned(),
            complete: false,
            limitations,
        });
    }

    let prefix = parse_prefix(&response.data.prefix)
        .map_err(|_| "RIPEstat response contained an invalid routed prefix")?;
    if !prefix.contains(address) {
        return Err("RIPEstat routed prefix did not contain the queried address");
    }
    let prefix = Some(prefix.canonical());
    if origin_asns.is_empty() {
        limitations.push(
            "RIPEstat returned a routed prefix without origin ASNs; attribution is indeterminate"
                .to_owned(),
        );
        return Ok(BgpRouteObservation {
            address,
            prefix,
            origin_asns,
            source: RIPESTAT_SOURCE.to_owned(),
            complete: false,
            limitations,
        });
    }

    let mut complete = true;
    if origin_asns.len() > 1 {
        limitations.push(
            "multiple origin ASNs were observed; no canonical origin was selected".to_owned(),
        );
    }
    if origin_asns.len() > MAX_BGP_ORIGIN_ASNS {
        complete = false;
        origin_asns.truncate(MAX_BGP_ORIGIN_ASNS);
        limitations.push("origin ASN limit reached; four sorted origins were retained".to_owned());
    }
    Ok(BgpRouteObservation {
        address,
        prefix,
        origin_asns,
        source: RIPESTAT_SOURCE.to_owned(),
        complete,
        limitations,
    })
}

const fn bgp_fetch_reason(error: FetchError) -> &'static str {
    match error {
        FetchError::Timeout => "RIPEstat request timed out",
        FetchError::Resolution => "RIPEstat hostname resolution failed",
        FetchError::Destination => "RIPEstat destination was not public",
        FetchError::Request => "RIPEstat request failed",
        FetchError::Http(_) => "RIPEstat service returned an HTTP error",
        FetchError::TooLarge => "RIPEstat response exceeded 128 KiB",
        FetchError::Cancelled => "scan interrupted",
        FetchError::Deadline => "global timeout expired",
    }
}

fn finish_bgp_routes(
    report: &mut ScanReport,
    mut observations: Vec<BgpRouteObservation>,
    failures: BTreeSet<&'static str>,
    stop: Option<BgpStop>,
) {
    observations.sort_by_key(|observation| observation.address);
    if !observations.is_empty() || !failures.is_empty() || stop.is_some() {
        let intelligence = report
            .intelligence
            .get_or_insert_with(|| IntelligenceObservation {
                complete: true,
                ..IntelligenceObservation::default()
            });
        intelligence.bgp_routes.extend(observations);
        intelligence
            .bgp_routes
            .sort_by_key(|observation| observation.address);
        intelligence
            .bgp_routes
            .dedup_by_key(|observation| observation.address);
        intelligence.complete &= failures.is_empty() && stop.is_none();
    }

    let reason = match stop {
        Some(BgpStop::Cancelled) => {
            if report.status != ScanStatus::Failed {
                report.status = ScanStatus::Interrupted;
                "Scan interrupted.".clone_into(&mut report.message);
            }
            Some("scan interrupted".to_owned())
        }
        Some(BgpStop::Deadline) => {
            mark_bgp_partial(report);
            Some("global timeout expired".to_owned())
        }
        None if !failures.is_empty() => {
            mark_bgp_partial(report);
            Some(format!(
                "BGP origin lookup incomplete: {}",
                failures.into_iter().collect::<Vec<_>>().join("; ")
            ))
        }
        None => None,
    };
    if let Some(reason) = reason {
        record_bgp_skip(report, &reason);
    }
}

fn mark_bgp_partial(report: &mut ScanReport) {
    if report.status == ScanStatus::Completed {
        report.status = ScanStatus::Partial;
        "Scan completed with incomplete intelligence.".clone_into(&mut report.message);
    }
}

fn record_bgp_skip(report: &mut ScanReport, reason: &str) {
    if let Some(existing) = report
        .skipped_checks
        .iter_mut()
        .find(|skip| skip.check == "bgp_origin")
    {
        reason.clone_into(&mut existing.reason);
    } else {
        report.skipped_checks.push(SkippedCheck {
            check: "bgp_origin".to_owned(),
            reason: reason.to_owned(),
        });
    }
}

fn parse_bootstrap(
    body: &[u8],
    ipv6: bool,
    allowed_bases: &[AllowedRdapBase],
) -> Result<Vec<BootstrapEntry>, &'static str> {
    validate_json_depth(body).map_err(|()| "bootstrap JSON exceeded nesting limit")?;
    let bootstrap: RdapBootstrap =
        serde_json::from_slice(body).map_err(|_| "bootstrap response was invalid")?;
    if bootstrap.services.len() > MAX_BOOTSTRAP_SERVICES {
        return Err("bootstrap response exceeded service limit");
    }
    let mut prefix_count = 0_usize;
    let mut entries = Vec::new();
    for (prefixes, alternates) in bootstrap.services {
        prefix_count = prefix_count.saturating_add(prefixes.len());
        if prefix_count > MAX_BOOTSTRAP_PREFIXES
            || alternates.len() > MAX_BOOTSTRAP_ALTERNATES
            || prefixes
                .iter()
                .chain(alternates.iter())
                .any(|value| value.len() > MAX_BOOTSTRAP_STRING_BYTES)
        {
            return Err("bootstrap response exceeded retained field limits");
        }
        let endpoint = alternates
            .iter()
            .find_map(|value| approved_rdap_base(value, allowed_bases));
        for value in prefixes {
            let prefix = parse_prefix(&value).map_err(|_| "bootstrap response was invalid")?;
            if prefix.network.is_ipv6() != ipv6 {
                return Err("bootstrap response mixed address families");
            }
            entries.push(BootstrapEntry {
                prefix,
                endpoint: endpoint.clone(),
            });
        }
    }
    Ok(entries)
}

fn approved_rdap_base(value: &str, allowed_bases: &[AllowedRdapBase]) -> Option<ApprovedRdapBase> {
    let url = Url::parse(value).ok()?;
    let policy = allowed_bases
        .iter()
        .copied()
        .find(|policy| url_matches_policy(&url, *policy, policy.base_path))?;
    Some(ApprovedRdapBase { url, policy })
}

fn url_matches_policy(url: &Url, policy: AllowedRdapBase, path: &str) -> bool {
    let port_matches = match policy.port {
        Some(port) => url.port() == Some(port),
        None => url.port().is_none(),
    };
    url.scheme() == policy.scheme
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str() == Some(policy.host)
        && port_matches
        && url.path() == path
        && url.query().is_none()
        && url.fragment().is_none()
}

fn longest_bootstrap_endpoint(
    address: IpAddr,
    entries: &[BootstrapEntry],
) -> Option<ApprovedRdapBase> {
    entries
        .iter()
        .filter(|entry| entry.prefix.contains(address))
        .max_by_key(|entry| entry.prefix.length)
        .and_then(|entry| entry.endpoint.clone())
}

fn construct_rdap_url(endpoint: &ApprovedRdapBase, address: IpAddr) -> Result<Url, &'static str> {
    if !url_matches_policy(&endpoint.url, endpoint.policy, endpoint.policy.base_path) {
        return Err("RDAP base endpoint failed validation");
    }
    let canonical = address.to_string();
    let mut url = endpoint.url.clone();
    url.path_segments_mut()
        .map_err(|()| "RDAP base endpoint failed validation")?
        .pop_if_empty()
        .push("ip")
        .push(&canonical);
    let expected_path = format!("{}ip/{canonical}", endpoint.policy.base_path);
    if !url_matches_policy(&url, endpoint.policy, &expected_path) {
        return Err("constructed RDAP endpoint failed validation");
    }
    Ok(url)
}

fn parse_rdap_response(
    body: &[u8],
    address: IpAddr,
    registry: &str,
) -> Result<NetworkRegistrationObservation, &'static str> {
    validate_json_depth(body).map_err(|()| "RDAP JSON exceeded nesting limit")?;
    let response: RdapNetworkResponse =
        serde_json::from_slice(body).map_err(|_| "RDAP response was invalid")?;
    if response.object_class_name.as_deref() != Some("ip network") {
        return Err("RDAP response was not an IP network object");
    }
    validate_optional_field(response.handle.as_ref(), MAX_RDAP_HANDLE_BYTES)?;
    validate_optional_field(response.name.as_ref(), MAX_RDAP_NAME_BYTES)?;
    validate_optional_field(response.network_type.as_ref(), MAX_RDAP_TYPE_BYTES)?;
    validate_optional_field(response.country.as_ref(), MAX_RDAP_COUNTRY_BYTES)?;
    if response.country.as_ref().is_some_and(|country| {
        country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic())
    }) {
        return Err("RDAP response contained an invalid registration country");
    }
    if response.status.len() > MAX_RDAP_STATUSES
        || response
            .status
            .iter()
            .any(|status| status.is_empty() || status.len() > MAX_RDAP_STATUS_BYTES)
    {
        return Err("RDAP response exceeded retained status limits");
    }
    let (start_address, end_address) = match (response.start_address, response.end_address) {
        (None, None) => (None, None),
        (Some(start), Some(end)) => {
            let start = start
                .parse::<IpAddr>()
                .map_err(|_| "RDAP response contained an invalid range")?;
            let end = end
                .parse::<IpAddr>()
                .map_err(|_| "RDAP response contained an invalid range")?;
            if !coherent_range(start, end, address) {
                return Err("RDAP response range did not contain the queried address");
            }
            (Some(start), Some(end))
        }
        _ => return Err("RDAP response contained an incomplete range"),
    };
    let mut statuses = response.status;
    statuses.sort();
    statuses.dedup();
    Ok(NetworkRegistrationObservation {
        address,
        source: "RDAP".to_owned(),
        registry: registry.to_owned(),
        handle: response.handle,
        name: response.name,
        network_type: response.network_type,
        start_address,
        end_address,
        registration_country: response.country,
        statuses,
    })
}

fn validate_optional_field(value: Option<&String>, maximum: usize) -> Result<(), &'static str> {
    if value.is_some_and(|value| value.is_empty() || value.len() > maximum) {
        return Err("RDAP response exceeded retained string limits");
    }
    Ok(())
}

fn coherent_range(start: IpAddr, end: IpAddr, address: IpAddr) -> bool {
    match (start, end, address) {
        (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(address)) => {
            u32::from(start) <= u32::from(address) && u32::from(address) <= u32::from(end)
        }
        (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(address)) => {
            u128::from(start) <= u128::from(address) && u128::from(address) <= u128::from(end)
        }
        _ => false,
    }
}

fn validate_json_depth(body: &[u8]) -> Result<(), ()> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(());
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

const fn bootstrap_fetch_reason(error: FetchError) -> &'static str {
    match error {
        FetchError::Timeout => "bootstrap request timed out",
        FetchError::Resolution => "bootstrap hostname resolution failed",
        FetchError::Destination => "bootstrap destination was not public",
        FetchError::Request => "bootstrap request failed",
        FetchError::Http(_) => "bootstrap service returned an HTTP error",
        FetchError::TooLarge => "bootstrap response exceeded 64 KiB",
        FetchError::Cancelled => "scan interrupted",
        FetchError::Deadline => "global timeout expired",
    }
}

const fn rdap_fetch_reason(error: FetchError) -> &'static str {
    match error {
        FetchError::Timeout => "RDAP request timed out",
        FetchError::Resolution => "RDAP hostname resolution failed",
        FetchError::Destination => "RDAP destination was not public",
        FetchError::Request => "RDAP request failed",
        FetchError::Http(_) => "RDAP service returned an HTTP error",
        FetchError::TooLarge => "RDAP response exceeded 256 KiB",
        FetchError::Cancelled => "scan interrupted",
        FetchError::Deadline => "global timeout expired",
    }
}

fn finish_network_registrations(
    report: &mut ScanReport,
    mut observations: Vec<NetworkRegistrationObservation>,
    failures: BTreeSet<&'static str>,
    stop: Option<RdapStop>,
) {
    observations.sort_by_key(|observation| observation.address);
    if !observations.is_empty() || !failures.is_empty() || stop.is_some() {
        let intelligence = report
            .intelligence
            .get_or_insert_with(|| IntelligenceObservation {
                complete: true,
                ..IntelligenceObservation::default()
            });
        intelligence.network_registrations.extend(observations);
        intelligence
            .network_registrations
            .sort_by_key(|observation| observation.address);
        intelligence
            .network_registrations
            .dedup_by_key(|observation| observation.address);
        intelligence.complete &= failures.is_empty() && stop.is_none();
    }

    let reason = match stop {
        Some(RdapStop::Cancelled) => {
            if report.status != ScanStatus::Failed {
                report.status = ScanStatus::Interrupted;
                "Scan interrupted.".clone_into(&mut report.message);
            }
            Some("scan interrupted".to_owned())
        }
        Some(RdapStop::Deadline) => {
            mark_network_registration_partial(report);
            Some("global timeout expired".to_owned())
        }
        None if !failures.is_empty() => {
            mark_network_registration_partial(report);
            Some(format!(
                "network registration lookup incomplete: {}",
                failures.into_iter().collect::<Vec<_>>().join("; ")
            ))
        }
        None => None,
    };
    if let Some(reason) = reason {
        record_network_registration_skip(report, &reason);
    }
}

fn mark_network_registration_partial(report: &mut ScanReport) {
    if report.status == ScanStatus::Completed {
        report.status = ScanStatus::Partial;
        "Scan completed with incomplete intelligence.".clone_into(&mut report.message);
    }
}

fn record_network_registration_skip(report: &mut ScanReport, reason: &str) {
    if let Some(existing) = report
        .skipped_checks
        .iter_mut()
        .find(|skip| skip.check == "network_registration")
    {
        reason.clone_into(&mut existing.reason);
    } else {
        report.skipped_checks.push(SkippedCheck {
            check: "network_registration".to_owned(),
            reason: reason.to_owned(),
        });
    }
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

#[derive(Debug, Clone, Copy)]
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

    fn canonical(self) -> String {
        match self.network {
            IpAddr::V4(network) => {
                let mask = if self.length == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.length)
                };
                format!(
                    "{}/{}",
                    std::net::Ipv4Addr::from(u32::from(network) & mask),
                    self.length
                )
            }
            IpAddr::V6(network) => {
                let mask = if self.length == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.length)
                };
                format!(
                    "{}/{}",
                    std::net::Ipv6Addr::from(u128::from(network) & mask),
                    self.length
                )
            }
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
        str::FromStr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use reqwest::Client;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use crate::{
        AddressSource, DetectionConfidence, DnsObservation, HostObservation, MailObservation,
        PortObservation, PortState, ResolvedHost, ScanConfiguration, ScanReport, ScanStatus,
        ServiceKind, ServiceObservation, SpfObservation, TransportProtocol, normalize_target,
    };

    use super::{
        AllowedRdapBase, BgpConfig, BgpStop, CertSpotterIssuance, MAX_BGP_RESPONSE_BYTES,
        MAX_BOOTSTRAP_BYTES, MAX_CT_RESPONSE_BYTES, MAX_RDAP_RESPONSE_BYTES, OFFICIAL_RDAP_BASES,
        PinnedClients, RdapConfig, RdapStop, analyze_bgp_routes_with,
        analyze_certificate_transparency_at, analyze_intelligence,
        analyze_network_registrations_with, approved_rdap_base, canonical_external_address,
        coherent_range, construct_bgp_url, construct_rdap_url, correlate_cves, correlate_networks,
        ct_candidates, eligible_bgp_addresses, eligible_rdap_addresses, fetch_certspotter_page,
        finish_bgp_routes, finish_network_registrations, identify_nameserver_provider,
        longest_bootstrap_endpoint, parse_bgp_response, parse_bootstrap, parse_bundle,
        parse_rdap_response, production_bgp_request_configuration, related_candidates,
        validate_json_depth,
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

    #[derive(Clone)]
    struct MockRoute {
        status: &'static str,
        headers: String,
        body: Vec<u8>,
        delay: Duration,
    }

    struct MockHttpRequests {
        stop: tokio::sync::oneshot::Sender<()>,
        task: JoinHandle<Vec<String>>,
    }

    impl MockHttpRequests {
        async fn finish(self) -> Vec<String> {
            let _ = self.stop.send(());
            self.task.await.unwrap_or_else(|error| panic!("{error}"))
        }
    }

    async fn mock_http_routes(
        maximum_requests: usize,
        build: impl FnOnce(SocketAddr) -> BTreeMap<String, MockRoute>,
    ) -> (SocketAddr, MockHttpRequests) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let routes = build(address);
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..maximum_requests {
                let (mut socket, request_text, reply) = tokio::select! {
                    result = async {
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
                        let request_text = String::from_utf8_lossy(&request).into_owned();
                        let path = request_text
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let reply = routes.get(path).cloned().unwrap_or(MockRoute {
                            status: "404 Not Found",
                            headers: String::new(),
                            body: Vec::new(),
                            delay: Duration::ZERO,
                        });
                        (socket, request_text, reply)
                    } => result,
                    _ = &mut stopped => break,
                };
                requests.push(request_text);
                let completed = tokio::select! {
                    () = async {
                        tokio::time::sleep(reply.delay).await;
                        let response = format!(
                            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                            reply.status,
                            reply.body.len(),
                            reply.headers
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.write_all(&reply.body).await;
                    } => true,
                    _ = &mut stopped => false,
                };
                if !completed {
                    break;
                }
            }
            requests
        });
        (address, MockHttpRequests { stop, task })
    }

    async fn mock_concurrent_responses(
        requests: usize,
        delay: Duration,
        body: &[u8],
    ) -> (SocketAddr, JoinHandle<(Vec<String>, usize)>) {
        let body = body.to_vec();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..requests {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let active = active.clone();
                let maximum = maximum.clone();
                let captured = captured.clone();
                let body = body.clone();
                tasks.spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0_u8; 1_024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = socket
                            .read(&mut chunk)
                            .await
                            .unwrap_or_else(|error| panic!("{error}"));
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }
                    captured
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(String::from_utf8_lossy(&request).into_owned());
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap_or_else(|error| panic!("{error}"));
            }
            let requests = captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            (requests, maximum.load(Ordering::SeqCst))
        });
        (address, task)
    }

    fn network_info(prefix: &str, mut asns: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "messages": [],
            "version": "1.1",
            "data_call_name": "network-info",
            "data_call_status": "supported",
            "status": "ok",
            "status_code": 200,
            "data": {"asns": asns.take(), "prefix": prefix}
        }))
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn fixture_bgp_config(address: SocketAddr) -> BgpConfig<'static> {
        let endpoint = Box::leak(
            format!(
                "http://stat.ripe.net:{}/data/network-info/data.json",
                address.port()
            )
            .into_boxed_str(),
        );
        BgpConfig {
            endpoint,
            scheme: "http",
            host: "stat.ripe.net",
            port: Some(address.port()),
            path: "/data/network-info/data.json",
        }
    }

    fn bgp_fixture_clients(request_timeout: Duration, address: SocketAddr) -> PinnedClients {
        PinnedClients::fixture(
            request_timeout,
            BTreeMap::from([("stat.ripe.net".to_owned(), vec![address])]),
        )
    }

    fn report_with_dns(addresses: impl IntoIterator<Item = IpAddr>) -> ScanReport {
        let mut report = report();
        report.status = ScanStatus::Completed;
        report.dns = Some(DnsObservation {
            queried_name: "example.com".to_owned(),
            records: Vec::new(),
            cname_chain: Vec::new(),
            dangling_cnames: Vec::new(),
            resolved_hosts: addresses
                .into_iter()
                .map(|ip| ResolvedHost {
                    hostname: Some("example.com".to_owned()),
                    ip,
                    source: if ip.is_ipv4() {
                        AddressSource::ARecord
                    } else {
                        AddressSource::AaaaRecord
                    },
                })
                .collect(),
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
            wildcard_dns: None,
            errors: Vec::new(),
        });
        report
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

    fn fixture_clients(
        request_timeout: Duration,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> PinnedClients {
        PinnedClients::fixture(
            request_timeout,
            addresses
                .into_iter()
                .map(|address| (address.ip().to_string(), vec![address]))
                .collect(),
        )
    }

    fn fixture_policy(address: SocketAddr) -> AllowedRdapBase {
        let host: &'static str = Box::leak(address.ip().to_string().into_boxed_str());
        AllowedRdapBase {
            scheme: "http",
            host,
            port: Some(address.port()),
            base_path: "/rdap/",
            registry: "TEST-RIR",
        }
    }

    #[tokio::test]
    async fn excluded_address_classes_make_no_requests() {
        let excluded = [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.168.1.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:192.0.2.1",
            "64:ff9b::",
            "64:ff9b::ffff:ffff",
            "64:ff9b:1::",
            "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "2620:4f:8000::1",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ]
        .into_iter()
        .map(|value| IpAddr::from_str(value).unwrap_or_else(|error| panic!("{error}")))
        .collect::<Vec<_>>();
        for address in &excluded {
            assert_eq!(canonical_external_address(*address), None, "{address}");
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let server = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let endpoint = format!("http://{server}/ipv4.json");
        let mut report = report_with_dns(excluded.clone());
        analyze_network_registrations_with(
            &mut report,
            Duration::from_millis(50),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &tokio_util::sync::CancellationToken::new(),
            RdapConfig {
                ipv4_bootstrap: &endpoint,
                ipv6_bootstrap: &endpoint,
                allowed_bases: &[],
            },
            fixture_clients(Duration::from_millis(50), [server]),
        )
        .await;
        let mut bgp_report = report_with_dns(excluded);
        analyze_bgp_routes_with(
            &mut bgp_report,
            Duration::from_millis(50),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &tokio_util::sync::CancellationToken::new(),
            fixture_bgp_config(server),
            bgp_fixture_clients(Duration::from_millis(50), server),
        )
        .await;

        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(report.status, ScanStatus::Completed);
        assert_eq!(report.skipped_checks.len(), 1);
        assert_eq!(report.skipped_checks[0].check, "network_registration");
        assert_eq!(bgp_report.status, ScanStatus::Completed);
        assert_eq!(bgp_report.skipped_checks.len(), 1);
        assert_eq!(bgp_report.skipped_checks[0].check, "bgp_origin");
    }

    #[test]
    fn eligible_addresses_are_canonical_sorted_deduplicated_and_capped() {
        let mut addresses = (1..=10)
            .rev()
            .map(|last| IpAddr::V4(Ipv4Addr::new(8, 8, 8, last)))
            .collect::<Vec<_>>();
        addresses.extend([
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::from_str("::ffff:8.8.8.8").unwrap_or_else(|error| panic!("{error}")),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ]);
        let report = report_with_dns(addresses);

        let (eligible, truncated) = eligible_rdap_addresses(&report);
        let (bgp_eligible, bgp_truncated) = eligible_bgp_addresses(&report);

        assert!(truncated);
        assert_eq!(eligible.len(), 8);
        assert!(eligible.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(eligible[0], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 1)));
        assert_eq!(eligible[7], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!((bgp_eligible, bgp_truncated), (eligible, truncated));
    }

    #[test]
    fn production_bgp_policy_is_exact_and_locally_encodes_the_canonical_address() {
        let (config, clients) = production_bgp_request_configuration(Duration::from_secs(1));
        assert_eq!(
            config.endpoint,
            "https://stat.ripe.net/data/network-info/data.json"
        );
        assert_eq!(config.scheme, "https");
        assert_eq!(config.host, "stat.ripe.net");
        assert_eq!(config.port, None);
        assert_eq!(config.path, "/data/network-info/data.json");
        assert_eq!(
            clients.policy(),
            crate::passive_http::ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect
        );

        let ipv4 = construct_bgp_url(
            config,
            "8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            ipv4.as_str(),
            "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8"
        );
        let ipv6 = construct_bgp_url(
            config,
            "2001:4860:4860:0:0:0:0:8888"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            ipv6.as_str(),
            "https://stat.ripe.net/data/network-info/data.json?resource=2001%3A4860%3A4860%3A%3A8888"
        );
    }

    #[test]
    fn bgp_parser_handles_no_route_duplicates_conflicts_and_truncation() {
        let address = "8.8.8.8"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"));
        let no_route = parse_bgp_response(&network_info("", serde_json::json!([])), address)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(no_route.complete);
        assert!(no_route.prefix.is_none());
        assert!(no_route.origin_asns.is_empty());

        let single = parse_bgp_response(
            &network_info("8.8.8.7/24", serde_json::json!(["15169", "15169"])),
            address,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(single.complete);
        assert_eq!(single.prefix.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(single.origin_asns, [15_169]);
        assert_eq!(single.source, "RIPE RIS via RIPEstat");

        let several = parse_bgp_response(
            &network_info("8.8.8.0/24", serde_json::json!(["4", "2", "3", "1"])),
            address,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(several.complete);
        assert_eq!(several.origin_asns, [1, 2, 3, 4]);
        assert!(
            several
                .limitations
                .iter()
                .any(|value| value.contains("multiple origin"))
        );
        assert!(
            several
                .limitations
                .iter()
                .any(|value| value.contains("observer-dependent"))
        );

        let truncated = parse_bgp_response(
            &network_info("8.8.8.0/24", serde_json::json!(["4", "2", "3", "1", "5"])),
            address,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!truncated.complete);
        assert_eq!(truncated.origin_asns, [1, 2, 3, 4]);
        assert!(
            truncated
                .limitations
                .iter()
                .any(|value| value.contains("multiple origin"))
        );
        assert!(
            truncated
                .limitations
                .iter()
                .any(|value| value.contains("limit reached"))
        );
        assert!(truncated.limitations.len() <= 3);
        assert!(truncated.limitations.iter().all(|value| value.len() < 128));
    }

    #[test]
    fn bgp_parser_rejects_invalid_asns_and_incoherent_prefixes() {
        let address = "8.8.8.8"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"));
        for asns in [
            serde_json::json!(["AS15169"]),
            serde_json::json!([""]),
            serde_json::json!(["0"]),
            serde_json::json!(["4294967296"]),
            serde_json::json!(["01"]),
            serde_json::json!([15169]),
        ] {
            assert!(parse_bgp_response(&network_info("8.8.8.0/24", asns), address).is_err());
        }
        for prefix in ["not-a-prefix", "8.8.9.0/24", "2001:4860::/32"] {
            assert!(
                parse_bgp_response(&network_info(prefix, serde_json::json!(["15169"])), address)
                    .is_err(),
                "{prefix}"
            );
        }

        let ipv6 = "2001:4860:4860::8888"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"));
        let observation = parse_bgp_response(
            &network_info("2001:4860:1::1/32", serde_json::json!(["15169"])),
            ipv6,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(observation.prefix.as_deref(), Some("2001:4860::/32"));
    }

    #[test]
    fn bgp_parser_treats_one_sided_attribution_as_indeterminate() {
        let address = "8.8.8.8"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"));
        let no_origins =
            parse_bgp_response(&network_info("8.8.8.0/24", serde_json::json!([])), address)
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(!no_origins.complete);
        assert!(no_origins.origin_asns.is_empty());
        let no_prefix =
            parse_bgp_response(&network_info("", serde_json::json!(["15169"])), address)
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(!no_prefix.complete);
        assert!(no_prefix.prefix.is_none());
        assert!(no_prefix.origin_asns.is_empty());
    }

    #[test]
    fn bgp_parser_validates_the_success_envelope_without_retaining_messages() {
        let address = "8.8.8.8"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(parse_bgp_response(b"not-json", address).is_err());
        for (field, value) in [
            ("status", serde_json::json!("error")),
            ("status_code", serde_json::json!(500)),
            ("data_call_name", serde_json::json!("other")),
            ("data_call_status", serde_json::json!("maintenance")),
            ("version", serde_json::json!("2.0")),
        ] {
            let mut envelope: serde_json::Value =
                serde_json::from_slice(&network_info("8.8.8.0/24", serde_json::json!(["15169"])))
                    .unwrap_or_else(|error| panic!("{error}"));
            envelope[field] = value;
            assert!(
                parse_bgp_response(
                    &serde_json::to_vec(&envelope).unwrap_or_else(|error| panic!("{error}")),
                    address
                )
                .is_err(),
                "{field}"
            );
        }
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&network_info("8.8.8.0/24", serde_json::json!(["15169"])))
                .unwrap_or_else(|error| panic!("{error}"));
        envelope["messages"] = serde_json::json!([["warning", "x".repeat(4_096)]]);
        let observation = parse_bgp_response(
            &serde_json::to_vec(&envelope).unwrap_or_else(|error| panic!("{error}")),
            address,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            observation
                .limitations
                .iter()
                .all(|value| value.len() < 128)
        );
    }

    #[test]
    fn bootstrap_uses_longest_prefix_and_preserves_family() {
        let ipv4 = br#"{
          "services":[
            [["8.0.0.0/8"],["https://rdap.arin.net/registry/"]],
            [["8.8.0.0/16"],["https://rdap.apnic.net/"]]
          ]
        }"#;
        let entries = parse_bootstrap(ipv4, false, OFFICIAL_RDAP_BASES)
            .unwrap_or_else(|error| panic!("{error}"));
        let endpoint = longest_bootstrap_endpoint(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &entries)
            .unwrap_or_else(|| panic!("missing endpoint"));
        assert_eq!(endpoint.policy.registry, "APNIC");

        let ipv6 = br#"{"services":[[["2001:4860::/32"],["https://rdap.db.ripe.net/"]]]}"#;
        let entries = parse_bootstrap(ipv6, true, OFFICIAL_RDAP_BASES)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            longest_bootstrap_endpoint(
                IpAddr::from_str("2001:4860:4860::8888").unwrap_or_else(|error| panic!("{error}")),
                &entries,
            )
            .is_some()
        );
        assert!(parse_bootstrap(ipv4, true, OFFICIAL_RDAP_BASES).is_err());
        assert!(parse_bootstrap(b"not-json", false, OFFICIAL_RDAP_BASES).is_err());
        let long_bootstrap = format!(
            r#"{{"services":[[["8.0.0.0/8"],["https://{}"]]]}}"#,
            "x".repeat(513)
        );
        assert!(parse_bootstrap(long_bootstrap.as_bytes(), false, OFFICIAL_RDAP_BASES).is_err());

        let malicious_specific = br#"{
          "services":[
            [["8.0.0.0/8"],["https://rdap.arin.net/registry/"]],
            [["8.8.0.0/16"],["https://evil.invalid/rdap/"]]
          ]
        }"#;
        let entries = parse_bootstrap(malicious_specific, false, OFFICIAL_RDAP_BASES)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            longest_bootstrap_endpoint(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &entries,).is_none()
        );
    }

    #[test]
    fn rdap_endpoint_policy_rejects_every_unsafe_url_component() {
        for rejected in [
            "http://rdap.arin.net/registry/",
            "https://evil.invalid/registry/",
            "https://rdap.arin.net:444/registry/",
            "https://rdap.arin.net/wrong/",
            "https://user@rdap.arin.net/registry/",
            "https://user:password@rdap.arin.net/registry/",
            "https://rdap.arin.net/registry/?query=1",
            "https://rdap.arin.net/registry/#fragment",
            "https://rdap.arin.net/registry",
        ] {
            assert!(
                approved_rdap_base(rejected, OFFICIAL_RDAP_BASES).is_none(),
                "{rejected}"
            );
        }
        assert!(
            approved_rdap_base("https://rdap.arin.net:443/registry/", OFFICIAL_RDAP_BASES)
                .is_some()
        );
    }

    #[test]
    fn rdap_url_uses_exact_canonical_percent_safe_ip_path() {
        let base = approved_rdap_base("https://rdap.apnic.net/", OFFICIAL_RDAP_BASES)
            .unwrap_or_else(|| panic!("approved endpoint rejected"));
        let ipv4 = construct_rdap_url(&base, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ipv4.as_str(), "https://rdap.apnic.net/ip/8.8.8.8");
        let address = IpAddr::from_str("2001:4860:4860:0:0:0:0:8888")
            .unwrap_or_else(|error| panic!("{error}"));
        let ipv6 = construct_rdap_url(&base, address).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            ipv6.as_str(),
            "https://rdap.apnic.net/ip/2001:4860:4860::8888"
        );
        assert!(ipv6.query().is_none());
        assert!(ipv6.fragment().is_none());
    }

    #[test]
    fn rdap_parser_bounds_json_and_retained_fields() {
        let too_deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert!(validate_json_depth(too_deep.as_bytes()).is_err());
        assert!(parse_rdap_response(b"not-json", "8.8.8.8".parse().unwrap(), "ARIN").is_err());

        let long_handle = format!(
            r#"{{"objectClassName":"ip network","handle":"{}"}}"#,
            "x".repeat(257)
        );
        assert!(
            parse_rdap_response(long_handle.as_bytes(), "8.8.8.8".parse().unwrap(), "ARIN")
                .is_err()
        );
        let statuses = serde_json::json!({
            "objectClassName": "ip network",
            "status": (0..17).map(|index| format!("status-{index}")).collect::<Vec<_>>()
        });
        assert!(
            parse_rdap_response(
                &serde_json::to_vec(&statuses).unwrap_or_else(|error| panic!("{error}")),
                "8.8.8.8".parse().unwrap(),
                "ARIN"
            )
            .is_err()
        );
        let long_status = serde_json::json!({
            "objectClassName": "ip network",
            "status": ["x".repeat(65)]
        });
        assert!(
            parse_rdap_response(
                &serde_json::to_vec(&long_status).unwrap_or_else(|error| panic!("{error}")),
                "8.8.8.8".parse().unwrap(),
                "ARIN"
            )
            .is_err()
        );
    }

    #[test]
    fn rdap_parser_retains_only_bounded_registration_fields() {
        let body = br#"{
          "objectClassName":"ip network",
          "handle":"NET-8-8-8-0-1",
          "name":"EXAMPLE-NET",
          "type":"DIRECT ALLOCATION",
          "startAddress":"8.8.8.0",
          "endAddress":"8.8.8.255",
          "country":"US",
          "status":["active","active"],
          "entities":[{"handle":"CONTACT"}],
          "remarks":[{"description":["not retained"]}],
          "links":[{"href":"https://example.invalid/next"}]
        }"#;
        let observation = parse_rdap_response(
            body,
            "8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}")),
            "ARIN",
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(observation.source, "RDAP");
        assert_eq!(observation.registry, "ARIN");
        assert_eq!(observation.handle.as_deref(), Some("NET-8-8-8-0-1"));
        assert_eq!(observation.registration_country.as_deref(), Some("US"));
        assert_eq!(observation.statuses, ["active"]);
        let serialized =
            serde_json::to_string(&observation).unwrap_or_else(|error| panic!("{error}"));
        assert!(!serialized.contains("CONTACT"));
        assert!(!serialized.contains("not retained"));
        assert!(!serialized.contains("example.invalid"));
    }

    #[test]
    fn rdap_ranges_must_be_coherent_and_contain_the_query() {
        assert!(coherent_range(
            "8.8.8.0".parse().unwrap(),
            "8.8.8.255".parse().unwrap(),
            "8.8.8.8".parse().unwrap()
        ));
        for body in [
            br#"{"objectClassName":"ip network","startAddress":"8.8.9.0","endAddress":"8.8.9.255"}"#.as_slice(),
            br#"{"objectClassName":"ip network","startAddress":"8.8.8.255","endAddress":"8.8.8.0"}"#.as_slice(),
            br#"{"objectClassName":"ip network","startAddress":"8.8.8.0"}"#.as_slice(),
            br#"{"objectClassName":"ip network","startAddress":"2001:4860::","endAddress":"2001:4860::ffff"}"#.as_slice(),
        ] {
            assert!(parse_rdap_response(body, "8.8.8.8".parse().unwrap(), "ARIN").is_err());
        }
    }

    #[tokio::test]
    async fn bgp_request_uses_exact_host_path_query_and_only_primary_dns_addresses() {
        let body = network_info("8.8.8.0/24", serde_json::json!(["15169", "13335", "15169"]));
        let (server, requests) = mock_http_routes(1, move |_| {
            BTreeMap::from([(
                "/data/network-info/data.json?resource=8.8.8.8".to_owned(),
                MockRoute {
                    status: "200 OK",
                    headers: String::new(),
                    body,
                    delay: Duration::ZERO,
                },
            )])
        })
        .await;
        let mut report = report_with_dns(["8.8.8.8"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"))]);
        report.intelligence = Some(super::IntelligenceObservation {
            networks: vec![super::NetworkMetadata {
                address: "1.1.1.1".parse().unwrap_or_else(|error| panic!("{error}")),
                prefix: "1.1.1.0/24".to_owned(),
                asn: Some(13_335),
                organization: Some("must not propagate".to_owned()),
                country: None,
            }],
            network_registrations: vec![super::NetworkRegistrationObservation {
                address: "9.9.9.9".parse().unwrap_or_else(|error| panic!("{error}")),
                source: "RDAP".to_owned(),
                registry: "TEST".to_owned(),
                handle: Some("AS64500 CONTACT".to_owned()),
                name: None,
                network_type: None,
                start_address: Some("9.9.9.0".parse().unwrap_or_else(|error| panic!("{error}"))),
                end_address: Some(
                    "9.9.9.255"
                        .parse()
                        .unwrap_or_else(|error| panic!("{error}")),
                ),
                registration_country: None,
                statuses: Vec::new(),
            }],
            complete: true,
            ..super::IntelligenceObservation::default()
        });

        analyze_bgp_routes_with(
            &mut report,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            fixture_bgp_config(server),
            bgp_fixture_clients(Duration::from_secs(1), server),
        )
        .await;
        let requests = requests.finish().await;

        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .starts_with("GET /data/network-info/data.json?resource=8.8.8.8 HTTP/1.1\r\n")
        );
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains(&format!("\r\nhost: stat.ripe.net:{}\r\n", server.port()))
        );
        assert_eq!(report.status, ScanStatus::Completed);
        let routes = &report
            .intelligence
            .as_ref()
            .unwrap_or_else(|| panic!("missing intelligence"))
            .bgp_routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].address,
            "8.8.8.8"
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert!(routes[0].complete);
        assert_eq!(routes[0].prefix.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(routes[0].origin_asns, [13_335, 15_169]);
        assert!(
            routes[0]
                .limitations
                .iter()
                .any(|value| value.contains("multiple origin"))
        );
        assert!(
            routes[0]
                .limitations
                .iter()
                .any(|value| value.contains("observer-dependent"))
        );
        assert!(report.skipped_checks.is_empty());
    }

    #[tokio::test]
    async fn bgp_requests_are_sorted_deduplicated_capped_and_four_concurrent() {
        let body = network_info("8.8.8.0/24", serde_json::json!(["15169"]));
        let (server, server_task) =
            mock_concurrent_responses(8, Duration::from_millis(50), &body).await;
        let addresses = (1..=8)
            .rev()
            .flat_map(|last| {
                let address = IpAddr::V4(Ipv4Addr::new(8, 8, 8, last));
                [address, address]
            })
            .collect::<Vec<_>>();
        let mut report = report_with_dns(addresses);

        tokio::time::timeout(
            Duration::from_secs(2),
            analyze_bgp_routes_with(
                &mut report,
                Duration::from_secs(1),
                tokio::time::Instant::now() + Duration::from_secs(2),
                &tokio_util::sync::CancellationToken::new(),
                fixture_bgp_config(server),
                bgp_fixture_clients(Duration::from_secs(1), server),
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let (requests, maximum) = server_task.await.unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(requests.len(), 8);
        assert_eq!(maximum, 4);
        let routes = &report
            .intelligence
            .as_ref()
            .unwrap_or_else(|| panic!("missing intelligence"))
            .bgp_routes;
        assert_eq!(routes.len(), 8);
        assert!(
            routes
                .windows(2)
                .all(|pair| pair[0].address < pair[1].address)
        );
        assert_eq!(report.status, ScanStatus::Completed);
    }

    #[tokio::test]
    async fn truncated_bgp_success_is_retained_with_one_deduplicated_skip() {
        let (server, requests) = mock_http_routes(2, |_| {
            BTreeMap::from([
                (
                    "/data/network-info/data.json?resource=1.1.1.1".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: network_info("1.1.1.0/24", serde_json::json!(["13335"])),
                        delay: Duration::ZERO,
                    },
                ),
                (
                    "/data/network-info/data.json?resource=8.8.8.8".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: network_info(
                            "8.8.8.0/24",
                            serde_json::json!(["5", "4", "3", "2", "1"]),
                        ),
                        delay: Duration::ZERO,
                    },
                ),
            ])
        })
        .await;
        let mut report = report_with_dns([
            "8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}")),
            "1.1.1.1".parse().unwrap_or_else(|error| panic!("{error}")),
        ]);

        analyze_bgp_routes_with(
            &mut report,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            fixture_bgp_config(server),
            bgp_fixture_clients(Duration::from_secs(1), server),
        )
        .await;
        let requests = requests.finish().await;

        assert_eq!(requests.len(), 2);
        assert_eq!(report.status, ScanStatus::Partial);
        assert_eq!(report.skipped_checks.len(), 1);
        assert_eq!(report.skipped_checks[0].check, "bgp_origin");
        assert!(
            report.skipped_checks[0]
                .reason
                .contains("incomplete BGP evidence")
        );
        let routes = &report
            .intelligence
            .as_ref()
            .unwrap_or_else(|| panic!("missing intelligence"))
            .bgp_routes;
        assert_eq!(routes.len(), 2);
        let truncated_address = "8.8.8.8"
            .parse::<IpAddr>()
            .unwrap_or_else(|error| panic!("{error}"));
        let truncated = routes
            .iter()
            .find(|route| route.address == truncated_address)
            .unwrap_or_else(|| panic!("missing truncated route"));
        assert!(!truncated.complete);
        assert_eq!(truncated.origin_asns, [1, 2, 3, 4]);
        assert!(
            truncated
                .limitations
                .iter()
                .any(|value| value.contains("limit reached"))
        );
    }

    #[tokio::test]
    async fn bgp_redirect_and_oversize_fail_inside_the_pinned_boundary() {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let target_url = format!(
            "http://{}/data/network-info/data.json",
            target
                .local_addr()
                .unwrap_or_else(|error| panic!("{error}"))
        );
        let (redirect, requests) = mock_http_routes(1, move |_| {
            BTreeMap::from([(
                "/data/network-info/data.json?resource=8.8.8.8".to_owned(),
                MockRoute {
                    status: "302 Found",
                    headers: format!("Location: {target_url}\r\n"),
                    body: Vec::new(),
                    delay: Duration::ZERO,
                },
            )])
        })
        .await;
        let mut redirected =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        analyze_bgp_routes_with(
            &mut redirected,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            fixture_bgp_config(redirect),
            bgp_fixture_clients(Duration::from_secs(1), redirect),
        )
        .await;
        assert_eq!(requests.finish().await.len(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
        assert!(redirected.skipped_checks[0].reason.contains("HTTP error"));

        let (oversize, requests) = mock_http_routes(1, |_| {
            BTreeMap::from([(
                "/data/network-info/data.json?resource=8.8.8.8".to_owned(),
                MockRoute {
                    status: "200 OK",
                    headers: String::new(),
                    body: vec![b' '; MAX_BGP_RESPONSE_BYTES + 1],
                    delay: Duration::ZERO,
                },
            )])
        })
        .await;
        let mut oversized =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        analyze_bgp_routes_with(
            &mut oversized,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            fixture_bgp_config(oversize),
            bgp_fixture_clients(Duration::from_secs(1), oversize),
        )
        .await;
        assert_eq!(requests.finish().await.len(), 1);
        assert!(oversized.skipped_checks[0].reason.contains("128 KiB"));
    }

    #[tokio::test]
    async fn bgp_timeout_deadline_and_cancellation_have_stable_lifecycle() {
        async fn delayed(request_timeout: Duration, deadline: Duration) -> ScanReport {
            let (server, requests) = mock_http_routes(1, |_| {
                BTreeMap::from([(
                    "/data/network-info/data.json?resource=8.8.8.8".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: network_info("8.8.8.0/24", serde_json::json!(["15169"])),
                        delay: Duration::from_millis(100),
                    },
                )])
            })
            .await;
            let mut report =
                report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
            analyze_bgp_routes_with(
                &mut report,
                request_timeout,
                tokio::time::Instant::now() + deadline,
                &tokio_util::sync::CancellationToken::new(),
                fixture_bgp_config(server),
                bgp_fixture_clients(request_timeout, server),
            )
            .await;
            let _ = requests.finish().await;
            report
        }

        let timed_out = delayed(Duration::from_millis(10), Duration::from_secs(1)).await;
        assert_eq!(timed_out.status, ScanStatus::Partial);
        assert!(timed_out.skipped_checks[0].reason.contains("timed out"));
        let deadline = delayed(Duration::from_secs(1), Duration::from_millis(10)).await;
        assert_eq!(deadline.status, ScanStatus::Partial);
        assert_eq!(deadline.skipped_checks[0].reason, "global timeout expired");

        let (server, requests) = mock_http_routes(1, |_| BTreeMap::new()).await;
        let cancellation = tokio_util::sync::CancellationToken::new();
        cancellation.cancel();
        let mut cancelled =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        analyze_bgp_routes_with(
            &mut cancelled,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &cancellation,
            fixture_bgp_config(server),
            bgp_fixture_clients(Duration::from_secs(1), server),
        )
        .await;
        assert_eq!(cancelled.status, ScanStatus::Interrupted);
        assert_eq!(cancelled.skipped_checks[0].reason, "scan interrupted");
        assert!(requests.finish().await.is_empty());
    }

    #[test]
    fn bgp_skip_is_deduplicated_and_preserves_terminal_states() {
        let mut report = report_with_dns([]);
        finish_bgp_routes(
            &mut report,
            Vec::new(),
            BTreeSet::from(["RIPEstat request failed"]),
            None,
        );
        finish_bgp_routes(
            &mut report,
            Vec::new(),
            BTreeSet::from(["RIPEstat request timed out"]),
            None,
        );
        assert_eq!(report.skipped_checks.len(), 1);
        assert_eq!(report.status, ScanStatus::Partial);

        report.status = ScanStatus::Failed;
        finish_bgp_routes(
            &mut report,
            Vec::new(),
            BTreeSet::new(),
            Some(BgpStop::Cancelled),
        );
        assert_eq!(report.status, ScanStatus::Failed);
        report.status = ScanStatus::Interrupted;
        finish_bgp_routes(
            &mut report,
            Vec::new(),
            BTreeSet::from(["RIPEstat request failed"]),
            None,
        );
        assert_eq!(report.status, ScanStatus::Interrupted);
        assert_eq!(report.skipped_checks.len(), 1);
    }

    #[tokio::test]
    async fn partial_rdap_success_is_retained_without_target_propagation() {
        let (server, requests) = mock_http_routes(3, |address| {
            let bootstrap = format!(
                r#"{{"services":[[["1.0.0.0/8","8.0.0.0/8"],["http://{address}/rdap/"]]]}}"#
            );
            BTreeMap::from([
                (
                    "/ipv4.json".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: bootstrap.into_bytes(),
                        delay: Duration::ZERO,
                    },
                ),
                (
                    "/rdap/ip/1.1.1.1".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: br#"{"objectClassName":"ip network","handle":"NET-1","startAddress":"1.0.0.0","endAddress":"1.255.255.255","country":"AU","entities":[{"handle":"DROP"}]}"#.to_vec(),
                        delay: Duration::ZERO,
                    },
                ),
                (
                    "/rdap/ip/8.8.8.8".to_owned(),
                    MockRoute {
                        status: "503 Service Unavailable",
                        headers: String::new(),
                        body: b"secret body".to_vec(),
                        delay: Duration::ZERO,
                    },
                ),
            ])
        })
        .await;
        let bootstrap = format!("http://{server}/ipv4.json");
        let allowed = [fixture_policy(server)];
        let mut report = report_with_dns([
            "8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}")),
            "1.1.1.1".parse().unwrap_or_else(|error| panic!("{error}")),
        ]);
        let hosts = report.hosts.clone();
        let services = report.services.clone();

        analyze_network_registrations_with(
            &mut report,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            RdapConfig {
                ipv4_bootstrap: &bootstrap,
                ipv6_bootstrap: &bootstrap,
                allowed_bases: &allowed,
            },
            fixture_clients(Duration::from_secs(1), [server]),
        )
        .await;
        let requests = requests.finish().await;

        let registrations = &report
            .intelligence
            .as_ref()
            .unwrap_or_else(|| panic!("missing intelligence"))
            .network_registrations;
        assert_eq!(registrations.len(), 1);
        assert_eq!(
            registrations[0].address,
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(report.status, ScanStatus::Partial);
        assert_eq!(report.skipped_checks.len(), 1);
        assert!(!report.skipped_checks[0].reason.contains("secret"));
        assert_eq!(report.hosts, hosts);
        assert_eq!(report.services, services);
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("GET /rdap/ip/"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn bootstrap_and_rdap_size_limits_are_enforced_before_json_parse() {
        let (bootstrap_server, bootstrap_requests) = mock_http_routes(1, |_| {
            BTreeMap::from([(
                "/ipv4.json".to_owned(),
                MockRoute {
                    status: "200 OK",
                    headers: String::new(),
                    body: vec![b' '; MAX_BOOTSTRAP_BYTES + 1],
                    delay: Duration::ZERO,
                },
            )])
        })
        .await;
        let endpoint = format!("http://{bootstrap_server}/ipv4.json");
        let mut report =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        analyze_network_registrations_with(
            &mut report,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            RdapConfig {
                ipv4_bootstrap: &endpoint,
                ipv6_bootstrap: &endpoint,
                allowed_bases: &[],
            },
            fixture_clients(Duration::from_secs(1), [bootstrap_server]),
        )
        .await;
        let bootstrap_requests = bootstrap_requests.finish().await;
        assert_eq!(bootstrap_requests.len(), 1);
        assert!(report.skipped_checks[0].reason.contains("64 KiB"));

        let (rdap_server, rdap_requests) = mock_http_routes(2, |address| {
            let bootstrap =
                format!(r#"{{"services":[[["8.0.0.0/8"],["http://{address}/rdap/"]]]}}"#);
            BTreeMap::from([
                (
                    "/ipv4.json".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: bootstrap.into_bytes(),
                        delay: Duration::ZERO,
                    },
                ),
                (
                    "/rdap/ip/8.8.8.8".to_owned(),
                    MockRoute {
                        status: "200 OK",
                        headers: String::new(),
                        body: vec![b' '; MAX_RDAP_RESPONSE_BYTES + 1],
                        delay: Duration::ZERO,
                    },
                ),
            ])
        })
        .await;
        let endpoint = format!("http://{rdap_server}/ipv4.json");
        let allowed = [fixture_policy(rdap_server)];
        let mut report =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        analyze_network_registrations_with(
            &mut report,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            RdapConfig {
                ipv4_bootstrap: &endpoint,
                ipv6_bootstrap: &endpoint,
                allowed_bases: &allowed,
            },
            fixture_clients(Duration::from_secs(1), [rdap_server]),
        )
        .await;
        let rdap_requests = rdap_requests.finish().await;
        assert_eq!(rdap_requests.len(), 2);
        assert!(report.skipped_checks[0].reason.contains("256 KiB"));
    }

    #[tokio::test]
    async fn rdap_redirects_are_not_followed() {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let target_url = format!(
            "http://{}/ipv4.json",
            target
                .local_addr()
                .unwrap_or_else(|error| panic!("{error}"))
        );
        let (redirect, requests) = mock_http_routes(1, move |_| {
            BTreeMap::from([(
                "/ipv4.json".to_owned(),
                MockRoute {
                    status: "302 Found",
                    headers: format!("Location: {target_url}\r\n"),
                    body: Vec::new(),
                    delay: Duration::ZERO,
                },
            )])
        })
        .await;
        let endpoint = format!("http://{redirect}/ipv4.json");
        let mut report =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        analyze_network_registrations_with(
            &mut report,
            Duration::from_secs(1),
            tokio::time::Instant::now() + Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
            RdapConfig {
                ipv4_bootstrap: &endpoint,
                ipv6_bootstrap: &endpoint,
                allowed_bases: &[],
            },
            fixture_clients(Duration::from_secs(1), [redirect]),
        )
        .await;
        let requests = requests.finish().await;
        assert_eq!(requests.len(), 1);

        assert!(
            tokio::time::timeout(Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
        assert!(report.skipped_checks[0].reason.contains("HTTP error"));
    }

    #[tokio::test]
    async fn request_timeout_deadline_and_cancellation_have_stable_lifecycle() {
        async fn run_delayed(request_timeout: Duration, deadline: Duration) -> ScanReport {
            let (server, requests) = mock_http_routes(2, |address| {
                let bootstrap =
                    format!(r#"{{"services":[[["8.0.0.0/8"],["http://{address}/rdap/"]]]}}"#);
                BTreeMap::from([
                    (
                        "/ipv4.json".to_owned(),
                        MockRoute {
                            status: "200 OK",
                            headers: String::new(),
                            body: bootstrap.into_bytes(),
                            delay: Duration::ZERO,
                        },
                    ),
                    (
                        "/rdap/ip/8.8.8.8".to_owned(),
                        MockRoute {
                            status: "200 OK",
                            headers: String::new(),
                            body: br#"{"objectClassName":"ip network"}"#.to_vec(),
                            delay: Duration::from_millis(100),
                        },
                    ),
                ])
            })
            .await;
            let endpoint = format!("http://{server}/ipv4.json");
            let allowed = [fixture_policy(server)];
            let mut report =
                report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
            tokio::time::timeout(
                Duration::from_secs(2),
                analyze_network_registrations_with(
                    &mut report,
                    request_timeout,
                    tokio::time::Instant::now() + deadline,
                    &tokio_util::sync::CancellationToken::new(),
                    RdapConfig {
                        ipv4_bootstrap: &endpoint,
                        ipv6_bootstrap: &endpoint,
                        allowed_bases: &allowed,
                    },
                    fixture_clients(request_timeout, [server]),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
            let requests = requests.finish().await;
            for path in ["/ipv4.json", "/rdap/ip/8.8.8.8"] {
                assert!(
                    requests
                        .iter()
                        .filter(|request| request.starts_with(&format!("GET {path} ")))
                        .count()
                        <= 1
                );
            }
            report
        }

        let timeout_report = run_delayed(Duration::from_millis(10), Duration::from_secs(1)).await;
        assert_eq!(timeout_report.status, ScanStatus::Partial);
        assert!(
            timeout_report.skipped_checks[0]
                .reason
                .contains("timed out")
        );

        let deadline_report = run_delayed(Duration::from_secs(1), Duration::from_millis(10)).await;
        assert_eq!(deadline_report.status, ScanStatus::Partial);
        assert_eq!(
            deadline_report.skipped_checks[0].reason,
            "global timeout expired"
        );

        let (server, requests) = mock_http_routes(1, |_| BTreeMap::new()).await;
        let endpoint = format!("http://{server}/ipv4.json");
        let cancellation = tokio_util::sync::CancellationToken::new();
        cancellation.cancel();
        let mut cancelled =
            report_with_dns(["8.8.8.8".parse().unwrap_or_else(|error| panic!("{error}"))]);
        tokio::time::timeout(
            Duration::from_secs(2),
            analyze_network_registrations_with(
                &mut cancelled,
                Duration::from_secs(1),
                tokio::time::Instant::now() + Duration::from_secs(1),
                &cancellation,
                RdapConfig {
                    ipv4_bootstrap: &endpoint,
                    ipv6_bootstrap: &endpoint,
                    allowed_bases: &[],
                },
                fixture_clients(Duration::from_secs(1), [server]),
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(cancelled.status, ScanStatus::Interrupted);
        assert_eq!(cancelled.skipped_checks[0].reason, "scan interrupted");
        assert!(requests.finish().await.is_empty());
    }

    #[test]
    fn network_registration_skip_is_deduplicated_and_preserves_terminal_states() {
        let mut report = report_with_dns([]);
        finish_network_registrations(
            &mut report,
            Vec::new(),
            BTreeSet::from(["RDAP request failed"]),
            None,
        );
        finish_network_registrations(
            &mut report,
            Vec::new(),
            BTreeSet::from(["RDAP request timed out"]),
            None,
        );
        assert_eq!(report.skipped_checks.len(), 1);
        assert_eq!(report.status, ScanStatus::Partial);

        report.status = ScanStatus::Failed;
        finish_network_registrations(
            &mut report,
            Vec::new(),
            BTreeSet::new(),
            Some(RdapStop::Cancelled),
        );
        assert_eq!(report.status, ScanStatus::Failed);
        report.status = ScanStatus::Interrupted;
        finish_network_registrations(
            &mut report,
            Vec::new(),
            BTreeSet::from(["RDAP request failed"]),
            None,
        );
        assert_eq!(report.status, ScanStatus::Interrupted);
        assert_eq!(report.skipped_checks.len(), 1);
    }

    #[test]
    fn older_intelligence_json_defaults_registration_evidence() {
        let observation: super::IntelligenceObservation = serde_json::from_str(
            r#"{
              "subdomains":[],"dkim":[],"networks":[],"cve_candidates":[],
              "bundle_version":null,"related_domains":null,
              "certificate_transparency":null,"complete":true,"errors":[]
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(observation.network_registrations.is_empty());
        assert!(observation.bgp_routes.is_empty());
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
