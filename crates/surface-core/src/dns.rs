//! Passive DNS collection and mail-record interpretation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use hickory_proto::{
    dnssec::Proof,
    op::{DnsResponse, OpCode, SerialMessage, update_message},
    rr::{Name, RData, Record, RecordType},
};
use hickory_resolver::{
    TokioResolver,
    net::{
        DnsError, DnsStreamHandle, NetError, runtime::TokioRuntimeProvider, tcp::TcpClientStream,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use tracing::{instrument::WithSubscriber, subscriber::NoSubscriber};
use uuid::Uuid;

use crate::{NormalizedTarget, ScanError, ScanErrorKind, ScanStage};

// Rust guideline compliant 2026-02-21

const MAX_DMARC_DESTINATIONS: usize = 16;
const MAX_DMARC_DESTINATION_CHARS: usize = 256;
const MAX_DNS_RECORDS: usize = 512;
const MAX_RESOLVED_HOSTS: usize = 16;
const MAX_SPECIAL_TXT_RECORDS: usize = 32;
const MAX_TXT_BYTES: usize = 2_048;

// Primary-target CNAME inspection is deliberately bounded and never expands discovery.
const MAX_CNAME_CHAIN_HOPS: usize = 16;
const MAX_DANGLING_CNAME_MESSAGES: usize = 8;
const MAX_DANGLING_CNAME_MESSAGE_CHARS: usize = 256;

// These limits bound authoritative infrastructure fan-out and transfer processing.
const MAX_AXFR_NAMESERVERS: usize = 4;
const MAX_AXFR_IPS_PER_NAMESERVER: usize = 2;
const MAX_AXFR_ENDPOINTS: usize = 8;
const MAX_AXFR_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_AXFR_RECORDS: usize = 4_096;
const MAX_AXFR_MESSAGES: usize = 64;

// Hickory yields one complete length-prefixed DNS message per stream item. This
// window lets a frame already queued to Tokio finish without waiting for TCP EOF.
// An arbitrarily delayed extra frame is indistinguishable from a persistent idle
// connection, so rejecting it would require waiting until the request timeout.
const AXFR_TRAILING_DRAIN_TIMEOUT: Duration = Duration::from_millis(10);

/// A serializable DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DnsRecord {
    /// IPv4 address record.
    A(Ipv4Addr),
    /// IPv6 address record.
    Aaaa(Ipv6Addr),
    /// Canonical name.
    Cname(String),
    /// Authoritative nameserver.
    Ns(String),
    /// Mail exchanger and preference.
    Mx { preference: u16, exchange: String },
    /// Text record, capped before storage.
    Txt(String),
    /// Certificate authority authorization.
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
}

/// Source of an actively scanned address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSource {
    /// Supplied directly by the operator.
    Explicit,
    /// Primary-host A record.
    ARecord,
    /// Primary-host AAAA record.
    AaaaRecord,
}

/// One canonical-name edge returned while resolving the primary target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CnameHop {
    /// Alias name.
    pub from: String,
    /// Canonical destination.
    pub to: String,
}

/// Conservative address status for one observed CNAME destination.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DanglingCnameStatus {
    /// At least one selected address query returned an address.
    Resolved,
    /// Every selected address query conclusively returned `NXDOMAIN`.
    #[serde(rename = "nxdomain")]
    NxDomain,
    /// Every selected query returned authenticated `NOERROR` without an address.
    NoAddress,
    /// Answers were incomplete, inconsistent, unauthenticated, or errored.
    #[default]
    Indeterminate,
}

impl DanglingCnameStatus {
    /// Returns the stable report representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NxDomain => "nxdomain",
            Self::NoAddress => "no_address",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Bounded evidence for one directly observed primary-chain CNAME destination.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DanglingCnameObservation {
    /// Directly observed source alias.
    pub source_alias: String,
    /// Directly observed canonical destination.
    pub canonical_target: String,
    /// Conservative selected-address classification.
    pub status: DanglingCnameStatus,
    /// Bounded protocol evidence used for classification.
    pub evidence: Vec<String>,
    /// Bounded request or resolver errors.
    pub errors: Vec<String>,
    /// Bounded scope and interpretation limitations.
    pub limitations: Vec<String>,
}

/// Associates a hostname with a discovered address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResolvedHost {
    /// Primary hostname, when present.
    pub hostname: Option<String>,
    /// Discovered address.
    pub ip: IpAddr,
    /// Discovery source.
    pub source: AddressSource,
}

/// Conservative SPF interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfObservation {
    /// Complete SPF records.
    pub records: Vec<String>,
    /// Last all-mechanism qualifier when directly parsable.
    pub terminal_policy: Option<String>,
}

/// Conservative DMARC interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmarcObservation {
    /// Complete DMARC record.
    pub record: String,
    /// Requested domain policy.
    pub policy: Option<String>,
    /// Requested subdomain policy.
    pub subdomain_policy: Option<String>,
    /// Percentage of messages covered.
    pub percentage: Option<u8>,
    /// Aggregate report destinations.
    pub aggregate_reports: Vec<String>,
    /// DKIM alignment mode.
    pub adkim: Option<String>,
    /// SPF alignment mode.
    pub aspf: Option<String>,
}

/// Passive mail-domain configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailObservation {
    /// Whether at least one MX record exists.
    pub mx_present: bool,
    /// SPF interpretation.
    pub spf: SpfObservation,
    /// DMARC records and interpretation.
    pub dmarc: Vec<DmarcObservation>,
    /// MTA-STS TXT records.
    pub mta_sts: Vec<String>,
    /// Whether the standard MTA-STS policy endpoint returned success.
    pub mta_sts_policy_available: Option<bool>,
    /// SMTP TLS reporting TXT records.
    pub tls_rpt: Vec<String>,
}

/// DNSSEC validation outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecStatus {
    /// Every retained proof established a trusted signature chain.
    Secure,
    /// The resolver authenticated that the `RRset` is unsigned or insecure.
    Insecure,
    /// Cryptographic validation failed for an `RRset` expected to be secure.
    Bogus,
    /// Validation could not reach a conclusive security state.
    #[default]
    Indeterminate,
    /// DNSSEC does not apply to this target or address-family selection.
    NotApplicable,
}

impl DnssecStatus {
    /// Returns the stable report representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Address `RRset` type requested from the validating resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecRecordType {
    /// `IPv4` address `RRset`.
    A,
    /// `IPv6` address `RRset`.
    Aaaa,
}

impl DnssecRecordType {
    const fn resolver_type(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
        }
    }

    /// Returns the DNS presentation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        }
    }
}

/// DNSSEC result for one bounded primary-host query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecRrsetObservation {
    /// Queried primary hostname.
    pub name: String,
    /// Requested address `RRset` type.
    pub record_type: DnssecRecordType,
    /// Resolver-derived DNSSEC status.
    pub status: DnssecStatus,
}

/// Bounded DNSSEC validation details for the primary hostname.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnssecObservation {
    /// Aggregate status across selected primary-host `RRsets`.
    pub status: DnssecStatus,
    /// Completed or failed primary-host `RRset` queries.
    pub checked_rrsets: Vec<DnssecRrsetObservation>,
    /// Validation or transport errors that prevented a conclusive result.
    pub errors: Vec<String>,
    /// Scope and interpretation limitations.
    pub limitations: Vec<String>,
}

/// Conservative wildcard-DNS detection outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WildcardDnsStatus {
    /// Both random names returned identical non-empty normalized answers.
    Detected,
    /// Both random names returned conclusive negative answers.
    NotDetected,
    /// Probe results were incomplete, mixed, unstable, or errored.
    #[default]
    Indeterminate,
    /// Wildcard DNS does not apply to a non-hostname target.
    NotApplicable,
}

impl WildcardDnsStatus {
    /// Returns the stable report representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::NotDetected => "not_detected",
            Self::Indeterminate => "indeterminate",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// DNS answer type retained in wildcard fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WildcardDnsRecordType {
    /// IPv4 address answer.
    A,
    /// IPv6 address answer.
    Aaaa,
    /// Canonical-name answer.
    Cname,
}

impl WildcardDnsRecordType {
    /// Returns the DNS presentation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
        }
    }
}

/// Bounded wildcard-DNS detection summary without random probe names.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WildcardDnsObservation {
    /// Conservative aggregate detection status.
    pub status: WildcardDnsStatus,
    /// Number of random child names for which querying began.
    pub probes_attempted: u8,
    /// Sorted answer record types observed across both probes.
    pub answer_types: Vec<WildcardDnsRecordType>,
    /// Sorted SHA-256 fingerprints of bounded normalized answers.
    pub answer_fingerprints: Vec<String>,
    /// Bounded diagnostics that never contain random probe names.
    pub errors: Vec<String>,
    /// Bounded scope and interpretation limitations.
    pub limitations: Vec<String>,
    /// Always false because probe answers never become active targets.
    pub probe_answers_scanned: bool,
}

/// Classification of one authoritative AXFR endpoint attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AxfrOutcome {
    /// A complete SOA-delimited transfer was returned.
    Allowed,
    /// The authoritative server refused the request.
    Refused,
    /// The server reported that it was not authoritative.
    NotAuthoritative,
    /// The TCP exchange or AXFR framing ended without a complete transfer.
    Incomplete,
    /// A TCP connection could not be established.
    Unreachable,
    /// The endpoint deadline or request timeout expired.
    Timeout,
    /// The caller cancelled the endpoint attempt.
    Cancelled,
    /// A byte, record, or message processing bound was reached.
    LimitExceeded,
}

impl AxfrOutcome {
    /// Returns the stable report representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Refused => "refused",
            Self::NotAuthoritative => "not_authoritative",
            Self::Incomplete => "incomplete",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::LimitExceeded => "limit_exceeded",
        }
    }
}

/// Fixed limits applied to authoritative AXFR discovery and processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AxfrLimits {
    /// Maximum explicitly observed NS hostnames.
    pub nameservers: usize,
    /// Maximum resolved addresses retained per NS hostname.
    pub ips_per_nameserver: usize,
    /// Maximum deduplicated TCP endpoints attempted.
    pub endpoints: usize,
    /// Maximum DNS payload bytes processed per endpoint.
    pub bytes: usize,
    /// Maximum answer records processed per endpoint.
    pub records: usize,
    /// Maximum DNS messages processed per endpoint.
    pub messages: usize,
}

impl Default for AxfrLimits {
    fn default() -> Self {
        Self {
            nameservers: MAX_AXFR_NAMESERVERS,
            ips_per_nameserver: MAX_AXFR_IPS_PER_NAMESERVER,
            endpoints: MAX_AXFR_ENDPOINTS,
            bytes: MAX_AXFR_BYTES,
            records: MAX_AXFR_RECORDS,
            messages: MAX_AXFR_MESSAGES,
        }
    }
}

/// Counts-only result from one authoritative TCP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxfrAttempt {
    /// Explicitly observed authoritative NS hostname associated with the endpoint.
    pub server: String,
    /// Deduplicated TCP endpoint.
    pub endpoint: SocketAddr,
    /// Protocol and transport outcome.
    pub outcome: AxfrOutcome,
    /// First DNS response code, when a response was decoded.
    pub response_code: Option<String>,
    /// DNS messages processed without crossing the bound.
    pub messages: usize,
    /// Answer records processed without crossing the bound.
    pub records: usize,
    /// DNS payload bytes processed without crossing the bound.
    pub bytes: usize,
    /// Stable diagnostic that never contains transferred owner names or records.
    pub error: Option<String>,
}

/// Bounded authoritative AXFR observations for one evidenced zone.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthoritativeAxfrObservation {
    /// Exact zone origin established from SOA and matching NS evidence.
    pub zone: String,
    /// Explicitly observed authoritative NS hostnames considered for resolution.
    pub nameservers: Vec<String>,
    /// Deduplicated TCP endpoint attempts.
    pub attempts: Vec<AxfrAttempt>,
    /// Applied discovery and transfer limits.
    pub limits: AxfrLimits,
    /// Always false because transferred records are reduced to bounded counts.
    pub transferred_records_retained: bool,
    /// Always false because transferred owner names are never stored.
    pub transferred_owner_names_retained: bool,
    /// Always false because transferred owner names never become scan targets.
    pub transferred_owner_names_scanned: bool,
}

#[derive(Debug)]
pub(crate) struct AuthoritativeEvidence {
    zone: Name,
    nameservers: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct DnsBaseline {
    pub(crate) observation: DnsObservation,
    pub(crate) authority: Option<AuthoritativeEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AxfrCheckState {
    Completed,
    Skipped(&'static str),
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct AxfrCheck {
    pub(crate) observation: Option<AuthoritativeAxfrObservation>,
    pub(crate) state: AxfrCheckState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WildcardDnsCheckState {
    Completed,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct WildcardDnsCheck {
    pub(crate) observation: WildcardDnsObservation,
    pub(crate) state: WildcardDnsCheckState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DanglingCnameCheckState {
    Completed,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct DanglingCnameCheck {
    pub(crate) observations: Vec<DanglingCnameObservation>,
    pub(crate) state: DanglingCnameCheckState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DanglingQueryOutcome {
    Address,
    NxDomain,
    NoAddress,
    Indeterminate,
}

/// Passive DNS results for the primary hostname.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsObservation {
    /// Primary queried hostname.
    pub queried_name: String,
    /// Raw normalized records from all supported queries.
    pub records: Vec<DnsRecord>,
    /// Canonical-name edges returned by the resolver for the primary target.
    #[serde(default)]
    pub cname_chain: Vec<CnameHop>,
    /// Conservative checks of only directly observed primary-chain destinations.
    #[serde(default)]
    pub dangling_cnames: Vec<DanglingCnameObservation>,
    /// Deduplicated active-scan addresses for only the primary target.
    pub resolved_hosts: Vec<ResolvedHost>,
    /// Passive mail-domain interpretation.
    pub mail: MailObservation,
    /// DNSSEC validation added in schema 0.3.0; absent in older reports.
    #[serde(default)]
    pub dnssec: Option<DnssecObservation>,
    /// Authoritative AXFR checking added in schema 0.3.0; absent in older reports.
    #[serde(default)]
    pub authoritative_axfr: Option<AuthoritativeAxfrObservation>,
    /// Wildcard-DNS detection added in schema 0.3.0; absent in older reports.
    #[serde(default)]
    pub wildcard_dns: Option<WildcardDnsObservation>,
    /// Recoverable lookup errors.
    pub errors: Vec<ScanError>,
}

/// Performs bounded passive DNS queries for the primary target.
///
/// # Errors
///
/// Returns an error only when the system resolver cannot be initialized.
pub async fn analyze_dns(
    target: &NormalizedTarget,
    query_timeout: Duration,
    ipv4_only: bool,
    ipv6_only: bool,
) -> Result<DnsObservation, String> {
    let mut observation =
        analyze_dns_baseline_for_scan(target, query_timeout, ipv4_only, ipv6_only, true)
            .await?
            .observation;
    if observation.dnssec.is_none() {
        observation.dnssec =
            Some(analyze_dnssec(target, query_timeout, ipv4_only, ipv6_only).await);
    }
    Ok(observation)
}

#[expect(
    clippy::too_many_lines,
    reason = "linear bounded DNS collection keeps one authoritative baseline flow"
)]
pub(crate) async fn analyze_dns_baseline_for_scan(
    target: &NormalizedTarget,
    query_timeout: Duration,
    ipv4_only: bool,
    ipv6_only: bool,
    fetch_mta_sts_policy: bool,
) -> Result<DnsBaseline, String> {
    if let Some(ip) = target.explicit_ip {
        return Ok(DnsBaseline {
            observation: explicit_ip_observation(target, ip),
            authority: None,
        });
    }
    let hostname = target
        .hostname
        .as_deref()
        .ok_or_else(|| "target has no hostname".to_owned())?;
    let resolver = TokioResolver::builder_tokio()
        .map_err(|error| format!("could not initialize system DNS resolver: {error}"))?
        .build()
        .map_err(|error| format!("could not build system DNS resolver: {error}"))?;

    let mut records = Vec::new();
    let mut resolved_hosts = BTreeSet::new();
    let mut cname_chain = BTreeSet::new();
    let mut errors = Vec::new();
    let query_types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::NS,
        RecordType::MX,
        RecordType::TXT,
        RecordType::CAA,
    ];
    for record_type in query_types {
        if (ipv4_only && record_type == RecordType::AAAA)
            || (ipv6_only && record_type == RecordType::A)
        {
            continue;
        }
        lookup(
            &resolver,
            hostname,
            record_type,
            query_timeout,
            &mut records,
            &mut resolved_hosts,
            &mut cname_chain,
            &mut errors,
        )
        .await;
    }

    if records.len() > MAX_DNS_RECORDS {
        records.truncate(MAX_DNS_RECORDS);
        errors.push(ScanError::new(
            ScanStage::Dns,
            Some(hostname.to_owned()),
            ScanErrorKind::Other,
            format!("DNS records truncated at {MAX_DNS_RECORDS}"),
            true,
        ));
    }

    let mut dmarc_records = Vec::new();
    let mut mta_sts = Vec::new();
    let mut tls_rpt = Vec::new();
    lookup_txt_values(
        &resolver,
        &format!("_dmarc.{hostname}"),
        query_timeout,
        &mut dmarc_records,
    )
    .await;
    lookup_txt_values(
        &resolver,
        &format!("_mta-sts.{hostname}"),
        query_timeout,
        &mut mta_sts,
    )
    .await;
    lookup_txt_values(
        &resolver,
        &format!("_smtp._tls.{hostname}"),
        query_timeout,
        &mut tls_rpt,
    )
    .await;

    let authority = authoritative_evidence(&resolver, hostname, query_timeout).await;

    records.sort_by_key(record_sort_key);
    records.dedup();
    let resolved_hosts = resolved_hosts
        .into_iter()
        .take(MAX_RESOLVED_HOSTS)
        .collect();
    let cname_chain = ordered_cname_chain(hostname, cname_chain);
    let mut mail = interpret_mail(&records, &dmarc_records, mta_sts, tls_rpt);
    if fetch_mta_sts_policy && !mail.mta_sts.is_empty() {
        mail.mta_sts_policy_available = check_mta_sts_policy(hostname, query_timeout).await;
    }
    Ok(DnsBaseline {
        observation: DnsObservation {
            queried_name: hostname.to_owned(),
            records,
            cname_chain,
            dangling_cnames: Vec::new(),
            resolved_hosts,
            mail,
            dnssec: None,
            authoritative_axfr: None,
            wildcard_dns: None,
            errors,
        },
        authority,
    })
}

async fn authoritative_evidence(
    resolver: &TokioResolver,
    hostname: &str,
    query_timeout: Duration,
) -> Option<AuthoritativeEvidence> {
    let queried_name = Name::from_ascii(format!("{hostname}.")).ok()?;
    let soa_result = timeout(
        query_timeout,
        resolver.lookup(queried_name.clone(), RecordType::SOA),
    )
    .await
    .ok()?;
    let zone = match soa_result {
        Ok(lookup) => exact_soa_zone(&queried_name, lookup.answers()),
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => no_records
            .authorities
            .as_deref()
            .and_then(|records| exact_soa_zone(&queried_name, records)),
        Err(_) => None,
    }?;

    let lookup = timeout(query_timeout, resolver.lookup(zone.clone(), RecordType::NS))
        .await
        .ok()?
        .ok()?;
    let nameservers = evidenced_nameservers(&zone, lookup.answers());
    (!nameservers.is_empty()).then_some(AuthoritativeEvidence { zone, nameservers })
}

fn exact_soa_zone(queried_name: &Name, records: &[Record]) -> Option<Name> {
    let mut zones = records
        .iter()
        .filter(|record| matches!(&record.data, RData::SOA(_)) && record.name.zone_of(queried_name))
        .map(|record| record.name.clone())
        .collect::<BTreeSet<_>>();
    let zone = zones.pop_first()?;
    zones.is_empty().then_some(zone)
}

fn evidenced_nameservers(zone: &Name, records: &[Record]) -> Vec<String> {
    records
        .iter()
        .filter(|record| &record.name == zone)
        .filter_map(|record| match &record.data {
            RData::NS(nameserver) => Some(trim_name(nameserver.to_string())),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_AXFR_NAMESERVERS)
        .collect()
}

fn add_axfr_endpoints(
    endpoints: &mut BTreeMap<SocketAddr, String>,
    nameserver: &str,
    addresses: impl IntoIterator<Item = IpAddr>,
) {
    for ip in addresses
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_AXFR_IPS_PER_NAMESERVER)
    {
        if endpoints.len() >= MAX_AXFR_ENDPOINTS {
            break;
        }
        endpoints
            .entry(SocketAddr::new(ip, 53))
            .or_insert_with(|| nameserver.to_owned());
    }
}

pub(crate) async fn analyze_authoritative_axfr(
    evidence: AuthoritativeEvidence,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> AxfrCheck {
    if cancellation.is_cancelled() {
        return AxfrCheck {
            observation: None,
            state: AxfrCheckState::Cancelled,
        };
    }
    if Instant::now() >= deadline {
        return AxfrCheck {
            observation: None,
            state: AxfrCheckState::TimedOut,
        };
    }
    let nameservers = evidence
        .nameservers
        .into_iter()
        .take(MAX_AXFR_NAMESERVERS)
        .collect::<Vec<_>>();
    let Ok(resolver) =
        TokioResolver::builder_tokio().and_then(hickory_resolver::ResolverBuilder::build)
    else {
        return AxfrCheck {
            observation: None,
            state: AxfrCheckState::Skipped(
                "authoritative NS endpoints could not be resolved from observed NS hostnames",
            ),
        };
    };
    let mut endpoints = BTreeMap::new();
    for nameserver in &nameservers {
        let lookup_deadline = deadline.min(Instant::now() + request_timeout);
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return AxfrCheck {
                    observation: None,
                    state: AxfrCheckState::Cancelled,
                };
            }
            result = timeout_at(lookup_deadline, resolver.lookup_ip(nameserver)) => result,
        };
        let Ok(Ok(lookup)) = result else {
            if Instant::now() >= deadline {
                return AxfrCheck {
                    observation: None,
                    state: AxfrCheckState::TimedOut,
                };
            }
            continue;
        };
        add_axfr_endpoints(&mut endpoints, nameserver, lookup.iter());
    }
    if endpoints.is_empty() {
        return AxfrCheck {
            observation: None,
            state: AxfrCheckState::Skipped(
                "authoritative NS endpoints could not be resolved from observed NS hostnames",
            ),
        };
    }

    let mut observation = AuthoritativeAxfrObservation {
        zone: trim_name(evidence.zone.to_string()),
        nameservers,
        ..AuthoritativeAxfrObservation::default()
    };
    for (endpoint, server) in endpoints.into_iter().take(MAX_AXFR_ENDPOINTS) {
        let endpoint_deadline = deadline.min(Instant::now() + request_timeout);
        let attempt = check_axfr_endpoint(
            server,
            endpoint,
            evidence.zone.clone(),
            request_timeout,
            endpoint_deadline,
            cancellation,
        )
        .await;
        let outcome = attempt.outcome;
        observation.attempts.push(attempt);
        if outcome == AxfrOutcome::Cancelled {
            return AxfrCheck {
                observation: Some(observation),
                state: AxfrCheckState::Cancelled,
            };
        }
        if Instant::now() >= deadline {
            return AxfrCheck {
                observation: Some(observation),
                state: AxfrCheckState::TimedOut,
            };
        }
    }
    AxfrCheck {
        observation: Some(observation),
        state: AxfrCheckState::Completed,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the official Hickory framed TCP stream and every terminal outcome stay auditable together"
)]
async fn check_axfr_endpoint(
    server: String,
    endpoint: SocketAddr,
    zone: Name,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> AxfrAttempt {
    let mut attempt = AxfrAttempt {
        server,
        endpoint,
        outcome: AxfrOutcome::Unreachable,
        response_code: None,
        messages: 0,
        records: 0,
        bytes: 0,
        error: None,
    };
    let provider = TokioRuntimeProvider::new();
    let (stream, sender) =
        TcpClientStream::new(endpoint, None, Some(request_timeout), provider.clone());
    let connected = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            attempt.outcome = AxfrOutcome::Cancelled;
            attempt.error = Some("AXFR endpoint attempt was cancelled".to_owned());
            return attempt;
        }
        result = timeout_at(deadline, stream) => result,
    };
    let mut stream = match connected {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            attempt.error = Some("TCP connection to authoritative endpoint failed".to_owned());
            return attempt;
        }
        Err(_) => {
            attempt.outcome = AxfrOutcome::Timeout;
            attempt.error = Some("AXFR endpoint deadline expired during TCP connection".to_owned());
            return attempt;
        }
    };

    // Hickory's AXFR wrapper stops at the closing SOA; the framed TCP stream exposes trailing data.
    let request = update_message::zone_transfer(zone.clone(), None);
    let request_id = request.metadata.id;
    let expected_queries = request.queries.clone();
    let Ok(request) = request.to_vec() else {
        attempt.outcome = AxfrOutcome::Incomplete;
        attempt.error = Some("AXFR request could not be encoded".to_owned());
        return attempt;
    };
    let mut sender = sender;
    if sender.send(SerialMessage::new(request, endpoint)).is_err() {
        attempt.error = Some("AXFR request could not be sent".to_owned());
        return attempt;
    }

    let request_deadline = deadline.min(Instant::now() + request_timeout);
    let mut first_soa_serial = None;
    let mut soa_count = 0_usize;
    let mut first_answer_seen = false;
    let mut closing_soa_seen = false;
    let mut authoritative = true;
    let mut truncated = false;

    loop {
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                attempt.outcome = AxfrOutcome::Cancelled;
                attempt.error = Some("AXFR endpoint attempt was cancelled".to_owned());
                break;
            }
            result = timeout_at(request_deadline, stream.next()) => result,
        };
        let serial = match next {
            Err(_) => {
                attempt.outcome = AxfrOutcome::Timeout;
                attempt.error = Some(if request_deadline == deadline {
                    "AXFR endpoint deadline expired".to_owned()
                } else {
                    "AXFR request timed out".to_owned()
                });
                break;
            }
            Ok(Some(Err(_))) => {
                attempt.outcome = AxfrOutcome::Incomplete;
                attempt.error = Some("AXFR response framing was invalid or incomplete".to_owned());
                break;
            }
            Ok(None) => {
                if attempt.messages > 0 && closing_soa_seen && authoritative && !truncated {
                    attempt.outcome = AxfrOutcome::Allowed;
                } else {
                    attempt.outcome = AxfrOutcome::Incomplete;
                    attempt.error = Some(
                        "AXFR ended without a complete authoritative SOA-delimited transfer"
                            .to_owned(),
                    );
                }
                break;
            }
            Ok(Some(Ok(serial))) => serial,
        };

        if closing_soa_seen {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error = Some("AXFR contained a message after the closing SOA".to_owned());
            break;
        }

        let response_bytes = serial.into_parts().0;
        let Ok(response) = DnsResponse::from_buffer(response_bytes) else {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error = Some("AXFR response framing was invalid or incomplete".to_owned());
            break;
        };
        if response.metadata.id != request_id {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error = Some("AXFR response used an unexpected DNS message ID".to_owned());
            break;
        }
        if response.metadata.op_code != OpCode::Query {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error = Some("AXFR response used an unexpected DNS opcode".to_owned());
            break;
        }
        let response_code = response.metadata.response_code;
        if response.queries != expected_queries
            && (attempt.messages == 0
                || response_code != hickory_proto::op::ResponseCode::NoError
                || !response.queries.is_empty())
        {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error =
                Some("AXFR response did not contain an allowed AXFR question section".to_owned());
            break;
        }

        let next_messages = attempt.messages.saturating_add(1);
        let next_bytes = attempt.bytes.saturating_add(response.as_buffer().len());
        let next_records = attempt.records.saturating_add(response.answers.len());
        let exceeded = if next_messages > MAX_AXFR_MESSAGES {
            Some(format!(
                "AXFR exceeded the {MAX_AXFR_MESSAGES}-message limit"
            ))
        } else if next_bytes > MAX_AXFR_BYTES {
            Some(format!("AXFR exceeded the {MAX_AXFR_BYTES}-byte limit"))
        } else if next_records > MAX_AXFR_RECORDS {
            Some(format!("AXFR exceeded the {MAX_AXFR_RECORDS}-record limit"))
        } else {
            None
        };
        if let Some(error) = exceeded {
            attempt.outcome = AxfrOutcome::LimitExceeded;
            attempt.error = Some(error);
            break;
        }
        attempt.messages = next_messages;
        attempt.bytes = next_bytes;
        attempt.records = next_records;

        let response_code_text = format!("{response_code:?}");
        if attempt.response_code.is_none() {
            attempt.response_code = Some(response_code_text.clone());
        } else if attempt.response_code.as_deref() != Some(response_code_text.as_str()) {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error = Some("AXFR response code changed during the transfer".to_owned());
            break;
        }
        match response_code {
            hickory_proto::op::ResponseCode::NoError => {}
            hickory_proto::op::ResponseCode::Refused => {
                attempt.outcome = AxfrOutcome::Refused;
                break;
            }
            hickory_proto::op::ResponseCode::NotAuth => {
                attempt.outcome = AxfrOutcome::NotAuthoritative;
                break;
            }
            _ => {
                attempt.outcome = AxfrOutcome::Incomplete;
                attempt.error = Some(format!(
                    "authoritative endpoint returned DNS response code {response_code_text}"
                ));
                break;
            }
        }
        authoritative &= response.metadata.authoritative;
        truncated |= response.metadata.truncation;
        for record in &response.answers {
            if closing_soa_seen {
                attempt.outcome = AxfrOutcome::Incomplete;
                attempt.error = Some("AXFR contained a record after the closing SOA".to_owned());
                break;
            }
            if !first_answer_seen {
                first_answer_seen = true;
                if let RData::SOA(soa) = &record.data
                    && record.name == zone
                {
                    first_soa_serial = Some(soa.serial);
                }
            }
            if let RData::SOA(soa) = &record.data {
                soa_count = soa_count.saturating_add(1);
                if soa_count >= 2 && record.name == zone && first_soa_serial == Some(soa.serial) {
                    closing_soa_seen = true;
                }
            }
        }
        if attempt.outcome == AxfrOutcome::Incomplete {
            break;
        }
        if closing_soa_seen && (!authoritative || truncated) {
            attempt.outcome = AxfrOutcome::Incomplete;
            attempt.error = Some(
                "AXFR ended without a complete authoritative SOA-delimited transfer".to_owned(),
            );
            break;
        }
        if closing_soa_seen {
            let drain_deadline = request_deadline.min(Instant::now() + AXFR_TRAILING_DRAIN_TIMEOUT);
            let trailing = tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    attempt.outcome = AxfrOutcome::Cancelled;
                    attempt.error = Some("AXFR endpoint attempt was cancelled".to_owned());
                    break;
                }
                result = timeout_at(drain_deadline, stream.next()) => result,
            };
            match trailing {
                Ok(Some(Ok(_))) => {
                    attempt.outcome = AxfrOutcome::Incomplete;
                    attempt.error =
                        Some("AXFR contained a message after the closing SOA".to_owned());
                }
                Ok(Some(Err(_))) => {
                    attempt.outcome = AxfrOutcome::Incomplete;
                    attempt.error =
                        Some("AXFR response framing was invalid or incomplete".to_owned());
                }
                Ok(None) | Err(_) => attempt.outcome = AxfrOutcome::Allowed,
            }
            break;
        }
    }
    attempt
}

#[expect(
    clippy::too_many_lines,
    reason = "resolver setup and two bounded query outcomes stay visible together"
)]
pub(crate) async fn analyze_dnssec(
    target: &NormalizedTarget,
    query_timeout: Duration,
    ipv4_only: bool,
    ipv6_only: bool,
) -> DnssecObservation {
    if target.explicit_ip.is_some() {
        return DnssecObservation {
            status: DnssecStatus::NotApplicable,
            limitations: vec!["DNSSEC validation applies only to hostname targets.".to_owned()],
            ..DnssecObservation::default()
        };
    }
    let Some(hostname) = target.hostname.as_deref() else {
        return DnssecObservation {
            status: DnssecStatus::NotApplicable,
            limitations: vec!["DNSSEC validation applies only to hostname targets.".to_owned()],
            ..DnssecObservation::default()
        };
    };
    let query_types = match (ipv4_only, ipv6_only) {
        (true, false) => &DNSSEC_A[..],
        (false, true) => &DNSSEC_AAAA[..],
        (false, false) => &DNSSEC_A_AND_AAAA[..],
        (true, true) => {
            return DnssecObservation {
                status: DnssecStatus::NotApplicable,
                limitations: vec![
                    "No address RRset is selected when both address-family filters are enabled."
                        .to_owned(),
                ],
                ..DnssecObservation::default()
            };
        }
    };
    let mut observation = DnssecObservation {
        limitations: vec![
            "Validation uses Hickory Resolver's built-in trust anchors and covers only selected primary-host A/AAAA RRsets."
                .to_owned(),
        ],
        ..DnssecObservation::default()
    };
    let mut builder = match TokioResolver::builder_tokio() {
        Ok(builder) => builder,
        Err(error) => {
            observation.errors.push(capped(format!(
                "could not initialize validating DNS resolver: {error}"
            )));
            return observation;
        }
    };
    builder.options_mut().validate = true;
    builder.options_mut().try_tcp_on_error = true;
    let resolver = match builder.build() {
        Ok(resolver) => resolver,
        Err(error) => {
            observation.errors.push(capped(format!(
                "could not build validating DNS resolver: {error}"
            )));
            return observation;
        }
    };

    for &record_type in query_types {
        let result = timeout(
            query_timeout,
            resolver.lookup(hostname, record_type.resolver_type()),
        )
        .await;
        let status = match result {
            Ok(Ok(lookup)) => {
                let status =
                    dnssec_status_from_proofs(lookup.answers().iter().map(|record| record.proof));
                if status == DnssecStatus::Indeterminate {
                    observation.errors.push(format!(
                        "{} {} validation returned no conclusive DNSSEC proof",
                        hostname,
                        record_type.as_str()
                    ));
                }
                status
            }
            Ok(Err(error)) => {
                let status =
                    dnssec_status_from_lookup_error(&error).unwrap_or(DnssecStatus::Indeterminate);
                if status == DnssecStatus::Indeterminate {
                    observation.errors.push(capped(format!(
                        "{} {} validation failed: {error}",
                        hostname,
                        record_type.as_str()
                    )));
                }
                status
            }
            Err(_) => {
                observation.errors.push(format!(
                    "{} {} validation timed out",
                    hostname,
                    record_type.as_str()
                ));
                DnssecStatus::Indeterminate
            }
        };
        observation.checked_rrsets.push(DnssecRrsetObservation {
            name: hostname.to_owned(),
            record_type,
            status,
        });
    }
    observation.status =
        aggregate_dnssec_status(observation.checked_rrsets.iter().map(|rrset| rrset.status));
    observation
}

struct WildcardProbeResult {
    fingerprints: BTreeSet<String>,
    answer_types: BTreeSet<WildcardDnsRecordType>,
    all_negative: bool,
    conclusive: bool,
    limited: bool,
}

impl Default for WildcardProbeResult {
    fn default() -> Self {
        Self {
            fingerprints: BTreeSet::new(),
            answer_types: BTreeSet::new(),
            all_negative: true,
            conclusive: true,
            limited: false,
        }
    }
}

pub(crate) async fn analyze_wildcard_dns(
    target: &NormalizedTarget,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    ipv4_only: bool,
    ipv6_only: bool,
) -> WildcardDnsCheck {
    let Some(hostname) = target
        .hostname
        .as_deref()
        .filter(|_| target.explicit_ip.is_none())
    else {
        return WildcardDnsCheck {
            observation: WildcardDnsObservation {
                status: WildcardDnsStatus::NotApplicable,
                limitations: vec![
                    "Wildcard DNS detection applies only to hostname targets.".to_owned(),
                    "Random probe answers were not scanned or used as downstream targets."
                        .to_owned(),
                ],
                ..WildcardDnsObservation::default()
            },
            state: WildcardDnsCheckState::Completed,
        };
    };
    let probe_names = wildcard_probe_names(hostname);
    let Ok(mut builder) = TokioResolver::builder_tokio() else {
        return WildcardDnsCheck {
            observation: wildcard_resolver_failure(
                "Could not initialize the wildcard DNS resolver.",
            ),
            state: WildcardDnsCheckState::Completed,
        };
    };
    builder.options_mut().validate = true;
    builder.options_mut().try_tcp_on_error = true;
    let Ok(resolver) = builder.build() else {
        return WildcardDnsCheck {
            observation: wildcard_resolver_failure("Could not build the wildcard DNS resolver."),
            state: WildcardDnsCheckState::Completed,
        };
    };
    analyze_wildcard_dns_with_resolver(
        &resolver,
        &probe_names,
        request_timeout,
        deadline,
        cancellation,
        ipv4_only,
        ipv6_only,
    )
    .await
}

fn wildcard_probe_names(hostname: &str) -> [String; 2] {
    let hostname = hostname.trim_end_matches('.');
    [
        format!("{}.{}.", Uuid::new_v4().simple(), hostname),
        format!("{}.{}.", Uuid::new_v4().simple(), hostname),
    ]
}

fn wildcard_resolver_failure(message: &str) -> WildcardDnsObservation {
    WildcardDnsObservation {
        errors: vec![message.to_owned()],
        limitations: vec![
            "Wildcard DNS status is indeterminate because no probes completed.".to_owned(),
            "Random probe answers were not scanned or used as downstream targets.".to_owned(),
        ],
        ..WildcardDnsObservation::default()
    }
}

async fn analyze_wildcard_dns_with_resolver(
    resolver: &TokioResolver,
    probe_names: &[String; 2],
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    ipv4_only: bool,
    ipv6_only: bool,
) -> WildcardDnsCheck {
    let query_types = match (ipv4_only, ipv6_only) {
        (true, false) => &WILDCARD_A_AND_CNAME[..],
        (false, true) => &WILDCARD_AAAA_AND_CNAME[..],
        (false, false) => &WILDCARD_A_AAAA_AND_CNAME[..],
        (true, true) => &WILDCARD_CNAME[..],
    };
    let mut observation = WildcardDnsObservation {
        limitations: vec![
            "Detection uses exactly two random UUID-v4 child names and selected A/AAAA plus CNAME lookups."
                .to_owned(),
            "Random probe answers were not scanned or used as downstream targets.".to_owned(),
        ],
        ..WildcardDnsObservation::default()
    };
    let mut probes = Vec::with_capacity(2);
    for (probe_index, probe_name) in probe_names.iter().enumerate() {
        let state = if cancellation.is_cancelled() {
            Some(WildcardDnsCheckState::Cancelled)
        } else if Instant::now() >= deadline {
            Some(WildcardDnsCheckState::TimedOut)
        } else {
            None
        };
        if let Some(state) = state {
            finish_wildcard_observation(&mut observation, &probes);
            return WildcardDnsCheck { observation, state };
        }
        observation.probes_attempted = observation.probes_attempted.saturating_add(1);
        let mut probe = WildcardProbeResult::default();
        for &record_type in query_types {
            if let Err(state) = wildcard_lookup(
                resolver,
                probe_name,
                record_type,
                probe_index,
                request_timeout,
                deadline,
                cancellation,
                &mut probe,
                &mut observation.errors,
            )
            .await
            {
                probes.push(probe);
                finish_wildcard_observation(&mut observation, &probes);
                return WildcardDnsCheck { observation, state };
            }
        }
        probes.push(probe);
    }
    finish_wildcard_observation(&mut observation, &probes);
    WildcardDnsCheck {
        observation,
        state: WildcardDnsCheckState::Completed,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "one lookup mutates only its bounded probe and report diagnostics"
)]
async fn wildcard_lookup(
    resolver: &TokioResolver,
    probe_name: &str,
    record_type: RecordType,
    probe_index: usize,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    probe: &mut WildcardProbeResult,
    errors: &mut Vec<String>,
) -> Result<(), WildcardDnsCheckState> {
    if cancellation.is_cancelled() {
        probe.conclusive = false;
        return Err(WildcardDnsCheckState::Cancelled);
    }
    let now = Instant::now();
    if now >= deadline {
        probe.conclusive = false;
        return Err(WildcardDnsCheckState::TimedOut);
    }
    let request_deadline = now + request_timeout;
    let lookup_deadline = deadline.min(request_deadline);
    let result = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            probe.conclusive = false;
            return Err(WildcardDnsCheckState::Cancelled);
        }
        result = timeout_at(
            lookup_deadline,
            resolver
                .lookup(probe_name, record_type)
                .with_subscriber(NoSubscriber::default()),
        ) => result,
    };
    let result = match result {
        Ok(result) => result,
        Err(_) if deadline <= request_deadline => {
            probe.conclusive = false;
            return Err(WildcardDnsCheckState::TimedOut);
        }
        Err(_) => {
            probe.conclusive = false;
            probe.all_negative = false;
            push_wildcard_message(
                errors,
                format!(
                    "Probe {} {} lookup reached the request timeout.",
                    probe_index + 1,
                    record_type
                ),
            );
            return Ok(());
        }
    };
    match result {
        Ok(lookup) => {
            let before = probe.fingerprints.len();
            append_wildcard_answers(lookup.answers(), probe);
            if probe.fingerprints.len() == before {
                probe.conclusive = false;
                probe.all_negative = false;
                push_wildcard_message(
                    errors,
                    format!(
                        "Probe {} {} lookup returned no supported answer records.",
                        probe_index + 1,
                        record_type
                    ),
                );
            } else {
                probe.all_negative = false;
            }
        }
        Err(error) if wildcard_negative_response(&error) => {}
        Err(error) => {
            probe.conclusive = false;
            probe.all_negative = false;
            push_wildcard_message(
                errors,
                format!(
                    "Probe {} {} lookup {}.",
                    probe_index + 1,
                    record_type,
                    wildcard_error_summary(&error)
                ),
            );
        }
    }
    Ok(())
}

fn append_wildcard_answers(records: &[Record], probe: &mut WildcardProbeResult) {
    let mut retained_bytes = probe.fingerprints.iter().map(String::len).sum::<usize>();
    for record in records {
        let (record_type, normalized) = match &record.data {
            RData::A(value) => (WildcardDnsRecordType::A, format!("A:{}", value.0)),
            RData::AAAA(value) => (WildcardDnsRecordType::Aaaa, format!("AAAA:{}", value.0)),
            RData::CNAME(value) => (
                WildcardDnsRecordType::Cname,
                format!(
                    "CNAME:{}",
                    trim_name(value.to_string()).to_ascii_lowercase()
                ),
            ),
            _ => continue,
        };
        if probe.fingerprints.contains(&normalized) {
            continue;
        }
        if probe.fingerprints.len() >= MAX_DNS_RECORDS
            || retained_bytes.saturating_add(normalized.len()) > MAX_TXT_BYTES
        {
            probe.limited = true;
            probe.conclusive = false;
            break;
        }
        retained_bytes = retained_bytes.saturating_add(normalized.len());
        probe.answer_types.insert(record_type);
        probe.fingerprints.insert(normalized);
    }
}

fn wildcard_negative_response(error: &NetError) -> bool {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            matches!(
                no_records.response_code,
                hickory_proto::op::ResponseCode::NXDomain
                    | hickory_proto::op::ResponseCode::NoError
            ) && no_records
                .authorities
                .as_deref()
                .is_some_and(authenticated_negative_authorities)
        }
        NetError::Dns(DnsError::Nsec {
            response, proof, ..
        }) => {
            matches!(
                response.response_code,
                hickory_proto::op::ResponseCode::NXDomain
                    | hickory_proto::op::ResponseCode::NoError
            ) && matches!(proof, Proof::Secure | Proof::Insecure)
                && authenticated_negative_authorities(&response.authorities)
        }
        _ => false,
    }
}

fn authenticated_negative_authorities(records: &[Record]) -> bool {
    let mut relevant = records
        .iter()
        .filter(|record| {
            matches!(
                record.record_type(),
                RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
            )
        })
        .peekable();
    relevant.peek().is_some()
        && relevant.all(|record| matches!(record.proof, Proof::Secure | Proof::Insecure))
}

fn wildcard_error_summary(error: &NetError) -> &'static str {
    match error {
        NetError::Dns(DnsError::ResponseCode(hickory_proto::op::ResponseCode::ServFail)) => {
            "returned SERVFAIL"
        }
        NetError::Dns(DnsError::NoRecordsFound(_) | DnsError::Nsec { .. }) => {
            "returned an unauthenticated negative answer"
        }
        NetError::Timeout => "reached the resolver timeout",
        NetError::Io(_) | NetError::NoConnections => "failed at the DNS transport layer",
        _ => "failed without a conclusive answer",
    }
}

fn finish_wildcard_observation(
    observation: &mut WildcardDnsObservation,
    probes: &[WildcardProbeResult],
) {
    observation.status = if probes.len() == 2
        && probes
            .iter()
            .all(|probe| probe.conclusive && !probe.limited)
    {
        if probes.iter().all(|probe| probe.all_negative) {
            WildcardDnsStatus::NotDetected
        } else if !probes[0].fingerprints.is_empty()
            && probes[0].fingerprints == probes[1].fingerprints
        {
            WildcardDnsStatus::Detected
        } else {
            WildcardDnsStatus::Indeterminate
        }
    } else {
        WildcardDnsStatus::Indeterminate
    };
    let answer_types = probes
        .iter()
        .flat_map(|probe| probe.answer_types.iter().copied())
        .collect::<BTreeSet<_>>();
    let raw_fingerprints = probes
        .iter()
        .flat_map(|probe| probe.fingerprints.iter())
        .collect::<BTreeSet<_>>();
    if probes.iter().any(|probe| probe.limited) {
        push_wildcard_message(
            &mut observation.limitations,
            format!(
                "Wildcard answers exceeded the {MAX_DNS_RECORDS}-record or {MAX_TXT_BYTES}-byte DNS bound."
            ),
        );
    }
    if observation.status == WildcardDnsStatus::Indeterminate {
        push_wildcard_message(
            &mut observation.limitations,
            "Mixed, rotating, incomplete, or errored probe answers are not classified as wildcard DNS."
                .to_owned(),
        );
    }
    observation.answer_types = answer_types.into_iter().collect();
    let hashed_fingerprints = raw_fingerprints
        .into_iter()
        .map(|value| format!("sha256:{:x}", Sha256::digest(value.as_bytes())))
        .collect::<BTreeSet<_>>();
    let fingerprint_count = hashed_fingerprints.len();
    let mut retained_bytes = 0_usize;
    observation.answer_fingerprints = hashed_fingerprints
        .into_iter()
        .take(MAX_DNS_RECORDS)
        .take_while(|fingerprint| {
            let next_bytes = retained_bytes.saturating_add(fingerprint.len());
            if next_bytes > MAX_TXT_BYTES {
                return false;
            }
            retained_bytes = next_bytes;
            true
        })
        .collect();
    if observation.answer_fingerprints.len() < fingerprint_count {
        push_wildcard_message(
            &mut observation.limitations,
            format!(
                "Wildcard fingerprint summary was truncated at the {MAX_DNS_RECORDS}-record or {MAX_TXT_BYTES}-byte DNS bound."
            ),
        );
    }
    observation.errors.truncate(MAX_SPECIAL_TXT_RECORDS);
    observation.limitations.truncate(MAX_SPECIAL_TXT_RECORDS);
}

fn push_wildcard_message(messages: &mut Vec<String>, message: String) {
    if messages.len() < MAX_SPECIAL_TXT_RECORDS {
        messages.push(capped(message));
    }
}

pub(crate) async fn analyze_dangling_cnames(
    cname_chain: &[CnameHop],
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    ipv4_only: bool,
    ipv6_only: bool,
) -> DanglingCnameCheck {
    let mut observations = cname_chain
        .iter()
        .take(MAX_CNAME_CHAIN_HOPS)
        .map(dangling_cname_observation)
        .collect::<Vec<_>>();
    if observations.is_empty() {
        return DanglingCnameCheck {
            observations,
            state: DanglingCnameCheckState::Completed,
        };
    }
    let query_types = match (ipv4_only, ipv6_only) {
        (true, false) => &DANGLING_A[..],
        (false, true) => &DANGLING_AAAA[..],
        (false, false) => &DANGLING_A_AND_AAAA[..],
        (true, true) => {
            for observation in &mut observations {
                push_dangling_message(
                    &mut observation.limitations,
                    "No address record type was selected.".to_owned(),
                );
            }
            return DanglingCnameCheck {
                observations,
                state: DanglingCnameCheckState::Completed,
            };
        }
    };

    let Ok(mut builder) = TokioResolver::builder_tokio() else {
        mark_dangling_resolver_failure(
            &mut observations,
            "Could not initialize the CNAME destination resolver.",
        );
        return DanglingCnameCheck {
            observations,
            state: DanglingCnameCheckState::Completed,
        };
    };
    builder.options_mut().validate = true;
    builder.options_mut().try_tcp_on_error = true;
    let Ok(resolver) = builder.build() else {
        mark_dangling_resolver_failure(
            &mut observations,
            "Could not build the CNAME destination resolver.",
        );
        return DanglingCnameCheck {
            observations,
            state: DanglingCnameCheckState::Completed,
        };
    };
    analyze_dangling_cnames_with_resolver(
        &resolver,
        observations,
        query_types,
        request_timeout,
        deadline,
        cancellation,
    )
    .await
}

fn dangling_cname_observation(hop: &CnameHop) -> DanglingCnameObservation {
    DanglingCnameObservation {
        source_alias: hop.from.clone(),
        canonical_target: hop.to.clone(),
        limitations: vec![
            "Only selected A/AAAA lookups were performed; ownership, claimability, and takeover feasibility were not tested."
                .to_owned(),
            "Destination addresses were not scanned or used as downstream targets.".to_owned(),
        ],
        ..DanglingCnameObservation::default()
    }
}

fn mark_dangling_resolver_failure(observations: &mut [DanglingCnameObservation], message: &str) {
    for observation in observations {
        push_dangling_message(&mut observation.errors, message.to_owned());
    }
}

async fn analyze_dangling_cnames_with_resolver(
    resolver: &TokioResolver,
    mut observations: Vec<DanglingCnameObservation>,
    query_types: &[RecordType],
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> DanglingCnameCheck {
    let mut classified_targets = BTreeMap::<String, usize>::new();
    for index in 0..observations.len() {
        let target = observations[index].canonical_target.clone();
        let normalized_target = target.to_ascii_lowercase();
        if let Some(&classified_index) = classified_targets.get(&normalized_target) {
            let classified = observations[classified_index].clone();
            observations[index].status = classified.status;
            observations[index].evidence = classified.evidence;
            observations[index].errors = classified.errors;
            observations[index].limitations = classified.limitations;
            continue;
        }
        if classified_targets.len() >= MAX_CNAME_CHAIN_HOPS {
            push_dangling_message(
                &mut observations[index].limitations,
                format!(
                    "CNAME destination checking is limited to {MAX_CNAME_CHAIN_HOPS} unique targets."
                ),
            );
            continue;
        }

        let mut outcomes = Vec::with_capacity(query_types.len());
        for &record_type in query_types {
            match dangling_cname_lookup(
                resolver,
                &target,
                record_type,
                request_timeout,
                deadline,
                cancellation,
                &mut observations[index],
            )
            .await
            {
                Ok(outcome) => outcomes.push(outcome),
                Err(state) => {
                    let message = match state {
                        DanglingCnameCheckState::Cancelled => {
                            "CNAME destination checking was cancelled."
                        }
                        DanglingCnameCheckState::TimedOut => {
                            "The caller deadline expired during CNAME destination checking."
                        }
                        DanglingCnameCheckState::Completed => {
                            "CNAME destination checking stopped before completion."
                        }
                    };
                    for observation in &mut observations[index..] {
                        push_dangling_message(&mut observation.limitations, message.to_owned());
                    }
                    return DanglingCnameCheck {
                        observations,
                        state,
                    };
                }
            }
        }
        observations[index].status = classify_dangling_outcomes(&outcomes);
        classified_targets.insert(normalized_target, index);
    }
    DanglingCnameCheck {
        observations,
        state: DanglingCnameCheckState::Completed,
    }
}

async fn dangling_cname_lookup(
    resolver: &TokioResolver,
    target: &str,
    record_type: RecordType,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    observation: &mut DanglingCnameObservation,
) -> Result<DanglingQueryOutcome, DanglingCnameCheckState> {
    if cancellation.is_cancelled() {
        return Err(DanglingCnameCheckState::Cancelled);
    }
    let now = Instant::now();
    if now >= deadline {
        return Err(DanglingCnameCheckState::TimedOut);
    }
    let request_deadline = now + request_timeout;
    let lookup_deadline = deadline.min(request_deadline);
    let result = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(DanglingCnameCheckState::Cancelled),
        result = timeout_at(lookup_deadline, resolver.lookup(target, record_type)) => result,
    };
    let result = match result {
        Ok(result) => result,
        Err(_) if deadline <= request_deadline => {
            return Err(DanglingCnameCheckState::TimedOut);
        }
        Err(_) => {
            push_dangling_message(
                &mut observation.errors,
                format!("{record_type} lookup reached the request timeout."),
            );
            return Ok(DanglingQueryOutcome::Indeterminate);
        }
    };

    match result {
        Ok(lookup)
            if lookup.answers().iter().any(|record| match record_type {
                RecordType::A => matches!(&record.data, RData::A(_)),
                RecordType::AAAA => matches!(&record.data, RData::AAAA(_)),
                _ => false,
            }) =>
        {
            push_dangling_message(
                &mut observation.evidence,
                format!("{record_type} returned an address answer."),
            );
            Ok(DanglingQueryOutcome::Address)
        }
        Ok(_) => {
            push_dangling_message(
                &mut observation.errors,
                format!(
                    "{record_type} returned no selected address or authenticated negative evidence."
                ),
            );
            Ok(DanglingQueryOutcome::Indeterminate)
        }
        Err(error) => {
            if let Some(outcome) = dangling_negative_outcome(&error) {
                let description = match outcome {
                    DanglingQueryOutcome::NxDomain => "conclusive authenticated NXDOMAIN",
                    DanglingQueryOutcome::NoAddress => {
                        "authenticated NOERROR/NODATA with SOA/NSEC/NSEC3 evidence"
                    }
                    DanglingQueryOutcome::Address | DanglingQueryOutcome::Indeterminate => {
                        "an indeterminate negative answer"
                    }
                };
                push_dangling_message(
                    &mut observation.evidence,
                    format!("{record_type} returned {description}."),
                );
                Ok(outcome)
            } else {
                push_dangling_message(
                    &mut observation.errors,
                    format!("{record_type} lookup {}.", wildcard_error_summary(&error)),
                );
                Ok(DanglingQueryOutcome::Indeterminate)
            }
        }
    }
}

fn dangling_negative_outcome(error: &NetError) -> Option<DanglingQueryOutcome> {
    let response_code = match error {
        NetError::Dns(DnsError::NoRecordsFound(no_records))
            if no_records
                .authorities
                .as_deref()
                .is_some_and(authenticated_negative_authorities) =>
        {
            no_records.response_code
        }
        NetError::Dns(DnsError::Nsec {
            response, proof, ..
        }) if matches!(proof, Proof::Secure | Proof::Insecure)
            && authenticated_negative_authorities(&response.authorities) =>
        {
            response.response_code
        }
        _ => return None,
    };
    match response_code {
        hickory_proto::op::ResponseCode::NXDomain => Some(DanglingQueryOutcome::NxDomain),
        hickory_proto::op::ResponseCode::NoError => Some(DanglingQueryOutcome::NoAddress),
        _ => None,
    }
}

fn classify_dangling_outcomes(outcomes: &[DanglingQueryOutcome]) -> DanglingCnameStatus {
    if outcomes.contains(&DanglingQueryOutcome::Address) {
        DanglingCnameStatus::Resolved
    } else if !outcomes.is_empty()
        && outcomes
            .iter()
            .all(|outcome| *outcome == DanglingQueryOutcome::NxDomain)
    {
        DanglingCnameStatus::NxDomain
    } else if !outcomes.is_empty()
        && outcomes
            .iter()
            .all(|outcome| *outcome == DanglingQueryOutcome::NoAddress)
    {
        DanglingCnameStatus::NoAddress
    } else {
        DanglingCnameStatus::Indeterminate
    }
}

fn push_dangling_message(messages: &mut Vec<String>, message: impl Into<String>) {
    if messages.len() >= MAX_DANGLING_CNAME_MESSAGES {
        return;
    }
    let mut message = message.into();
    if let Some((boundary, _)) = message.char_indices().nth(MAX_DANGLING_CNAME_MESSAGE_CHARS) {
        message.truncate(boundary);
    }
    if !messages.contains(&message) {
        messages.push(message);
    }
}

const DANGLING_A: [RecordType; 1] = [RecordType::A];
const DANGLING_AAAA: [RecordType; 1] = [RecordType::AAAA];
const DANGLING_A_AND_AAAA: [RecordType; 2] = [RecordType::A, RecordType::AAAA];
const DNSSEC_A: [DnssecRecordType; 1] = [DnssecRecordType::A];
const DNSSEC_AAAA: [DnssecRecordType; 1] = [DnssecRecordType::Aaaa];
const DNSSEC_A_AND_AAAA: [DnssecRecordType; 2] = [DnssecRecordType::A, DnssecRecordType::Aaaa];
const WILDCARD_A_AND_CNAME: [RecordType; 2] = [RecordType::A, RecordType::CNAME];
const WILDCARD_AAAA_AND_CNAME: [RecordType; 2] = [RecordType::AAAA, RecordType::CNAME];
const WILDCARD_A_AAAA_AND_CNAME: [RecordType; 3] =
    [RecordType::A, RecordType::AAAA, RecordType::CNAME];
const WILDCARD_CNAME: [RecordType; 1] = [RecordType::CNAME];

fn dnssec_status_from_lookup_error(error: &NetError) -> Option<DnssecStatus> {
    match error {
        NetError::Dns(DnsError::Nsec { proof, .. }) => Some(dnssec_status_from_proof(*proof)),
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => no_records
            .authorities
            .as_deref()
            .map(|records| dnssec_status_from_proofs(records.iter().map(|record| record.proof))),
        _ => None,
    }
}

fn dnssec_status_from_proofs(proofs: impl IntoIterator<Item = Proof>) -> DnssecStatus {
    aggregate_dnssec_status(proofs.into_iter().map(dnssec_status_from_proof))
}

const fn dnssec_status_from_proof(proof: Proof) -> DnssecStatus {
    match proof {
        Proof::Secure => DnssecStatus::Secure,
        Proof::Insecure => DnssecStatus::Insecure,
        Proof::Bogus => DnssecStatus::Bogus,
        Proof::Indeterminate => DnssecStatus::Indeterminate,
    }
}

fn aggregate_dnssec_status(statuses: impl IntoIterator<Item = DnssecStatus>) -> DnssecStatus {
    let mut aggregate = None;
    for status in statuses {
        match status {
            DnssecStatus::Bogus => return DnssecStatus::Bogus,
            DnssecStatus::Indeterminate => aggregate = Some(DnssecStatus::Indeterminate),
            DnssecStatus::Insecure if aggregate != Some(DnssecStatus::Indeterminate) => {
                aggregate = Some(DnssecStatus::Insecure);
            }
            DnssecStatus::Secure if aggregate.is_none() => {
                aggregate = Some(DnssecStatus::Secure);
            }
            DnssecStatus::Secure | DnssecStatus::Insecure | DnssecStatus::NotApplicable => {}
        }
    }
    aggregate.unwrap_or(DnssecStatus::Indeterminate)
}

#[expect(
    clippy::too_many_arguments,
    reason = "bounded DNS lookup appends to one deterministic observation"
)]
async fn lookup(
    resolver: &TokioResolver,
    name: &str,
    record_type: RecordType,
    query_timeout: Duration,
    records: &mut Vec<DnsRecord>,
    resolved_hosts: &mut BTreeSet<ResolvedHost>,
    cname_chain: &mut BTreeSet<CnameHop>,
    errors: &mut Vec<ScanError>,
) {
    match timeout(query_timeout, resolver.lookup(name, record_type)).await {
        Ok(Ok(result)) => {
            for record in result.answers() {
                let owner = trim_name(record.name.to_string());
                match &record.data {
                    RData::A(value) => {
                        resolved_hosts.insert(ResolvedHost {
                            hostname: Some(owner),
                            ip: IpAddr::V4(value.0),
                            source: AddressSource::ARecord,
                        });
                    }
                    RData::AAAA(value) => {
                        resolved_hosts.insert(ResolvedHost {
                            hostname: Some(owner),
                            ip: IpAddr::V6(value.0),
                            source: AddressSource::AaaaRecord,
                        });
                    }
                    RData::CNAME(value) => {
                        cname_chain.insert(CnameHop {
                            from: owner,
                            to: trim_name(value.to_string()),
                        });
                    }
                    _ => {}
                }
                if let Some(record) = convert_record(&record.data) {
                    records.push(record);
                }
            }
        }
        Ok(Err(error)) if error.is_no_records_found() || error.is_nx_domain() => {}
        Ok(Err(error)) => errors.push(ScanError::new(
            ScanStage::Dns,
            Some(name.to_owned()),
            ScanErrorKind::Dns,
            format!("{record_type} lookup failed: {error}"),
            true,
        )),
        Err(_) => errors.push(ScanError::new(
            ScanStage::Dns,
            Some(name.to_owned()),
            ScanErrorKind::Timeout,
            format!("{record_type} lookup timed out"),
            true,
        )),
    }
}

/// Looks up bounded TXT values for an explicitly supplied DNS name.
///
/// # Errors
///
/// Returns an error when the system resolver cannot be initialized.
pub async fn lookup_txt(name: &str, query_timeout: Duration) -> Result<Vec<String>, String> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|error| format!("could not initialize system DNS resolver: {error}"))?
        .build()
        .map_err(|error| format!("could not build system DNS resolver: {error}"))?;
    let mut values = Vec::new();
    lookup_txt_values(&resolver, name, query_timeout, &mut values).await;
    Ok(values)
}

async fn lookup_txt_values(
    resolver: &TokioResolver,
    name: &str,
    query_timeout: Duration,
    values: &mut Vec<String>,
) {
    if let Ok(Ok(result)) = timeout(query_timeout, resolver.lookup(name, RecordType::TXT)).await {
        values.extend(
            result
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(txt_value(txt.txt_data.iter().map(AsRef::as_ref))),
                    _ => None,
                }),
        );
        values.sort();
        values.truncate(MAX_SPECIAL_TXT_RECORDS);
    }
}

fn convert_record(data: &RData) -> Option<DnsRecord> {
    match data {
        RData::A(value) => Some(DnsRecord::A(value.0)),
        RData::AAAA(value) => Some(DnsRecord::Aaaa(value.0)),
        RData::CNAME(value) => Some(DnsRecord::Cname(trim_name(value.to_string()))),
        RData::NS(value) => Some(DnsRecord::Ns(trim_name(value.to_string()))),
        RData::MX(value) => Some(DnsRecord::Mx {
            preference: value.preference,
            exchange: trim_name(value.exchange.to_string()),
        }),
        RData::TXT(value) => Some(DnsRecord::Txt(txt_value(
            value.txt_data.iter().map(AsRef::as_ref),
        ))),
        RData::CAA(value) => Some(DnsRecord::Caa {
            flags: value.reserved_flags | u8::from(value.issuer_critical) << 7,
            tag: value.tag.clone(),
            value: capped(String::from_utf8_lossy(&value.value).into_owned()),
        }),
        _ => None,
    }
}

fn txt_value<'a>(parts: impl Iterator<Item = &'a [u8]>) -> String {
    capped(String::from_utf8_lossy(&parts.flatten().copied().collect::<Vec<_>>()).into_owned())
}

fn capped(mut value: String) -> String {
    if value.len() > MAX_TXT_BYTES {
        let mut boundary = MAX_TXT_BYTES;
        while !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.truncate(boundary);
    }
    value
}

fn trim_name(mut value: String) -> String {
    value.truncate(value.trim_end_matches('.').len());
    value.to_lowercase()
}

fn record_sort_key(record: &DnsRecord) -> String {
    format!("{record:?}")
}

fn ordered_cname_chain(hostname: &str, mut edges: BTreeSet<CnameHop>) -> Vec<CnameHop> {
    let mut chain = Vec::new();
    let mut visited = BTreeSet::new();
    let mut current = hostname.to_owned();
    while chain.len() < MAX_CNAME_CHAIN_HOPS && visited.insert(current.clone()) {
        let Some(hop) = edges
            .iter()
            .find(|hop| hop.from.eq_ignore_ascii_case(&current))
            .cloned()
        else {
            break;
        };
        edges.remove(&hop);
        current.clone_from(&hop.to);
        chain.push(hop);
    }
    chain
}

fn explicit_ip_observation(target: &NormalizedTarget, ip: IpAddr) -> DnsObservation {
    DnsObservation {
        queried_name: target.hostname.clone().unwrap_or_else(|| ip.to_string()),
        records: Vec::new(),
        cname_chain: Vec::new(),
        dangling_cnames: Vec::new(),
        resolved_hosts: vec![ResolvedHost {
            hostname: None,
            ip,
            source: AddressSource::Explicit,
        }],
        mail: interpret_mail(&[], &[], Vec::new(), Vec::new()),
        dnssec: Some(DnssecObservation {
            status: DnssecStatus::NotApplicable,
            limitations: vec!["DNSSEC validation applies only to hostname targets.".to_owned()],
            ..DnssecObservation::default()
        }),
        authoritative_axfr: None,
        wildcard_dns: Some(WildcardDnsObservation {
            status: WildcardDnsStatus::NotApplicable,
            limitations: vec![
                "Wildcard DNS detection applies only to hostname targets.".to_owned(),
                "Random probe answers were not scanned or used as downstream targets.".to_owned(),
            ],
            ..WildcardDnsObservation::default()
        }),
        errors: Vec::new(),
    }
}

/// Interprets passive mail records without making delivery-security claims.
#[must_use]
pub fn interpret_mail(
    records: &[DnsRecord],
    dmarc_records: &[String],
    mta_sts: Vec<String>,
    tls_rpt: Vec<String>,
) -> MailObservation {
    let mut spf_records = records
        .iter()
        .filter_map(|record| match record {
            DnsRecord::Txt(value) if value.to_ascii_lowercase().starts_with("v=spf1 ") => {
                Some(value.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    spf_records.sort();
    let terminal_policy = spf_records.first().and_then(|record| {
        record
            .split_ascii_whitespace()
            .rev()
            .find(|term| matches!(*term, "-all" | "~all" | "?all" | "+all" | "all"))
            .map(str::to_owned)
    });
    let mut dmarc = dmarc_records
        .iter()
        .filter(|record| record.to_ascii_lowercase().starts_with("v=dmarc1"))
        .map(|record| parse_dmarc(record))
        .collect::<Vec<_>>();
    dmarc.sort_by(|left, right| left.record.cmp(&right.record));

    MailObservation {
        mx_present: records
            .iter()
            .any(|record| matches!(record, DnsRecord::Mx { .. })),
        spf: SpfObservation {
            records: spf_records,
            terminal_policy,
        },
        dmarc,
        mta_sts,
        mta_sts_policy_available: None,
        tls_rpt,
    }
}

async fn check_mta_sts_policy(domain: &str, request_timeout: Duration) -> Option<bool> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    client
        .get(url)
        .send()
        .await
        .ok()
        .map(|response| response.status().is_success())
}

fn parse_dmarc(record: &str) -> DmarcObservation {
    let mut result = DmarcObservation {
        record: record.to_owned(),
        policy: None,
        subdomain_policy: None,
        percentage: None,
        aggregate_reports: Vec::new(),
        adkim: None,
        aspf: None,
    };
    for part in record.split(';').map(str::trim) {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        match name.to_ascii_lowercase().as_str() {
            "p" => result.policy = Some(value.to_ascii_lowercase()),
            "sp" => result.subdomain_policy = Some(value.to_ascii_lowercase()),
            "pct" => result.percentage = value.parse::<u8>().ok().filter(|value| *value <= 100),
            "rua" => {
                result.aggregate_reports = value
                    .split(',')
                    .map(str::trim)
                    .take(MAX_DMARC_DESTINATIONS)
                    .map(|destination| {
                        destination
                            .chars()
                            .take(MAX_DMARC_DESTINATION_CHARS)
                            .collect()
                    })
                    .collect();
            }
            "adkim" => result.adkim = Some(value.to_ascii_lowercase()),
            "aspf" => result.aspf = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        io::{self, Write},
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use hickory_proto::{
        dnssec::{
            Proof,
            rdata::{DNSSECRData, NSEC},
        },
        op::{DnsResponse, Message, OpCode, Query, ResponseCode},
        rr::{
            DNSClass, Name, RData, Record, RecordType,
            rdata::{A, CNAME, NS, SOA, TXT},
        },
    };
    use hickory_resolver::{
        TokioResolver,
        config::{ConnectionConfig, NameServerConfig, ResolverConfig},
        net::{DnsError, NetError, runtime::TokioRuntimeProvider},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        task::JoinHandle,
        time::Instant,
    };
    use tokio_util::sync::CancellationToken;
    use tracing::instrument::WithSubscriber;

    use super::{
        AXFR_TRAILING_DRAIN_TIMEOUT, AuthoritativeAxfrObservation, AxfrOutcome, CnameHop,
        DANGLING_A, DANGLING_A_AND_AAAA, DanglingCnameCheckState, DanglingCnameStatus,
        DanglingQueryOutcome, DnsObservation, DnsRecord, DnssecStatus, MAX_AXFR_BYTES,
        MAX_AXFR_ENDPOINTS, MAX_AXFR_IPS_PER_NAMESERVER, MAX_AXFR_MESSAGES, MAX_AXFR_NAMESERVERS,
        MAX_AXFR_RECORDS, MAX_CNAME_CHAIN_HOPS, MAX_DMARC_DESTINATION_CHARS,
        MAX_DMARC_DESTINATIONS, WildcardDnsCheckState, WildcardDnsStatus, add_axfr_endpoints,
        analyze_dangling_cnames_with_resolver, analyze_wildcard_dns_with_resolver,
        check_axfr_endpoint, classify_dangling_outcomes, dangling_cname_observation,
        dangling_negative_outcome, dnssec_status_from_lookup_error, dnssec_status_from_proofs,
        evidenced_nameservers, exact_soa_zone, explicit_ip_observation, interpret_mail,
        ordered_cname_chain, parse_dmarc, wildcard_probe_names,
    };
    use crate::{generate_findings, normalize_target};

    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("captured log lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    enum MockReply {
        Message(Message),
        CustomMessage(Message),
        Raw(Vec<u8>),
        Hold(Duration),
    }

    #[derive(Clone, Copy)]
    enum MockWildcardReply {
        Identical,
        NxDomain,
        NoData,
        Rotating,
        ServFail,
        Hold,
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the local DNS fixture keeps each deterministic reply behavior together"
    )]
    async fn mock_wildcard_dns(
        reply: MockWildcardReply,
    ) -> (TokioResolver, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = socket
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            let mut bytes = [0_u8; 2_048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut bytes).await else {
                    return;
                };
                let Ok(request) = Message::from_vec(&bytes[..length]) else {
                    continue;
                };
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };
                captured
                    .lock()
                    .expect("wildcard query capture lock")
                    .push(query.name.to_string().trim_end_matches('.').to_lowercase());
                if matches!(reply, MockWildcardReply::Hold) {
                    continue;
                }
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response.metadata.authoritative = true;
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                match reply {
                    MockWildcardReply::Identical => match query.query_type {
                        RecordType::A => {
                            response.add_answer(Record::from_rdata(
                                query.name,
                                60,
                                RData::A(A(Ipv4Addr::new(192, 0, 2, 200))),
                            ));
                        }
                        RecordType::CNAME => {
                            response.add_answer(Record::from_rdata(
                                query.name,
                                60,
                                RData::CNAME(CNAME(
                                    Name::from_ascii("wildcard.target.test.")
                                        .unwrap_or_else(|error| panic!("{error}")),
                                )),
                            ));
                        }
                        _ => {}
                    },
                    MockWildcardReply::Rotating => match query.query_type {
                        RecordType::A => {
                            let last_octet = if query.name.to_string().starts_with("probe-one.") {
                                201
                            } else {
                                202
                            };
                            response.add_answer(Record::from_rdata(
                                query.name,
                                60,
                                RData::A(A(Ipv4Addr::new(192, 0, 2, last_octet))),
                            ));
                        }
                        RecordType::CNAME => {
                            response.add_answer(Record::from_rdata(
                                query.name,
                                60,
                                RData::CNAME(CNAME(
                                    Name::from_ascii("wildcard.target.test.")
                                        .unwrap_or_else(|error| panic!("{error}")),
                                )),
                            ));
                        }
                        _ => {}
                    },
                    MockWildcardReply::NxDomain | MockWildcardReply::NoData => {
                        if matches!(reply, MockWildcardReply::NxDomain) {
                            response.metadata.response_code = ResponseCode::NXDomain;
                        }
                        let zone = Name::from_ascii("example.test.")
                            .unwrap_or_else(|error| panic!("{error}"));
                        response.add_authority(soa_record(&zone, 1));
                    }
                    MockWildcardReply::ServFail => {
                        response.metadata.response_code = ResponseCode::ServFail;
                    }
                    MockWildcardReply::Hold => continue,
                }
                let Ok(response_bytes) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&response_bytes, peer).await;
            }
        });

        let mut connection = ConnectionConfig::udp();
        connection.port = address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(address.ip(), true, vec![connection])],
        );
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().attempts = 1;
        builder.options_mut().cache_size = 0;
        builder.options_mut().num_concurrent_reqs = 1;
        builder.options_mut().timeout = Duration::from_secs(1);
        let resolver = builder.build().unwrap_or_else(|error| panic!("{error}"));
        (resolver, seen, task)
    }

    async fn run_wildcard_fixture(
        reply: MockWildcardReply,
        request_timeout: Duration,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> (super::WildcardDnsCheck, Vec<String>) {
        let (resolver, seen, task) = mock_wildcard_dns(reply).await;
        let names = [
            "probe-one.example.test".to_owned(),
            "probe-two.example.test".to_owned(),
        ];
        let check = analyze_wildcard_dns_with_resolver(
            &resolver,
            &names,
            request_timeout,
            deadline,
            cancellation,
            true,
            false,
        )
        .await;
        task.abort();
        let seen = seen.lock().expect("wildcard query capture lock").clone();
        (check, seen)
    }

    async fn mock_tcp_dns(replies: Vec<MockReply>) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let task = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let Ok(length) = socket.read_u16().await else {
                return;
            };
            let mut request_bytes = vec![0; usize::from(length)];
            if socket.read_exact(&mut request_bytes).await.is_err() {
                return;
            }
            let Ok(request) = Message::from_vec(&request_bytes) else {
                return;
            };
            for reply in replies {
                let bytes = match reply {
                    MockReply::Message(mut message) => {
                        message.metadata.id = request.metadata.id;
                        message.queries.clone_from(&request.queries);
                        match message.to_vec() {
                            Ok(bytes) => bytes,
                            Err(_) => return,
                        }
                    }
                    MockReply::CustomMessage(mut message) => {
                        message.metadata.id = request.metadata.id;
                        match message.to_vec() {
                            Ok(bytes) => bytes,
                            Err(_) => return,
                        }
                    }
                    MockReply::Raw(bytes) => bytes,
                    MockReply::Hold(duration) => {
                        tokio::time::sleep(duration).await;
                        continue;
                    }
                };
                let Ok(length) = u16::try_from(bytes.len()) else {
                    return;
                };
                if socket.write_u16(length).await.is_err()
                    || socket.write_all(&bytes).await.is_err()
                {
                    return;
                }
            }
        });
        (address, task)
    }

    fn soa_record(zone: &Name, serial: u32) -> Record {
        Record::from_rdata(
            zone.clone(),
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.test.").unwrap_or_else(|error| panic!("{error}")),
                Name::from_ascii("hostmaster.example.test.")
                    .unwrap_or_else(|error| panic!("{error}")),
                serial,
                60,
                60,
                60,
                60,
            )),
        )
    }

    fn ns_record(zone: &Name, nameserver: &Name) -> Record {
        Record::from_rdata(zone.clone(), 60, RData::NS(NS(nameserver.clone())))
    }

    fn axfr_message(response_code: ResponseCode, answers: Vec<Record>) -> Message {
        let mut message = Message::response(0, OpCode::Query);
        message.metadata.response_code = response_code;
        message.metadata.authoritative = true;
        message.insert_answers(answers);
        message
    }

    #[test]
    fn axfr_authority_requires_unambiguous_soa_and_exact_ns_evidence() {
        let hostname =
            Name::from_ascii("www.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let parent = Name::from_ascii("test.").unwrap_or_else(|error| panic!("{error}"));
        let unrelated =
            Name::from_ascii("unrelated.test.").unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            exact_soa_zone(&hostname, &[soa_record(&zone, 7)]),
            Some(zone.clone())
        );
        assert!(exact_soa_zone(&hostname, &[]).is_none());
        assert!(exact_soa_zone(&hostname, &[soa_record(&unrelated, 7)]).is_none());
        assert!(
            exact_soa_zone(&hostname, &[soa_record(&zone, 7), soa_record(&parent, 7)]).is_none()
        );

        let ns1 = Name::from_ascii("ns1.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let ns2 = Name::from_ascii("ns2.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let ns3 = Name::from_ascii("ns3.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let ns4 = Name::from_ascii("ns4.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let ns5 = Name::from_ascii("ns5.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let parent_ns = Name::from_ascii("ns1.test.").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            evidenced_nameservers(
                &zone,
                &[
                    ns_record(&zone, &ns5),
                    ns_record(&zone, &ns2),
                    ns_record(&zone, &ns1),
                    ns_record(&zone, &ns1),
                    ns_record(&zone, &ns4),
                    ns_record(&zone, &ns3),
                    ns_record(&parent, &parent_ns),
                ]
            ),
            vec![
                "ns1.example.test".to_owned(),
                "ns2.example.test".to_owned(),
                "ns3.example.test".to_owned(),
                "ns4.example.test".to_owned(),
            ]
        );

        let mut endpoints = std::collections::BTreeMap::new();
        for index in 1..=5_u8 {
            add_axfr_endpoints(
                &mut endpoints,
                &format!("ns{index}.example.test"),
                [
                    IpAddr::from([192, 0, index, 1]),
                    IpAddr::from([192, 0, index, 2]),
                    IpAddr::from([192, 0, index, 3]),
                ],
            );
        }
        assert_eq!(endpoints.len(), MAX_AXFR_ENDPOINTS);
        assert!((1..=5_u8).all(|index| {
            !endpoints.contains_key(&std::net::SocketAddr::new(
                IpAddr::from([192, 0, index, 3]),
                53,
            ))
        }));

        let limits = super::AxfrLimits::default();
        assert_eq!(limits.nameservers, MAX_AXFR_NAMESERVERS);
        assert_eq!(limits.ips_per_nameserver, MAX_AXFR_IPS_PER_NAMESERVER);
        assert_eq!(limits.endpoints, MAX_AXFR_ENDPOINTS);
    }

    #[tokio::test]
    async fn accepts_only_complete_soa_delimited_axfr_without_retaining_names() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let transferred_name = Name::from_ascii("private-owner.example.test.")
            .unwrap_or_else(|error| panic!("{error}"));
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![
                    Record::from_rdata(transferred_name, 60, RData::A(A::new(192, 0, 2, 9))),
                    soa_record(&zone, 7),
                ],
            )),
        ])
        .await;
        let attempt = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;

        assert_eq!(attempt.outcome, AxfrOutcome::Allowed);
        assert_eq!(attempt.messages, 2);
        assert_eq!(attempt.records, 3);
        let serialized = serde_json::to_string(&attempt)
            .unwrap_or_else(|error| panic!("could not serialize AXFR attempt: {error}"));
        assert!(!serialized.contains("private-owner"));

        let target = normalize_target("192.0.2.1").unwrap_or_else(|error| panic!("{error}"));
        let mut dns = explicit_ip_observation(
            &target,
            target.explicit_ip.unwrap_or_else(|| panic!("explicit IP")),
        );
        dns.authoritative_axfr = Some(AuthoritativeAxfrObservation {
            zone: "example.test".to_owned(),
            nameservers: vec!["ns1.example.test".to_owned()],
            attempts: vec![attempt],
            ..AuthoritativeAxfrObservation::default()
        });
        let findings = generate_findings(
            "example.test",
            Some(&dns),
            &[],
            &[],
            &[],
            &[],
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(dns.resolved_hosts.len(), 1);
        assert!(
            dns.resolved_hosts
                .iter()
                .all(|host| host.hostname.as_deref() != Some("private-owner.example.test"))
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.target == "example.test")
        );
    }

    #[tokio::test]
    async fn accepts_empty_or_repeated_question_after_first_axfr_message() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        for repeat_question in [false, true] {
            let second = axfr_message(ResponseCode::NoError, vec![soa_record(&zone, 7)]);
            let second = if repeat_question {
                MockReply::Message(second)
            } else {
                MockReply::CustomMessage(second)
            };
            let (endpoint, server) = mock_tcp_dns(vec![
                MockReply::Message(axfr_message(
                    ResponseCode::NoError,
                    vec![soa_record(&zone, 7)],
                )),
                second,
            ])
            .await;
            let attempt = check_axfr_endpoint(
                "ns1.example.test".to_owned(),
                endpoint,
                zone.clone(),
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
            let _ = server.await;

            assert_eq!(attempt.outcome, AxfrOutcome::Allowed);
            assert_eq!(attempt.messages, 2);
        }
    }

    #[tokio::test]
    async fn rejects_wrong_or_multiple_question_after_first_axfr_message() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let mut wrong = axfr_message(ResponseCode::NoError, vec![soa_record(&zone, 7)]);
        wrong.add_query(Query::query(zone.clone(), RecordType::A));
        let mut multiple = axfr_message(ResponseCode::NoError, vec![soa_record(&zone, 7)]);
        multiple.add_query(Query::query(zone.clone(), RecordType::AXFR));
        multiple.add_query(Query::query(zone.clone(), RecordType::AXFR));

        for second in [wrong, multiple] {
            let (endpoint, server) = mock_tcp_dns(vec![
                MockReply::Message(axfr_message(
                    ResponseCode::NoError,
                    vec![soa_record(&zone, 7)],
                )),
                MockReply::CustomMessage(second),
            ])
            .await;
            let attempt = check_axfr_endpoint(
                "ns1.example.test".to_owned(),
                endpoint,
                zone.clone(),
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
            let _ = server.await;

            assert_eq!(attempt.outcome, AxfrOutcome::Incomplete);
        }
    }

    #[tokio::test]
    async fn rejects_error_response_without_expected_axfr_question() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let response = axfr_message(ResponseCode::Refused, Vec::new());
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::CustomMessage(response),
        ])
        .await;
        let attempt = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;

        assert_eq!(attempt.outcome, AxfrOutcome::Incomplete);
        assert_eq!(
            attempt.error.as_deref(),
            Some("AXFR response did not contain an allowed AXFR question section")
        );
    }

    #[tokio::test]
    async fn accepts_complete_axfr_before_persistent_connection_closes() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Hold(AXFR_TRAILING_DRAIN_TIMEOUT * 50),
        ])
        .await;
        let attempt = tokio::time::timeout(
            AXFR_TRAILING_DRAIN_TIMEOUT * 20,
            check_axfr_endpoint(
                "ns1.example.test".to_owned(),
                endpoint,
                zone,
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("AXFR waited for persistent TCP EOF: {error}"));

        assert_eq!(attempt.outcome, AxfrOutcome::Allowed);
        assert!(!server.is_finished());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn rejects_records_after_closing_soa_in_the_same_message() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let trailing = Record::from_rdata(zone.clone(), 60, RData::A(A::new(192, 0, 2, 9)));
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7), trailing],
            )),
        ])
        .await;
        let attempt = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;

        assert_eq!(attempt.outcome, AxfrOutcome::Incomplete);
    }

    #[tokio::test]
    async fn rejects_messages_after_closing_soa() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(axfr_message(ResponseCode::NoError, Vec::new())),
        ])
        .await;
        let attempt = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;

        assert_eq!(attempt.outcome, AxfrOutcome::Incomplete);
    }

    #[tokio::test]
    async fn rejects_missing_or_wrong_axfr_question_and_wrong_opcode() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let wrong_zone =
            Name::from_ascii("wrong.example.test.").unwrap_or_else(|error| panic!("{error}"));
        let complete_message = || {
            axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7), soa_record(&zone, 7)],
            )
        };

        let missing_question = complete_message();
        let mut wrong_name = complete_message();
        wrong_name.add_query(Query::query(wrong_zone, RecordType::AXFR));
        let mut wrong_type = complete_message();
        wrong_type.add_query(Query::query(zone.clone(), RecordType::A));
        let mut wrong_class_query = Query::query(zone.clone(), RecordType::AXFR);
        wrong_class_query.set_query_class(DNSClass::CH);
        let mut wrong_class = complete_message();
        wrong_class.add_query(wrong_class_query);
        let mut wrong_opcode = complete_message();
        wrong_opcode.metadata.op_code = OpCode::Update;
        wrong_opcode.add_query(Query::query(zone.clone(), RecordType::AXFR));

        for response in [
            missing_question,
            wrong_name,
            wrong_type,
            wrong_class,
            wrong_opcode,
        ] {
            let (endpoint, server) = mock_tcp_dns(vec![MockReply::CustomMessage(response)]).await;
            let attempt = check_axfr_endpoint(
                "ns1.example.test".to_owned(),
                endpoint,
                zone.clone(),
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
            let _ = server.await;

            assert_eq!(attempt.outcome, AxfrOutcome::Incomplete);
        }
    }

    #[tokio::test]
    async fn preserves_refused_and_not_authoritative_responses() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        for (response_code, expected) in [
            (ResponseCode::Refused, AxfrOutcome::Refused),
            (ResponseCode::NotAuth, AxfrOutcome::NotAuthoritative),
        ] {
            let (endpoint, server) = mock_tcp_dns(vec![MockReply::Message(axfr_message(
                response_code,
                Vec::new(),
            ))])
            .await;
            let attempt = check_axfr_endpoint(
                "ns1.example.test".to_owned(),
                endpoint,
                zone.clone(),
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
            let _ = server.await;
            assert_eq!(attempt.outcome, expected);
            assert_eq!(attempt.response_code, Some(format!("{response_code:?}")));
            assert!(attempt.error.is_none());
        }
    }

    #[tokio::test]
    async fn rejects_incomplete_and_malformed_axfr_framing() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let (endpoint, server) = mock_tcp_dns(vec![MockReply::Message(axfr_message(
            ResponseCode::NoError,
            vec![soa_record(&zone, 7)],
        ))])
        .await;
        let incomplete = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(incomplete.outcome, AxfrOutcome::Incomplete);

        let wrong_zone = Name::from_ascii("other.test.").unwrap_or_else(|error| panic!("{error}"));
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&wrong_zone, 7)],
            )),
        ])
        .await;
        let mismatched = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(mismatched.outcome, AxfrOutcome::Incomplete);

        let mut non_authoritative_close =
            axfr_message(ResponseCode::NoError, vec![soa_record(&zone, 7)]);
        non_authoritative_close.metadata.authoritative = false;
        let (endpoint, server) = mock_tcp_dns(vec![
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![soa_record(&zone, 7)],
            )),
            MockReply::Message(non_authoritative_close),
        ])
        .await;
        let non_authoritative = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(non_authoritative.outcome, AxfrOutcome::Incomplete);

        let (endpoint, server) = mock_tcp_dns(vec![MockReply::Raw(vec![0, 1, 2])]).await;
        let malformed = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(malformed.outcome, AxfrOutcome::Incomplete);
    }

    #[tokio::test]
    async fn stops_at_byte_record_and_message_bounds() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let large_txt = TXT::new(vec!["x".repeat(255); 240]);
        let mut byte_replies = vec![MockReply::Message(axfr_message(
            ResponseCode::NoError,
            vec![soa_record(&zone, 7)],
        ))];
        byte_replies.extend((0..35).map(|_| {
            MockReply::Message(axfr_message(
                ResponseCode::NoError,
                vec![Record::from_rdata(
                    zone.clone(),
                    60,
                    RData::TXT(large_txt.clone()),
                )],
            ))
        }));
        let (endpoint, server) = mock_tcp_dns(byte_replies).await;
        let byte_bound = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(byte_bound.outcome, AxfrOutcome::LimitExceeded);
        assert!(byte_bound.bytes <= MAX_AXFR_BYTES);

        let mut record_replies = vec![MockReply::Message(axfr_message(
            ResponseCode::NoError,
            vec![soa_record(&zone, 7)],
        ))];
        for message_index in 0..16_u8 {
            let answers = (0_u8..=u8::MAX)
                .map(|record_index| {
                    Record::from_rdata(
                        zone.clone(),
                        60,
                        RData::A(A::new(192, 0, message_index, record_index)),
                    )
                })
                .collect();
            record_replies.push(MockReply::Message(axfr_message(
                ResponseCode::NoError,
                answers,
            )));
        }
        let (endpoint, server) = mock_tcp_dns(record_replies).await;
        let record_bound = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(
            record_bound.outcome,
            AxfrOutcome::LimitExceeded,
            "{record_bound:?}"
        );
        assert!(record_bound.records <= MAX_AXFR_RECORDS);

        let mut message_replies = vec![MockReply::Message(axfr_message(
            ResponseCode::NoError,
            vec![soa_record(&zone, 7)],
        ))];
        message_replies.extend(
            (0..MAX_AXFR_MESSAGES)
                .map(|_| MockReply::Message(axfr_message(ResponseCode::NoError, Vec::new()))),
        );
        let (endpoint, server) = mock_tcp_dns(message_replies).await;
        let message_bound = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        let _ = server.await;
        assert_eq!(message_bound.outcome, AxfrOutcome::LimitExceeded);
        assert_eq!(message_bound.messages, MAX_AXFR_MESSAGES);
    }

    #[tokio::test]
    async fn respects_endpoint_deadline_and_cancellation() {
        let zone = Name::from_ascii("example.test.").unwrap_or_else(|error| panic!("{error}"));
        let (endpoint, server) = mock_tcp_dns(vec![MockReply::Hold(Duration::from_secs(1))]).await;
        let timed_out = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_secs(1),
            Instant::now() + Duration::from_millis(30),
            &CancellationToken::new(),
        )
        .await;
        server.abort();
        assert_eq!(timed_out.outcome, AxfrOutcome::Timeout);

        let (endpoint, server) = mock_tcp_dns(vec![MockReply::Hold(Duration::from_secs(1))]).await;
        let request_timed_out = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone.clone(),
            Duration::from_millis(30),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        server.abort();
        assert_eq!(request_timed_out.outcome, AxfrOutcome::Timeout);

        let (endpoint, server) = mock_tcp_dns(vec![MockReply::Hold(Duration::from_secs(1))]).await;
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            cancel.cancel();
        });
        let cancelled = check_axfr_endpoint(
            "ns1.example.test".to_owned(),
            endpoint,
            zone,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &cancellation,
        )
        .await;
        server.abort();
        let _ = cancel_task.await;
        assert_eq!(cancelled.outcome, AxfrOutcome::Cancelled);
    }

    #[test]
    fn wildcard_probe_names_are_exactly_two_unpredictable_uuid_v4_children() {
        let names = wildcard_probe_names("example.test");
        assert_ne!(names[0], names[1]);
        for name in names {
            assert!(name.ends_with('.'));
            let label = name
                .trim_end_matches('.')
                .strip_suffix(".example.test")
                .expect("probe child suffix");
            let uuid = uuid::Uuid::parse_str(label).expect("UUID probe label");
            assert_eq!(uuid.get_version_num(), 4);
        }
    }

    #[tokio::test]
    async fn identical_local_a_and_cname_answers_detect_wildcard_without_name_leakage() {
        let (check, seen) = run_wildcard_fixture(
            MockWildcardReply::Identical,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(check.state, WildcardDnsCheckState::Completed);
        assert_eq!(check.observation.status, WildcardDnsStatus::Detected);
        assert_eq!(check.observation.probes_attempted, 2);
        assert_eq!(check.observation.answer_types.len(), 2);
        assert_eq!(check.observation.answer_fingerprints.len(), 2);
        assert!(check.observation.answer_fingerprints.is_sorted());
        assert!(
            check
                .observation
                .answer_fingerprints
                .iter()
                .map(String::len)
                .sum::<usize>()
                <= super::MAX_TXT_BYTES
        );
        assert!(!check.observation.probe_answers_scanned);
        assert_eq!(seen.len(), 4);
        let queried_names = seen.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(queried_names.len(), 2);
        assert!(queried_names.contains("probe-one.example.test"));
        assert!(queried_names.contains("probe-two.example.test"));

        let serialized =
            serde_json::to_string(&check.observation).unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{check:?}");
        for private_value in [
            "probe-one.example.test",
            "probe-two.example.test",
            "192.0.2.200",
            "wildcard.target.test",
        ] {
            assert!(!serialized.contains(private_value));
            assert!(!debug.contains(private_value));
        }
    }

    #[tokio::test]
    async fn unauthenticated_nxdomain_and_nodata_are_indeterminate() {
        for reply in [MockWildcardReply::NxDomain, MockWildcardReply::NoData] {
            let (check, seen) = run_wildcard_fixture(
                reply,
                Duration::from_millis(100),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;

            assert_eq!(check.state, WildcardDnsCheckState::Completed);
            assert_eq!(check.observation.status, WildcardDnsStatus::Indeterminate);
            assert_eq!(check.observation.probes_attempted, 2);
            assert!(check.observation.answer_types.is_empty());
            assert!(check.observation.answer_fingerprints.is_empty());
            assert_eq!(seen.len(), 4);
            assert_eq!(seen.into_iter().collect::<BTreeSet<_>>().len(), 2);
        }
    }

    #[test]
    fn wildcard_negative_answers_require_authenticated_authority_evidence() {
        for response_code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            for (proof, expected) in [
                (Proof::Secure, true),
                (Proof::Insecure, true),
                (Proof::Bogus, false),
                (Proof::Indeterminate, false),
            ] {
                for authority in [hickory_soa_record(proof), hickory_nsec_record(proof)] {
                    assert_eq!(
                        super::wildcard_negative_response(&hickory_negative_error(
                            response_code,
                            [authority]
                        )),
                        expected,
                        "unexpected {response_code} classification for {proof}"
                    );
                }
            }

            assert!(!super::wildcard_negative_response(&hickory_negative_error(
                response_code,
                []
            )));
            let zone = Name::from_ascii("example.test.")
                .unwrap_or_else(|error| panic!("invalid test name: {error}"));
            let nameserver = Name::from_ascii("ns1.example.test.")
                .unwrap_or_else(|error| panic!("invalid test name: {error}"));
            let mut non_denial_authority = ns_record(&zone, &nameserver);
            non_denial_authority.proof = Proof::Secure;
            assert!(!super::wildcard_negative_response(&hickory_negative_error(
                response_code,
                [non_denial_authority]
            )));
        }
    }

    #[test]
    fn wildcard_non_negative_failures_are_never_conclusive() {
        for error in [
            NetError::Timeout,
            NetError::NoConnections,
            NetError::from(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed DNS response",
            )),
            hickory_response_error(ResponseCode::ServFail),
        ] {
            assert!(!super::wildcard_negative_response(&error));
        }
    }

    #[tokio::test]
    async fn wildcard_probe_names_are_suppressed_from_dependency_logs() {
        let (resolver, _, task) = mock_wildcard_dns(MockWildcardReply::Identical).await;
        let names = [
            "private-probe-one.example.test".to_owned(),
            "private-probe-two.example.test".to_owned(),
        ];
        let captured = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&captured);
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .with_writer(move || CapturedWriter(Arc::clone(&writer)))
            .finish();

        let check = analyze_wildcard_dns_with_resolver(
            &resolver,
            &names,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
            true,
            false,
        )
        .with_subscriber(subscriber)
        .await;
        task.abort();

        assert_eq!(check.observation.status, WildcardDnsStatus::Detected);
        let logs = String::from_utf8(captured.lock().expect("captured log lock").clone())
            .expect("captured logs are UTF-8");
        for name in names {
            assert!(!logs.contains(&name));
        }
    }

    #[tokio::test]
    async fn rotating_local_answers_are_indeterminate() {
        let (check, _) = run_wildcard_fixture(
            MockWildcardReply::Rotating,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(check.state, WildcardDnsCheckState::Completed);
        assert_eq!(check.observation.status, WildcardDnsStatus::Indeterminate);
        assert_eq!(check.observation.probes_attempted, 2);
        assert!(
            check
                .observation
                .limitations
                .iter()
                .any(|limitation| limitation.contains("rotating"))
        );
    }

    #[tokio::test]
    async fn servfail_and_request_timeout_are_indeterminate() {
        for reply in [MockWildcardReply::ServFail, MockWildcardReply::Hold] {
            let (check, _) = run_wildcard_fixture(
                reply,
                Duration::from_millis(25),
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
            assert_eq!(check.state, WildcardDnsCheckState::Completed);
            assert_eq!(check.observation.status, WildcardDnsStatus::Indeterminate);
            assert_eq!(check.observation.probes_attempted, 2);
            assert!(!check.observation.errors.is_empty());
        }
    }

    #[tokio::test]
    async fn wildcard_detection_respects_cancellation_and_absolute_deadline() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (cancelled, _) = run_wildcard_fixture(
            MockWildcardReply::Hold,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &cancellation,
        )
        .await;
        assert_eq!(cancelled.state, WildcardDnsCheckState::Cancelled);
        assert_eq!(
            cancelled.observation.status,
            WildcardDnsStatus::Indeterminate
        );
        assert_eq!(cancelled.observation.probes_attempted, 0);

        let (timed_out, _) = run_wildcard_fixture(
            MockWildcardReply::Hold,
            Duration::from_secs(1),
            Instant::now() - Duration::from_millis(1),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(timed_out.state, WildcardDnsCheckState::TimedOut);
        assert_eq!(
            timed_out.observation.status,
            WildcardDnsStatus::Indeterminate
        );
        assert_eq!(timed_out.observation.probes_attempted, 0);
    }

    #[test]
    fn interprets_spf_and_dmarc_conservatively() {
        let records = vec![
            DnsRecord::Txt("v=spf1 include:_spf.example -all".to_owned()),
            DnsRecord::Mx {
                preference: 10,
                exchange: "mail.example".to_owned(),
            },
        ];
        let mail = interpret_mail(
            &records,
            &["v=DMARC1; p=none; sp=quarantine; pct=50; rua=mailto:d@example; adkim=s".to_owned()],
            vec!["v=STSv1; id=1".to_owned()],
            vec!["v=TLSRPTv1; rua=mailto:t@example".to_owned()],
        );
        assert!(mail.mx_present);
        assert_eq!(mail.spf.terminal_policy.as_deref(), Some("-all"));
        assert_eq!(mail.dmarc[0].policy.as_deref(), Some("none"));
        assert_eq!(mail.dmarc[0].percentage, Some(50));
    }

    #[test]
    fn caps_dmarc_aggregate_destinations() {
        let destinations = (0..20)
            .map(|index| format!("mailto:{index}@{}", "x".repeat(300)))
            .collect::<Vec<_>>()
            .join(",");
        let dmarc = parse_dmarc(&format!("v=DMARC1; p=none; rua={destinations}"));
        assert_eq!(dmarc.aggregate_reports.len(), MAX_DMARC_DESTINATIONS);
        assert!(
            dmarc
                .aggregate_reports
                .iter()
                .all(|destination| destination.chars().count() <= MAX_DMARC_DESTINATION_CHARS)
        );
    }

    #[test]
    fn orders_cname_edges_and_stops_on_cycles() {
        let edges = BTreeSet::from([
            CnameHop {
                from: "alias.example".to_owned(),
                to: "origin.example".to_owned(),
            },
            CnameHop {
                from: "origin.example".to_owned(),
                to: "example.com".to_owned(),
            },
            CnameHop {
                from: "example.com".to_owned(),
                to: "alias.example".to_owned(),
            },
        ]);
        let chain = ordered_cname_chain("example.com", edges);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].to, "alias.example");
        assert_eq!(chain[1].to, "origin.example");
        assert_eq!(chain[2].to, "example.com");

        let long_chain = (0..20)
            .map(|index| CnameHop {
                from: format!("name-{index}.example"),
                to: format!("name-{}.example", index + 1),
            })
            .collect();
        let bounded = ordered_cname_chain("name-0.example", long_chain);
        assert_eq!(bounded.len(), MAX_CNAME_CHAIN_HOPS);
        assert_eq!(
            bounded.last().map(|hop| hop.to.as_str()),
            Some("name-16.example")
        );
    }

    #[tokio::test]
    async fn dangling_destination_resolves_without_expanding_targets() {
        let (resolver, seen, task) = mock_wildcard_dns(MockWildcardReply::Identical).await;
        let observations = vec![dangling_cname_observation(&CnameHop {
            from: "alias.example.test".to_owned(),
            to: "destination.example.test".to_owned(),
        })];
        let check = analyze_dangling_cnames_with_resolver(
            &resolver,
            observations,
            &DANGLING_A,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        task.abort();

        assert_eq!(check.state, DanglingCnameCheckState::Completed);
        assert_eq!(check.observations[0].status, DanglingCnameStatus::Resolved);
        assert_eq!(
            seen.lock().expect("dangling query capture lock").as_slice(),
            ["destination.example.test"]
        );
        assert!(
            check.observations[0]
                .limitations
                .iter()
                .any(|limitation| limitation.contains("not scanned"))
        );
    }

    #[tokio::test]
    async fn dangling_targets_are_queried_once_after_case_normalization() {
        let (resolver, seen, task) = mock_wildcard_dns(MockWildcardReply::Identical).await;
        let observations = [
            CnameHop {
                from: "start.example.test".to_owned(),
                to: "Loop.Example.Test".to_owned(),
            },
            CnameHop {
                from: "Loop.Example.Test".to_owned(),
                to: "loop.example.test".to_owned(),
            },
            CnameHop {
                from: "other.example.test".to_owned(),
                to: "distinct.example.test".to_owned(),
            },
        ]
        .iter()
        .map(dangling_cname_observation)
        .collect();
        let check = analyze_dangling_cnames_with_resolver(
            &resolver,
            observations,
            &DANGLING_A_AND_AAAA,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        task.abort();

        assert_eq!(check.state, DanglingCnameCheckState::Completed);
        assert!(
            check
                .observations
                .iter()
                .all(|observation| observation.status == DanglingCnameStatus::Resolved),
            "observations: {:?}",
            check.observations
        );
        assert_eq!(
            check.observations[0].evidence,
            check.observations[1].evidence
        );
        assert_eq!(
            seen.lock().expect("dangling query capture lock").as_slice(),
            [
                "loop.example.test",
                "loop.example.test",
                "distinct.example.test",
                "distinct.example.test"
            ]
        );
    }

    #[test]
    fn dangling_negative_answers_are_classified_conservatively() {
        let nxdomain = hickory_negative_error(
            ResponseCode::NXDomain,
            [hickory_nsec_record(Proof::Insecure)],
        );
        let no_address =
            hickory_negative_error(ResponseCode::NoError, [hickory_soa_record(Proof::Secure)]);
        let unauthenticated = hickory_negative_error(
            ResponseCode::NXDomain,
            [hickory_nsec_record(Proof::Indeterminate)],
        );
        let bogus =
            hickory_negative_error(ResponseCode::NoError, [hickory_soa_record(Proof::Bogus)]);
        let servfail = hickory_response_error(ResponseCode::ServFail);

        assert_eq!(
            dangling_negative_outcome(&nxdomain),
            Some(DanglingQueryOutcome::NxDomain)
        );
        assert_eq!(
            dangling_negative_outcome(&no_address),
            Some(DanglingQueryOutcome::NoAddress)
        );
        assert_eq!(dangling_negative_outcome(&unauthenticated), None);
        assert_eq!(dangling_negative_outcome(&bogus), None);
        assert_eq!(dangling_negative_outcome(&servfail), None);
        assert_eq!(
            classify_dangling_outcomes(&[
                DanglingQueryOutcome::NxDomain,
                DanglingQueryOutcome::NxDomain,
            ]),
            DanglingCnameStatus::NxDomain
        );
        assert_eq!(
            classify_dangling_outcomes(&[
                DanglingQueryOutcome::NoAddress,
                DanglingQueryOutcome::NoAddress,
            ]),
            DanglingCnameStatus::NoAddress
        );
        assert_eq!(
            classify_dangling_outcomes(&[
                DanglingQueryOutcome::NxDomain,
                DanglingQueryOutcome::NoAddress,
            ]),
            DanglingCnameStatus::Indeterminate
        );
        assert_eq!(
            classify_dangling_outcomes(&[
                DanglingQueryOutcome::Address,
                DanglingQueryOutcome::Indeterminate,
            ]),
            DanglingCnameStatus::Resolved
        );
    }

    #[tokio::test]
    async fn dangling_timeout_deadline_and_cancellation_are_indeterminate() {
        let observation = || {
            vec![dangling_cname_observation(&CnameHop {
                from: "alias.example.test".to_owned(),
                to: "destination.example.test".to_owned(),
            })]
        };
        let (resolver, _, task) = mock_wildcard_dns(MockWildcardReply::Hold).await;
        let timed_out = analyze_dangling_cnames_with_resolver(
            &resolver,
            observation(),
            &DANGLING_A,
            Duration::from_millis(10),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        task.abort();
        assert_eq!(timed_out.state, DanglingCnameCheckState::Completed);
        assert_eq!(
            timed_out.observations[0].status,
            DanglingCnameStatus::Indeterminate
        );
        assert!(
            timed_out.observations[0]
                .errors
                .iter()
                .any(|error| error.contains("request timeout"))
        );

        let (resolver, _, task) = mock_wildcard_dns(MockWildcardReply::Hold).await;
        let deadline = analyze_dangling_cnames_with_resolver(
            &resolver,
            observation(),
            &DANGLING_A,
            Duration::from_secs(1),
            Instant::now(),
            &CancellationToken::new(),
        )
        .await;
        task.abort();
        assert_eq!(deadline.state, DanglingCnameCheckState::TimedOut);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (resolver, _, task) = mock_wildcard_dns(MockWildcardReply::Hold).await;
        let cancelled = analyze_dangling_cnames_with_resolver(
            &resolver,
            observation(),
            &DANGLING_A,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &cancellation,
        )
        .await;
        task.abort();
        assert_eq!(cancelled.state, DanglingCnameCheckState::Cancelled);
        assert_eq!(
            cancelled.observations[0].status,
            DanglingCnameStatus::Indeterminate
        );
    }

    #[test]
    fn aggregates_answer_proofs_conservatively() {
        assert_eq!(
            dnssec_status_from_proofs([Proof::Secure]),
            DnssecStatus::Secure
        );
        assert_eq!(
            dnssec_status_from_proofs([Proof::Secure, Proof::Insecure]),
            DnssecStatus::Insecure
        );
        assert_eq!(
            dnssec_status_from_proofs([Proof::Bogus]),
            DnssecStatus::Bogus
        );
    }

    #[test]
    fn maps_hickory_no_records_nsec_authority_proofs() {
        for (proof, expected) in [
            (Proof::Secure, DnssecStatus::Secure),
            (Proof::Insecure, DnssecStatus::Insecure),
            (Proof::Bogus, DnssecStatus::Bogus),
            (Proof::Indeterminate, DnssecStatus::Indeterminate),
        ] {
            let error = hickory_no_records_error([proof]);
            assert!(matches!(
                &error,
                NetError::Dns(DnsError::NoRecordsFound(no_records))
                    if no_records.authorities.as_deref().is_some_and(|records| records.len() == 1)
            ));
            assert_eq!(dnssec_status_from_lookup_error(&error), Some(expected));
        }
    }

    #[test]
    fn hickory_non_proof_errors_and_inconclusive_results_never_map_to_bogus() {
        let errors = [
            NetError::Timeout,
            NetError::NoConnections,
            NetError::from(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "offline transport failure",
            )),
            hickory_response_error(ResponseCode::ServFail),
            hickory_response_error(ResponseCode::NotImp),
            hickory_no_records_error([]),
            hickory_no_records_error([Proof::Indeterminate]),
        ];

        for error in errors {
            assert_ne!(
                dnssec_status_from_lookup_error(&error).unwrap_or(DnssecStatus::Indeterminate),
                DnssecStatus::Bogus,
                "unexpected bogus mapping for {error:?}"
            );
        }
    }

    // Hickory creates the non-exhaustive DnsError::Nsec variant inside its validating resolver,
    // so external offline tests cannot construct that path directly. This fixture exercises the
    // public NoRecordsFound path that preserves validated NSEC authority-record proofs.
    fn hickory_no_records_error(proofs: impl IntoIterator<Item = Proof>) -> NetError {
        hickory_negative_error(
            ResponseCode::NoError,
            proofs.into_iter().map(hickory_nsec_record),
        )
    }

    fn hickory_negative_error(
        response_code: ResponseCode,
        authorities: impl IntoIterator<Item = Record>,
    ) -> NetError {
        let name = Name::from_ascii("example.test.")
            .unwrap_or_else(|error| panic!("invalid test name: {error}"));
        let mut message = Message::response(1, OpCode::Query);
        message.metadata.response_code = response_code;
        message.add_query(Query::query(name, RecordType::A));
        message.insert_authorities(authorities.into_iter().collect());
        let response = DnsResponse::from_message(message)
            .unwrap_or_else(|error| panic!("invalid test response: {error}"));
        NetError::Dns(
            DnsError::from_response(response)
                .expect_err("empty Hickory response must produce NoRecordsFound"),
        )
    }

    fn hickory_soa_record(proof: Proof) -> Record {
        let zone = Name::from_ascii("example.test.")
            .unwrap_or_else(|error| panic!("invalid test name: {error}"));
        let mut record = soa_record(&zone, 1);
        record.proof = proof;
        record
    }

    fn hickory_nsec_record(proof: Proof) -> Record {
        let name = Name::from_ascii("example.test.")
            .unwrap_or_else(|error| panic!("invalid test name: {error}"));
        let mut record = Record::from_rdata(
            name,
            60,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_ascii("next.example.test.")
                    .unwrap_or_else(|error| panic!("invalid test name: {error}")),
                [RecordType::A],
            ))),
        );
        record.proof = proof;
        record
    }

    fn hickory_response_error(response_code: ResponseCode) -> NetError {
        let response =
            DnsResponse::from_message(Message::error_msg(1, OpCode::Query, response_code))
                .unwrap_or_else(|error| panic!("invalid test response: {error}"));
        NetError::Dns(
            DnsError::from_response(response)
                .expect_err("Hickory error response must produce DnsError"),
        )
    }

    #[test]
    fn old_dns_observations_default_new_dns_checks_to_absent() {
        let target = normalize_target("192.0.2.1").unwrap_or_else(|error| panic!("{error}"));
        let mut value = serde_json::to_value(explicit_ip_observation(
            &target,
            target.explicit_ip.expect("explicit IP"),
        ))
        .unwrap_or_else(|error| panic!("{error}"));
        let object = value.as_object_mut().expect("DNS observation object");
        object.remove("dnssec");
        object.remove("authoritative_axfr");
        object.remove("wildcard_dns");
        object.remove("dangling_cnames");

        let decoded: DnsObservation =
            serde_json::from_value(value).unwrap_or_else(|error| panic!("{error}"));
        assert!(decoded.dnssec.is_none());
        assert!(decoded.authoritative_axfr.is_none());
        assert!(decoded.wildcard_dns.is_none());
        assert!(decoded.dangling_cnames.is_empty());
    }

    #[test]
    fn detects_multiple_spf_records_without_inferring_dkim() {
        let records = vec![
            DnsRecord::Txt("v=spf1 ~all".to_owned()),
            DnsRecord::Txt("v=spf1 -all".to_owned()),
        ];
        let mail = interpret_mail(&records, &[], Vec::new(), Vec::new());
        assert_eq!(mail.spf.records.len(), 2);
        assert!(mail.dmarc.is_empty());
    }
}
