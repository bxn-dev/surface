//! Passive DNS collection and mail-record interpretation.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::{NormalizedTarget, ScanError, ScanErrorKind, ScanStage};

// Rust guideline compliant 2026-02-21

const MAX_DMARC_DESTINATIONS: usize = 16;
const MAX_DMARC_DESTINATION_CHARS: usize = 256;
const MAX_DNS_RECORDS: usize = 512;
const MAX_RESOLVED_HOSTS: usize = 16;
const MAX_SPECIAL_TXT_RECORDS: usize = 32;
const MAX_TXT_BYTES: usize = 2_048;

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

/// Associates a primary hostname with a discovered address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Passive DNS results for the primary hostname.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsObservation {
    /// Primary queried hostname.
    pub queried_name: String,
    /// Raw normalized records from all supported queries.
    pub records: Vec<DnsRecord>,
    /// Deduplicated active-scan addresses for only the primary target.
    pub resolved_hosts: Vec<ResolvedHost>,
    /// Passive mail-domain interpretation.
    pub mail: MailObservation,
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
    analyze_dns_with_policy(target, query_timeout, ipv4_only, ipv6_only, true).await
}

pub(crate) async fn analyze_dns_with_policy(
    target: &NormalizedTarget,
    query_timeout: Duration,
    ipv4_only: bool,
    ipv6_only: bool,
    fetch_mta_sts_policy: bool,
) -> Result<DnsObservation, String> {
    if let Some(ip) = target.explicit_ip {
        return Ok(explicit_ip_observation(target, ip));
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

    records.sort_by_key(record_sort_key);
    let resolved_hosts = resolved_hosts(hostname, &records);
    let mut mail = interpret_mail(&records, &dmarc_records, mta_sts, tls_rpt);
    if fetch_mta_sts_policy && !mail.mta_sts.is_empty() {
        mail.mta_sts_policy_available = check_mta_sts_policy(hostname, query_timeout).await;
    }
    Ok(DnsObservation {
        queried_name: hostname.to_owned(),
        records,
        resolved_hosts,
        mail,
        errors,
    })
}

async fn lookup(
    resolver: &TokioResolver,
    name: &str,
    record_type: RecordType,
    query_timeout: Duration,
    records: &mut Vec<DnsRecord>,
    errors: &mut Vec<ScanError>,
) {
    match timeout(query_timeout, resolver.lookup(name, record_type)).await {
        Ok(Ok(result)) => records.extend(
            result
                .answers()
                .iter()
                .filter_map(|record| convert_record(&record.data)),
        ),
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

fn resolved_hosts(hostname: &str, records: &[DnsRecord]) -> Vec<ResolvedHost> {
    let mut addresses = BTreeSet::new();
    for record in records {
        match record {
            DnsRecord::A(ip) => {
                addresses.insert((IpAddr::V4(*ip), AddressSource::ARecord));
            }
            DnsRecord::Aaaa(ip) => {
                addresses.insert((IpAddr::V6(*ip), AddressSource::AaaaRecord));
            }
            _ => {}
        }
    }
    addresses
        .into_iter()
        .take(MAX_RESOLVED_HOSTS)
        .map(|(ip, source)| ResolvedHost {
            hostname: Some(hostname.to_owned()),
            ip,
            source,
        })
        .collect()
}

fn explicit_ip_observation(target: &NormalizedTarget, ip: IpAddr) -> DnsObservation {
    DnsObservation {
        queried_name: target.hostname.clone().unwrap_or_else(|| ip.to_string()),
        records: Vec::new(),
        resolved_hosts: vec![ResolvedHost {
            hostname: None,
            ip,
            source: AddressSource::Explicit,
        }],
        mail: interpret_mail(&[], &[], Vec::new(), Vec::new()),
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
    use super::{
        DnsRecord, MAX_DMARC_DESTINATION_CHARS, MAX_DMARC_DESTINATIONS, interpret_mail, parse_dmarc,
    };

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
