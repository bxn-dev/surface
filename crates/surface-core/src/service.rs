//! Safe, bounded service identification.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{HostObservation, PortState};

// Rust guideline compliant 2026-02-21

const MAX_BANNER_BYTES: usize = 1_024;
const MAX_SERVICE_ENDPOINTS: usize = 64;

/// Identified application protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
    /// Secure Shell.
    Ssh,
    /// Simple Mail Transfer Protocol.
    Smtp,
    /// File Transfer Protocol.
    Ftp,
    /// Internet Message Access Protocol.
    Imap,
    /// Post Office Protocol version 3.
    Pop3,
    /// Redis serialization protocol.
    Redis,
    /// MySQL-compatible server greeting.
    Mysql,
    /// PostgreSQL-compatible endpoint hint.
    Postgresql,
    /// Message Queuing Telemetry Transport endpoint hint.
    Mqtt,
    /// Generic TLS-wrapped service.
    Tls,
    /// No reliable protocol identification.
    Unknown,
}

/// Confidence in protocol identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionConfidence {
    /// Port hint or weak banner evidence.
    Low,
    /// Recognizable protocol response.
    Medium,
    /// Successful protocol-specific exchange.
    High,
}

/// Bounded service evidence for an open socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceObservation {
    /// Open socket address.
    pub address: SocketAddr,
    /// Identified protocol.
    pub service: ServiceKind,
    /// Detection confidence.
    pub confidence: DetectionConfidence,
    /// Sanitized, capped banner.
    pub banner: Option<String>,
    /// Small deterministic protocol metadata.
    pub protocol_details: BTreeMap<String, String>,
}

/// Probes open ports with bounded concurrency and safe payloads.
#[must_use]
pub async fn detect_services(
    hosts: &[HostObservation],
    hostname: Option<&str>,
    concurrency: usize,
    probe_timeout: Duration,
    cancellation: &CancellationToken,
) -> Vec<ServiceObservation> {
    let addresses = hosts
        .iter()
        .flat_map(|host| {
            host.ports
                .iter()
                .filter(|port| port.state == PortState::Open)
                .map(|port| port.address)
        })
        .take(MAX_SERVICE_ENDPOINTS);
    let host = hostname.unwrap_or("localhost").to_owned();
    let mut observations = stream::iter(addresses)
        .map(|address| probe(address, host.clone(), probe_timeout, cancellation.clone()))
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    observations.sort_by_key(|observation| observation.address);
    observations
}

async fn probe(
    address: SocketAddr,
    hostname: String,
    probe_timeout: Duration,
    cancellation: CancellationToken,
) -> Option<ServiceObservation> {
    tokio::select! {
        () = cancellation.cancelled() => None,
        result = timeout(probe_timeout, probe_inner(address, &hostname)) => {
            result.ok().flatten().or_else(|| Some(hint_observation(address)))
        },
    }
}

async fn probe_inner(address: SocketAddr, hostname: &str) -> Option<ServiceObservation> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    let mut buffer = [0_u8; MAX_BANNER_BYTES];
    let behavior = probe_behavior(address.port());
    let mut length = 0;
    match behavior {
        ProbeBehavior::Http => {
            let request = format!(
                "HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\nUser-Agent: Surface/0.1 (+authorized-security-assessment)\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await.ok()?;
        }
        ProbeBehavior::Request(payload) => stream.write_all(payload).await.ok()?,
        ProbeBehavior::SmtpEhlo => {
            length = stream.read(&mut buffer).await.ok()?;
            if length < MAX_BANNER_BYTES {
                let ehlo = format!("EHLO {hostname}\r\n");
                stream.write_all(ehlo.as_bytes()).await.ok()?;
                length += stream.read(&mut buffer[length..]).await.ok()?;
            }
        }
        ProbeBehavior::ReadOnly | ProbeBehavior::TlsOnly => {}
    }
    if !matches!(behavior, ProbeBehavior::SmtpEhlo) {
        length = stream.read(&mut buffer).await.ok()?;
    }
    let banner = sanitize_banner(&buffer[..length]);
    let (service, confidence) = classify_banner(&banner, address.port());
    let protocol_details = if service == ServiceKind::Smtp {
        smtp_details(&banner)
    } else {
        BTreeMap::new()
    };
    Some(ServiceObservation {
        address,
        service,
        confidence,
        banner: (!banner.is_empty()).then_some(banner),
        protocol_details,
    })
}

#[derive(Debug, Clone, Copy)]
enum ProbeBehavior {
    Http,
    Request(&'static [u8]),
    SmtpEhlo,
    ReadOnly,
    TlsOnly,
}

const fn probe_behavior(port: u16) -> ProbeBehavior {
    match port {
        25 | 587 => ProbeBehavior::SmtpEhlo,
        80 | 8000 | 8080 | 8888 => ProbeBehavior::Http,
        110 => ProbeBehavior::Request(b"CAPA\r\n"),
        143 => ProbeBehavior::Request(b"a001 CAPABILITY\r\n"),
        6379 => ProbeBehavior::Request(b"*1\r\n$4\r\nPING\r\n"),
        443 | 465 | 993 | 995 | 8443 => ProbeBehavior::TlsOnly,
        _ => ProbeBehavior::ReadOnly,
    }
}

fn smtp_details(banner: &str) -> BTreeMap<String, String> {
    let uppercase = banner.to_ascii_uppercase();
    let mut details = BTreeMap::new();
    for capability in ["STARTTLS", "AUTH", "SIZE"] {
        if uppercase.contains(capability) {
            details.insert(capability.to_ascii_lowercase(), "advertised".to_owned());
        }
    }
    details
}

fn hint_observation(address: SocketAddr) -> ServiceObservation {
    let service = match address.port() {
        21 => ServiceKind::Ftp,
        25 | 587 => ServiceKind::Smtp,
        80 | 8000 | 8080 | 8888 => ServiceKind::Http,
        110 => ServiceKind::Pop3,
        143 => ServiceKind::Imap,
        443 | 8443 => ServiceKind::Https,
        465 | 993 | 995 => ServiceKind::Tls,
        1883 | 8883 => ServiceKind::Mqtt,
        3306 => ServiceKind::Mysql,
        5432 => ServiceKind::Postgresql,
        6379 => ServiceKind::Redis,
        _ => ServiceKind::Unknown,
    };
    ServiceObservation {
        address,
        service,
        confidence: DetectionConfidence::Low,
        banner: None,
        protocol_details: BTreeMap::new(),
    }
}

fn classify_banner(banner: &str, port: u16) -> (ServiceKind, DetectionConfidence) {
    let uppercase = banner.to_ascii_uppercase();
    if banner.starts_with("SSH-") {
        (ServiceKind::Ssh, DetectionConfidence::High)
    } else if uppercase.starts_with("HTTP/") {
        (ServiceKind::Http, DetectionConfidence::High)
    } else if matches!(port, 25 | 587) && uppercase.starts_with("220 ") {
        (ServiceKind::Smtp, DetectionConfidence::High)
    } else if port == 21 && uppercase.starts_with("220 ") {
        (ServiceKind::Ftp, DetectionConfidence::High)
    } else if port == 110 && uppercase.contains("+OK") {
        (ServiceKind::Pop3, DetectionConfidence::High)
    } else if port == 143 && uppercase.contains("CAPABILITY") {
        (ServiceKind::Imap, DetectionConfidence::High)
    } else if port == 6379 && uppercase.contains("+PONG") {
        (ServiceKind::Redis, DetectionConfidence::High)
    } else if port == 3306 && !banner.is_empty() {
        (ServiceKind::Mysql, DetectionConfidence::Medium)
    } else if matches!(port, 25 | 587) {
        (ServiceKind::Smtp, DetectionConfidence::Low)
    } else if matches!(port, 443 | 8443) {
        (ServiceKind::Https, DetectionConfidence::Low)
    } else if matches!(port, 465 | 993 | 995) {
        (ServiceKind::Tls, DetectionConfidence::Low)
    } else {
        (ServiceKind::Unknown, DetectionConfidence::Low)
    }
}

/// Removes terminal controls and caps untrusted banners.
#[must_use]
pub fn sanitize_banner(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_BANNER_BYTES)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        DetectionConfidence, ProbeBehavior, ServiceKind, classify_banner, probe_behavior,
        sanitize_banner, smtp_details,
    };

    #[test]
    fn classifies_protocol_evidence_not_only_ports() {
        assert_eq!(
            classify_banner("SSH-2.0-OpenSSH", 1234),
            (ServiceKind::Ssh, DetectionConfidence::High)
        );
        assert_eq!(
            classify_banner("HTTP/1.1 200 OK", 1234).0,
            ServiceKind::Http
        );
        assert_eq!(classify_banner("220 host ESMTP", 25).0, ServiceKind::Smtp);
    }

    #[test]
    fn registers_only_bounded_read_only_probe_payloads() {
        assert!(matches!(probe_behavior(21), ProbeBehavior::ReadOnly));
        assert!(matches!(probe_behavior(25), ProbeBehavior::SmtpEhlo));
        assert!(matches!(
            probe_behavior(110),
            ProbeBehavior::Request(b"CAPA\r\n")
        ));
        assert!(matches!(
            probe_behavior(143),
            ProbeBehavior::Request(b"a001 CAPABILITY\r\n")
        ));
        assert!(matches!(
            probe_behavior(6379),
            ProbeBehavior::Request(b"*1\r\n$4\r\nPING\r\n")
        ));
        assert!(matches!(probe_behavior(993), ProbeBehavior::TlsOnly));
        assert_eq!(classify_banner("220 FTP ready", 21).0, ServiceKind::Ftp);
        assert_eq!(
            classify_banner("+OK capability list", 110).0,
            ServiceKind::Pop3
        );
        assert_eq!(
            classify_banner("* CAPABILITY IMAP4rev1", 143).0,
            ServiceKind::Imap
        );
        assert_eq!(classify_banner("+PONG", 6379).0, ServiceKind::Redis);
        assert_eq!(
            classify_banner("binary greeting", 3306).0,
            ServiceKind::Mysql
        );
        let details = smtp_details("220 mail ESMTP 250-STARTTLS 250-AUTH PLAIN 250 SIZE 1000");
        assert_eq!(
            details.get("starttls").map(String::as_str),
            Some("advertised")
        );
        assert_eq!(details.get("auth").map(String::as_str), Some("advertised"));
        assert_eq!(details.get("size").map(String::as_str), Some("advertised"));
    }

    #[test]
    fn sanitizes_terminal_controls_and_caps_banners() {
        let banner = sanitize_banner(&[b'O', b'K', 0x1b, b'[', b'3', b'1', b'm', 0]);
        assert!(!banner.contains('\u{1b}'));
        assert!(!banner.contains('\0'));
    }
}
