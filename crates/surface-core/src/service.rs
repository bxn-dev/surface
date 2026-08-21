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
    let known_http = matches!(address.port(), 80 | 8000 | 8080 | 8888);
    if known_http {
        let request = format!(
            "HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\nUser-Agent: Surface/0.1 (+authorized-security-assessment)\r\n\r\n"
        );
        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }
    }
    let length = stream.read(&mut buffer).await.ok()?;
    let banner = sanitize_banner(&buffer[..length]);
    let (service, confidence) = classify_banner(&banner, address.port());
    Some(ServiceObservation {
        address,
        service,
        confidence,
        banner: (!banner.is_empty()).then_some(banner),
        protocol_details: BTreeMap::new(),
    })
}

fn hint_observation(address: SocketAddr) -> ServiceObservation {
    let service = match address.port() {
        25 | 465 | 587 => ServiceKind::Smtp,
        80 | 8000 | 8080 | 8888 => ServiceKind::Http,
        443 | 8443 => ServiceKind::Https,
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
    } else if uppercase.starts_with("220 ") && uppercase.contains("SMTP") {
        (ServiceKind::Smtp, DetectionConfidence::High)
    } else if matches!(port, 25 | 465 | 587) {
        (ServiceKind::Smtp, DetectionConfidence::Low)
    } else if matches!(port, 443 | 8443) {
        (ServiceKind::Https, DetectionConfidence::Low)
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
    use super::{DetectionConfidence, ServiceKind, classify_banner, sanitize_banner};

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
    fn sanitizes_terminal_controls_and_caps_banners() {
        let banner = sanitize_banner(&[b'O', b'K', 0x1b, b'[', b'3', b'1', b'm', 0]);
        assert!(!banner.contains('\u{1b}'));
        assert!(!banner.contains('\0'));
    }
}
