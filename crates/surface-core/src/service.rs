//! Safe, bounded service identification.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{HostObservation, PortState, TransportProtocol};

// Rust guideline compliant 2026-02-21

const MAX_BANNER_BYTES: usize = 1_024;
const MAX_SERVICE_ENDPOINTS: usize = 256;

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
    /// Message submission over implicit TLS.
    Smtps,
    /// File Transfer Protocol.
    Ftp,
    /// Internet Message Access Protocol.
    Imap,
    /// Internet Message Access Protocol over implicit TLS.
    Imaps,
    /// Post Office Protocol version 3.
    Pop3,
    /// Post Office Protocol version 3 over implicit TLS.
    Pop3s,
    /// Domain Name System.
    Dns,
    /// Redis serialization protocol.
    Redis,
    /// `MySQL`-compatible server greeting.
    Mysql,
    /// `PostgreSQL`-compatible endpoint hint.
    Postgresql,
    /// Message Queuing Telemetry Transport endpoint hint.
    Mqtt,
    /// Microsoft SQL Server.
    Mssql,
    /// Oracle database listener.
    Oracle,
    /// `MongoDB` database.
    Mongodb,
    /// `Memcached` cache server.
    Memcached,
    /// `Elasticsearch` HTTP API.
    Elasticsearch,
    /// `RabbitMQ` message broker.
    Rabbitmq,
    /// Apache Kafka broker.
    Kafka,
    /// Apache Cassandra native protocol.
    Cassandra,
    /// `ClickHouse` database.
    Clickhouse,
    /// `Neo4j` Bolt protocol.
    Neo4j,
    /// Server Message Block.
    Smb,
    /// Network File System.
    Nfs,
    /// Remote Desktop Protocol.
    Rdp,
    /// Virtual Network Computing.
    Vnc,
    /// `Docker` remote API.
    Docker,
    /// `Kubernetes` API.
    Kubernetes,
    /// `Prometheus` metrics service.
    Prometheus,
    /// `Grafana` web service.
    Grafana,
    /// `WireGuard`-compatible UDP endpoint hint.
    Wireguard,
    /// Session Traversal Utilities for NAT or TURN.
    StunTurn,
    /// `NetBird` self-hosted endpoint hint.
    Netbird,
    /// `Minecraft` Java Edition server.
    MinecraftJava,
    /// `Minecraft` Bedrock Edition server.
    MinecraftBedrock,
    /// `Terraria` server.
    Terraria,
    /// `Valheim` server.
    Valheim,
    /// `Factorio` server.
    Factorio,
    /// Source Engine query endpoint.
    SourceEngine,
    /// Generic TLS-wrapped service.
    Tls,
    /// No reliable protocol identification.
    Unknown,
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Smtps => "SMTPS",
            Self::Imaps => "IMAPS",
            Self::Pop3s => "POP3S",
            Self::Dns => "DNS",
            Self::Mssql => "MSSQL",
            Self::Smb => "SMB",
            Self::Nfs => "NFS",
            Self::Rdp => "RDP",
            Self::Vnc => "VNC",
            Self::StunTurn => "STUN/TURN",
            Self::SourceEngine => "Source Engine",
            other => return write!(formatter, "{other:?}"),
        };
        formatter.write_str(name)
    }
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

/// SSH identification observed before key exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshIdentification {
    /// SSH protocol version from the server identification line.
    pub protocol: String,
    /// Sanitized server software identification.
    pub software: String,
}

/// Complete client-first SSH algorithm selections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshAlgorithmSelections {
    /// Key-exchange algorithm.
    pub kex: String,
    /// Server host-key algorithm.
    pub host_key: String,
    /// Client-to-server cipher.
    pub cipher_c2s: String,
    /// Server-to-client cipher.
    pub cipher_s2c: String,
    /// Client-to-server message authentication code.
    pub mac_c2s: String,
    /// Server-to-client message authentication code.
    pub mac_s2c: String,
}

/// Available client-first selections from an incomplete SSH analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSshAlgorithmSelections {
    /// Key-exchange algorithm, when selected.
    pub kex: Option<String>,
    /// Server host-key algorithm, when selected.
    pub host_key: Option<String>,
    /// Client-to-server cipher, when selected.
    pub cipher_c2s: Option<String>,
    /// Server-to-client cipher, when selected.
    pub cipher_s2c: Option<String>,
    /// Client-to-server message authentication code, when selected.
    pub mac_c2s: Option<String>,
    /// Server-to-client message authentication code, when selected.
    pub mac_s2c: Option<String>,
}

/// Outcome of bounded SSH posture analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SshPostureOutcome {
    /// Every required algorithm selection was inferred.
    Complete {
        /// Complete inferred selections.
        selections: SshAlgorithmSelections,
    },
    /// Some selections were inferred before analysis became incomplete.
    Partial {
        /// Selections available before analysis stopped.
        selections: PartialSshAlgorithmSelections,
        /// Stable explanation of the incomplete analysis.
        reason: String,
    },
    /// No algorithm selection could be inferred.
    Indeterminate {
        /// Stable explanation of the unavailable analysis.
        reason: String,
    },
}

/// Typed SSH protocol evidence for one endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshPosture {
    /// Server identification, when available.
    pub identification: Option<SshIdentification>,
    /// Analysis outcome and inferred selections.
    pub outcome: SshPostureOutcome,
}

/// Bounded service evidence for an open socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceObservation {
    /// Observed network transport.
    #[serde(default)]
    pub transport: TransportProtocol,
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
    /// Typed SSH posture for SSH services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshPosture>,
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
    let tcp_addresses = hosts
        .iter()
        .flat_map(|host| {
            host.ports
                .iter()
                .filter(|port| {
                    port.transport == TransportProtocol::Tcp && port.state == PortState::Open
                })
                .map(|port| port.address)
        })
        .collect::<Vec<_>>();
    let host = hostname.unwrap_or("localhost").to_owned();
    let mut observations = stream::iter(tcp_addresses.iter().copied().take(MAX_SERVICE_ENDPOINTS))
        .map(|address| probe(address, host.clone(), probe_timeout, cancellation.clone()))
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    observations.extend(
        tcp_addresses
            .iter()
            .copied()
            .skip(MAX_SERVICE_ENDPOINTS)
            .filter_map(|address| {
                let observation = hint_observation(address);
                (observation.service != ServiceKind::Unknown).then_some(observation)
            }),
    );
    observations.extend(hosts.iter().flat_map(|host| {
        host.ports.iter().filter_map(|port| {
            if port.transport != TransportProtocol::Udp
                || !matches!(port.state, PortState::Open | PortState::OpenFiltered)
            {
                return None;
            }
            let service = hinted_service(TransportProtocol::Udp, port.address.port());
            (port.state == PortState::Open || service != ServiceKind::Unknown).then_some(
                ServiceObservation {
                    transport: TransportProtocol::Udp,
                    address: port.address,
                    service,
                    confidence: if port.state == PortState::Open && service != ServiceKind::Unknown
                    {
                        DetectionConfidence::Medium
                    } else {
                        DetectionConfidence::Low
                    },
                    banner: None,
                    protocol_details: BTreeMap::new(),
                    ssh: None,
                },
            )
        })
    }));
    observations.sort_by_key(|observation| (observation.address, observation.transport));
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
        transport: TransportProtocol::Tcp,
        address,
        service,
        confidence,
        banner: (!banner.is_empty()).then_some(banner),
        protocol_details,
        ssh: None,
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
    let service = hinted_service(TransportProtocol::Tcp, address.port());
    ServiceObservation {
        transport: TransportProtocol::Tcp,
        address,
        service,
        confidence: DetectionConfidence::Low,
        banner: None,
        protocol_details: BTreeMap::new(),
        ssh: None,
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
    } else {
        (
            hinted_service(TransportProtocol::Tcp, port),
            DetectionConfidence::Low,
        )
    }
}

// Curated from the IANA Service Name and Transport Protocol Port Number Registry,
// the Wikipedia TCP/UDP port list retrieved 2026-08-23, and official vendor
// documentation for NetBird, WireGuard, and game servers. These are unverified
// hints only; protocol responses determine medium or high confidence.
const fn hinted_service(transport: TransportProtocol, port: u16) -> ServiceKind {
    match (transport, port) {
        (TransportProtocol::Tcp, 21) => ServiceKind::Ftp,
        (TransportProtocol::Tcp, 25 | 587) => ServiceKind::Smtp,
        (TransportProtocol::Tcp | TransportProtocol::Udp, 53) => ServiceKind::Dns,
        (TransportProtocol::Tcp, 80 | 8000 | 8080 | 8888) => ServiceKind::Http,
        (TransportProtocol::Tcp, 110) => ServiceKind::Pop3,
        (TransportProtocol::Tcp, 143) => ServiceKind::Imap,
        (TransportProtocol::Tcp, 443 | 8443) => ServiceKind::Https,
        (TransportProtocol::Tcp, 445) => ServiceKind::Smb,
        (TransportProtocol::Tcp, 465) => ServiceKind::Smtps,
        (TransportProtocol::Tcp, 993) => ServiceKind::Imaps,
        (TransportProtocol::Tcp, 995) => ServiceKind::Pop3s,
        (TransportProtocol::Tcp, 1433) => ServiceKind::Mssql,
        (TransportProtocol::Tcp, 1521 | 2483 | 2484) => ServiceKind::Oracle,
        (TransportProtocol::Tcp, 1883 | 8883) => ServiceKind::Mqtt,
        (TransportProtocol::Tcp | TransportProtocol::Udp, 2049) => ServiceKind::Nfs,
        (TransportProtocol::Tcp, 2375 | 2376) => ServiceKind::Docker,
        (TransportProtocol::Tcp, 3306 | 33060) => ServiceKind::Mysql,
        (TransportProtocol::Tcp | TransportProtocol::Udp, 3389) => ServiceKind::Rdp,
        (TransportProtocol::Tcp, 5432) => ServiceKind::Postgresql,
        (TransportProtocol::Tcp, 5671 | 5672 | 15671 | 15672) => ServiceKind::Rabbitmq,
        (TransportProtocol::Tcp, 5900) => ServiceKind::Vnc,
        (TransportProtocol::Tcp, 6379) => ServiceKind::Redis,
        (TransportProtocol::Tcp, 6443) => ServiceKind::Kubernetes,
        (TransportProtocol::Tcp, 7474 | 7687) => ServiceKind::Neo4j,
        (TransportProtocol::Tcp | TransportProtocol::Udp, 7777) => ServiceKind::Terraria,
        (TransportProtocol::Tcp, 8123 | 9000) => ServiceKind::Clickhouse,
        (TransportProtocol::Tcp, 9090 | 9100) => ServiceKind::Prometheus,
        (TransportProtocol::Tcp, 9092) => ServiceKind::Kafka,
        (TransportProtocol::Tcp, 9042) => ServiceKind::Cassandra,
        (TransportProtocol::Tcp, 9200 | 9300) => ServiceKind::Elasticsearch,
        (TransportProtocol::Tcp | TransportProtocol::Udp, 11211) => ServiceKind::Memcached,
        (TransportProtocol::Tcp | TransportProtocol::Udp, 19132 | 19133) => {
            ServiceKind::MinecraftBedrock
        }
        (TransportProtocol::Udp, 2456..=2458) => ServiceKind::Valheim,
        (TransportProtocol::Tcp, 25565) => ServiceKind::MinecraftJava,
        (TransportProtocol::Udp, 27015) => ServiceKind::SourceEngine,
        (TransportProtocol::Tcp, 27017) => ServiceKind::Mongodb,
        (TransportProtocol::Udp, 34197) => ServiceKind::Factorio,
        (TransportProtocol::Udp, 3478) => ServiceKind::StunTurn,
        (TransportProtocol::Tcp, 3000) => ServiceKind::Grafana,
        (TransportProtocol::Tcp, 33073 | 33080) => ServiceKind::Netbird,
        (TransportProtocol::Udp, 51820) => ServiceKind::Wireguard,
        _ => ServiceKind::Unknown,
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
        DetectionConfidence, PartialSshAlgorithmSelections, ProbeBehavior, ServiceKind,
        SshAlgorithmSelections, SshIdentification, SshPosture, SshPostureOutcome, classify_banner,
        hinted_service, probe_behavior, sanitize_banner, smtp_details,
    };

    #[test]
    fn ssh_posture_round_trips_complete_partial_and_indeterminate_outcomes() {
        let identification = SshIdentification {
            protocol: "2.0".to_owned(),
            software: "OpenSSH_9.9".to_owned(),
        };
        let postures = [
            SshPosture {
                identification: Some(identification.clone()),
                outcome: SshPostureOutcome::Complete {
                    selections: SshAlgorithmSelections {
                        kex: "curve25519-sha256".to_owned(),
                        host_key: "ssh-ed25519".to_owned(),
                        cipher_c2s: "aes256-ctr".to_owned(),
                        cipher_s2c: "aes256-ctr".to_owned(),
                        mac_c2s: "hmac-sha2-512".to_owned(),
                        mac_s2c: "hmac-sha2-512".to_owned(),
                    },
                },
            },
            SshPosture {
                identification: Some(identification),
                outcome: SshPostureOutcome::Partial {
                    selections: PartialSshAlgorithmSelections {
                        kex: Some("curve25519-sha256".to_owned()),
                        ..PartialSshAlgorithmSelections::default()
                    },
                    reason: "no common required algorithm: host_key".to_owned(),
                },
            },
            SshPosture {
                identification: None,
                outcome: SshPostureOutcome::Indeterminate {
                    reason: "identification timed out".to_owned(),
                },
            },
        ];

        for expected in postures {
            let encoded = serde_json::to_string(&expected).expect("posture serializes");
            let actual: SshPosture = serde_json::from_str(&encoded).expect("posture deserializes");
            assert_eq!(actual, expected);
        }
    }

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
        assert_eq!(
            hinted_service(crate::TransportProtocol::Tcp, 465),
            ServiceKind::Smtps
        );
        assert_eq!(ServiceKind::Smtps.to_string(), "SMTPS");
        assert_eq!(
            hinted_service(crate::TransportProtocol::Tcp, 993),
            ServiceKind::Imaps
        );
        assert_eq!(
            hinted_service(crate::TransportProtocol::Udp, 51820),
            ServiceKind::Wireguard
        );
        assert_eq!(
            hinted_service(crate::TransportProtocol::Udp, 19132),
            ServiceKind::MinecraftBedrock
        );
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
