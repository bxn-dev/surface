//! Bounded asynchronous TCP and UDP port scanning.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

// Rust guideline compliant 2026-02-21

/// Network transport used for a port observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    /// Transmission Control Protocol.
    #[default]
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl TransportProtocol {
    /// Returns the lowercase protocol label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Conservative result of one port probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    /// TCP connection completed.
    Open,
    /// Peer refused the TCP connection.
    Closed,
    /// UDP probe received no response or rejection before its deadline.
    OpenFiltered,
    /// Connection did not finish before its deadline.
    TimedOut,
    /// Operating system reported an unreachable route or host.
    Unreachable,
    /// Another connection error occurred.
    Error,
    /// Attempt was cancelled before completion.
    Cancelled,
}

/// One bounded port observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortObservation {
    /// Scanned transport.
    #[serde(default)]
    pub transport: TransportProtocol,
    /// Attempted socket address.
    pub address: SocketAddr,
    /// Conservative observed state.
    pub state: PortState,
    /// Elapsed milliseconds when available.
    pub latency_ms: Option<u64>,
    /// Sanitized operating-system error.
    pub error: Option<String>,
}

/// All deterministic port observations for one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostObservation {
    /// Scanned IP address.
    pub ip: IpAddr,
    /// Sorted TCP and UDP observations.
    pub ports: Vec<PortObservation>,
}

/// Scans TCP ports with bounded in-flight connections.
#[must_use]
pub async fn scan_ports(
    addresses: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    connect_timeout: Duration,
    cancellation: &CancellationToken,
) -> Vec<HostObservation> {
    let attempts = addresses
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| SocketAddr::new(*ip, *port)));
    let mut observations = stream::iter(attempts)
        .map(|address| connect(address, connect_timeout, cancellation.clone()))
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;
    observations.sort_by_key(|observation| observation.address);

    group_by_host(addresses, &observations)
}

/// Scans UDP ports with bounded protocol-aware probes.
#[must_use]
pub async fn scan_udp_ports(
    addresses: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    probe_timeout: Duration,
    cancellation: &CancellationToken,
) -> Vec<HostObservation> {
    let attempts = addresses
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| SocketAddr::new(*ip, *port)));
    let mut observations = stream::iter(attempts)
        .map(|address| probe_udp(address, probe_timeout, cancellation.clone()))
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;
    observations.sort_by_key(|observation| observation.address);
    group_by_host(addresses, &observations)
}

fn group_by_host(addresses: &[IpAddr], observations: &[PortObservation]) -> Vec<HostObservation> {
    addresses
        .iter()
        .map(|ip| HostObservation {
            ip: *ip,
            ports: observations
                .iter()
                .filter(|observation| observation.address.ip() == *ip)
                .cloned()
                .collect(),
        })
        .collect()
}

async fn connect(
    address: SocketAddr,
    connect_timeout: Duration,
    cancellation: CancellationToken,
) -> PortObservation {
    let started = Instant::now();
    tokio::select! {
        () = cancellation.cancelled() => PortObservation {
            transport: TransportProtocol::Tcp,
            address,
            state: PortState::Cancelled,
            latency_ms: None,
            error: None,
        },
        result = timeout(connect_timeout, TcpStream::connect(address)) => {
            let latency_ms = u64::try_from(started.elapsed().as_millis()).ok();
            match result {
                Ok(Ok(_stream)) => PortObservation {
                    transport: TransportProtocol::Tcp,
                    address,
                    state: PortState::Open,
                    latency_ms,
                    error: None,
                },
                Ok(Err(error)) => PortObservation {
                    transport: TransportProtocol::Tcp,
                    address,
                    state: classify_error(error.kind()),
                    latency_ms,
                    error: Some(sanitize_error(&error.to_string())),
                },
                Err(_) => PortObservation {
                    transport: TransportProtocol::Tcp,
                    address,
                    state: PortState::TimedOut,
                    latency_ms,
                    error: Some("connection timed out".to_owned()),
                },
            }
        }
    }
}

async fn probe_udp(
    address: SocketAddr,
    probe_timeout: Duration,
    cancellation: CancellationToken,
) -> PortObservation {
    let started = Instant::now();
    let bind_address = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let result = async {
        let socket = UdpSocket::bind(bind_address).await?;
        socket.connect(address).await?;
        socket.send(udp_probe_payload(address.port())).await?;
        let mut response = [0_u8; 1_024];
        socket.recv(&mut response).await
    };
    tokio::select! {
        () = cancellation.cancelled() => PortObservation {
            transport: TransportProtocol::Udp,
            address,
            state: PortState::Cancelled,
            latency_ms: None,
            error: None,
        },
        result = timeout(probe_timeout, result) => {
            let latency_ms = u64::try_from(started.elapsed().as_millis()).ok();
            match result {
                Ok(Ok(_)) => PortObservation {
                    transport: TransportProtocol::Udp,
                    address,
                    state: PortState::Open,
                    latency_ms,
                    error: None,
                },
                Ok(Err(error)) => PortObservation {
                    transport: TransportProtocol::Udp,
                    address,
                    state: classify_error(error.kind()),
                    latency_ms,
                    error: Some(sanitize_error(&error.to_string())),
                },
                Err(_) => PortObservation {
                    transport: TransportProtocol::Udp,
                    address,
                    state: PortState::OpenFiltered,
                    latency_ms,
                    error: None,
                },
            }
        }
    }
}

const fn udp_probe_payload(port: u16) -> &'static [u8] {
    match port {
        53 => b"\x53\x55\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",
        123 => b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        3478 => b"\x00\x01\x00\x00\x21\x12\xa4\x42SURFACEPROBE",
        19132 | 19133 => b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00",
        27015 => b"\xff\xff\xff\xffTSource Engine Query\x00",
        _ => b"",
    }
}

fn classify_error(kind: ErrorKind) -> PortState {
    match kind {
        ErrorKind::ConnectionRefused => PortState::Closed,
        ErrorKind::TimedOut => PortState::TimedOut,
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => PortState::Unreachable,
        _ => PortState::Error,
    }
}

fn sanitize_error(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::net::{TcpListener, UdpSocket};
    use tokio_util::sync::CancellationToken;

    use super::{PortState, TransportProtocol, scan_ports, scan_udp_ports, udp_probe_payload};

    #[tokio::test]
    async fn detects_local_open_and_closed_ports_in_order() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let open_port = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"))
            .port();
        let closed_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let closed_port = closed_listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"))
            .port();
        drop(closed_listener);

        let hosts = scan_ports(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[closed_port, open_port],
            1,
            Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(hosts[0].ports.len(), 2);
        assert_eq!(
            hosts[0]
                .ports
                .iter()
                .find(|observation| observation.address.port() == open_port)
                .map(|observation| observation.state),
            Some(PortState::Open)
        );
        assert_eq!(hosts[0].ports[0].address.port(), open_port.min(closed_port));
    }

    #[test]
    fn udp_dns_probe_is_a_valid_root_ns_query() {
        let probe = udp_probe_payload(53);
        assert_eq!(probe.len(), 17);
        assert_eq!(&probe[4..6], &[0, 1]);
        assert_eq!(&probe[12..], &[0, 0, 2, 0, 1]);
    }

    #[tokio::test]
    async fn detects_responding_udp_port() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let port = socket
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"))
            .port();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            let (_, peer) = socket
                .recv_from(&mut buffer)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            socket
                .send_to(b"ok", peer)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        });

        let hosts = scan_udp_ports(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[port],
            1,
            Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        server.await.unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(hosts[0].ports[0].transport, TransportProtocol::Udp);
        assert_eq!(hosts[0].ports[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn cancellation_stops_connect_attempts() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let hosts = scan_ports(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[9],
            1,
            Duration::from_secs(1),
            &cancellation,
        )
        .await;
        assert_eq!(hosts[0].ports[0].state, PortState::Cancelled);
    }
}
