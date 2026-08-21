//! Bounded asynchronous TCP connect scanning.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

// Rust guideline compliant 2026-02-21

/// Conservative result of one TCP connect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    /// TCP connection completed.
    Open,
    /// Peer refused the TCP connection.
    Closed,
    /// Connection did not finish before its deadline.
    TimedOut,
    /// Operating system reported an unreachable route or host.
    Unreachable,
    /// Another connection error occurred.
    Error,
    /// Attempt was cancelled before completion.
    Cancelled,
}

/// One TCP connect observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortObservation {
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
    /// Sorted TCP observations.
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
            address,
            state: PortState::Cancelled,
            latency_ms: None,
            error: None,
        },
        result = timeout(connect_timeout, TcpStream::connect(address)) => {
            let latency_ms = u64::try_from(started.elapsed().as_millis()).ok();
            match result {
                Ok(Ok(_stream)) => PortObservation {
                    address,
                    state: PortState::Open,
                    latency_ms,
                    error: None,
                },
                Ok(Err(error)) => PortObservation {
                    address,
                    state: classify_error(error.kind()),
                    latency_ms,
                    error: Some(sanitize_error(&error.to_string())),
                },
                Err(_) => PortObservation {
                    address,
                    state: PortState::TimedOut,
                    latency_ms,
                    error: Some("connection timed out".to_owned()),
                },
            }
        }
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

    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::{PortState, scan_ports};

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
