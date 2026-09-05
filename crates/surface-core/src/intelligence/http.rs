//! Bounded, destination-pinned HTTP reads for intelligence sources.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use reqwest::{Client, Url};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

// Rust guideline compliant 2026-02-21

/// Maximum unique addresses accepted from one DNS answer.
///
/// This bounds connection attempts and rejects unexpectedly large resolver answers.
const MAX_DNS_ADDRESSES: usize = 8;

type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, ()>> + Send + 'a>>;

trait HostResolver: Send + Sync {
    fn resolve<'a>(&'a self, hostname: &'a str) -> ResolveFuture<'a>;
}

#[derive(Debug)]
struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve<'a>(&'a self, hostname: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            tokio::net::lookup_host((hostname, 0))
                .await
                .map(Iterator::collect)
                .map_err(|_| ())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchError {
    Cancelled,
    Deadline,
    Timeout,
    Resolution,
    Destination,
    Request,
    Http(u16),
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientPolicy {
    PublicHttpsPinnedDnsNoProxyNoRedirect,
    #[cfg(test)]
    FixtureHttpPinnedDnsNoProxyNoRedirect,
}

pub(crate) struct PinnedClients {
    request_timeout: Duration,
    clients: BTreeMap<String, Client>,
    resolver: Arc<dyn HostResolver>,
    policy: ClientPolicy,
}

impl PinnedClients {
    pub(crate) fn new(request_timeout: Duration) -> Self {
        Self {
            request_timeout,
            clients: BTreeMap::new(),
            resolver: Arc::new(SystemResolver),
            policy: ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect,
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        request_timeout: Duration,
        answers: BTreeMap<String, Vec<SocketAddr>>,
    ) -> Self {
        Self::fixture_with_delay(request_timeout, answers, Duration::ZERO, false).0
    }

    #[cfg(test)]
    fn strict_fixture(
        request_timeout: Duration,
        answers: BTreeMap<String, Vec<SocketAddr>>,
        delay: Duration,
    ) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        Self::fixture_with_delay(request_timeout, answers, delay, true)
    }

    #[cfg(test)]
    fn fixture_with_delay(
        request_timeout: Duration,
        answers: BTreeMap<String, Vec<SocketAddr>>,
        delay: Duration,
        strict: bool,
    ) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Self {
                request_timeout,
                clients: BTreeMap::new(),
                resolver: Arc::new(FixtureResolver {
                    answers: Arc::new(answers),
                    delay,
                    calls: calls.clone(),
                }),
                policy: if strict {
                    ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect
                } else {
                    ClientPolicy::FixtureHttpPinnedDnsNoProxyNoRedirect
                },
            },
            calls,
        )
    }

    #[cfg(test)]
    pub(crate) const fn policy(&self) -> ClientPolicy {
        self.policy
    }

    pub(crate) async fn client_for(
        &mut self,
        url: &Url,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Client, FetchError> {
        let hostname = url.host_str().ok_or(FetchError::Request)?.to_owned();
        if let Some(client) = self.clients.get(&hostname) {
            return Ok(client.clone());
        }

        let resolution = self.resolver.resolve(&hostname);
        let addresses = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(FetchError::Cancelled),
            result = timeout_at(deadline, timeout(self.request_timeout, resolution)) => match result {
                Err(_) => return Err(FetchError::Deadline),
                Ok(Err(_)) => return Err(FetchError::Timeout),
                Ok(Ok(Err(()))) => return Err(FetchError::Resolution),
                Ok(Ok(Ok(addresses))) => addresses,
            },
        };
        let addresses = validated_destinations(addresses, self.policy)?;
        let client = build_client(&hostname, &addresses, self.request_timeout, self.policy)?;
        self.clients.insert(hostname, client.clone());
        Ok(client)
    }
}

fn validated_destinations(
    addresses: Vec<SocketAddr>,
    policy: ClientPolicy,
) -> Result<Vec<SocketAddr>, FetchError> {
    let addresses = addresses
        .into_iter()
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() || addresses.len() > MAX_DNS_ADDRESSES {
        return Err(FetchError::Resolution);
    }
    if matches!(policy, ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect)
        && addresses
            .iter()
            .any(|address| !is_public_destination(*address))
    {
        return Err(FetchError::Destination);
    }
    Ok(addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, 0))
        .collect())
}

fn build_client(
    hostname: &str,
    addresses: &[SocketAddr],
    request_timeout: Duration,
    policy: ClientPolicy,
) -> Result<Client, FetchError> {
    let builder = Client::builder()
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(concat!("surface/", env!("CARGO_PKG_VERSION")))
        .resolve_to_addrs(hostname, addresses);
    let builder = match policy {
        ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect => builder.https_only(true),
        #[cfg(test)]
        ClientPolicy::FixtureHttpPinnedDnsNoProxyNoRedirect => builder,
    };
    builder.build().map_err(|_| FetchError::Request)
}

pub(crate) fn is_public_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => ipv4_is_public(address),
        IpAddr::V6(address) => {
            address.to_ipv4_mapped().is_none() && !ipv6_is_nat64(address) && ipv6_is_public(address)
        }
    }
}

fn ipv4_is_public(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    // Conservative IANA special-purpose exclusions. Each range is explicit because changes
    // affect which resolver answers may become direct connection destinations.
    ![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 31, 196, 0], 24),
        ([192, 52, 193, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([192, 175, 48, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
    .into_iter()
    .any(|(network, length)| contains_v4(value, u32::from_be_bytes(network), length))
}

fn contains_v4(address: u32, network: u32, length: u8) -> bool {
    let mask = u32::MAX << (32 - length);
    address & mask == network & mask
}

fn ipv6_is_public(address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    // Current external unicast space is 2000::/3. Explicit exceptions remove documentation,
    // transition, benchmark, protocol, and special anycast allocations.
    value >> 125 == 1
        && ![
            (u128::from(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0)), 23),
            (
                u128::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
                32,
            ),
            (u128::from(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0)), 16),
            (
                u128::from(Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0)),
                48,
            ),
            (u128::from(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0)), 20),
        ]
        .into_iter()
        .any(|(network, length)| contains_v6(value, network, length))
}

fn ipv6_is_nat64(address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    contains_v6(
        value,
        u128::from(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0)),
        96,
    ) || contains_v6(
        value,
        u128::from(Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0)),
        48,
    )
}

fn contains_v6(address: u128, network: u128, length: u8) -> bool {
    let mask = u128::MAX << (128 - length);
    address & mask == network & mask
}

pub(crate) async fn get_bounded(
    client: &Client,
    url: Url,
    maximum_bytes: usize,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, FetchError> {
    get_bounded_with_bearer(
        client,
        url,
        maximum_bytes,
        request_timeout,
        deadline,
        cancellation,
        None,
    )
    .await
}

pub(crate) async fn get_bounded_with_bearer(
    client: &Client,
    url: Url,
    maximum_bytes: usize,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
    bearer: Option<&str>,
) -> Result<Vec<u8>, FetchError> {
    let fetch = async {
        let mut request = client.get(url);
        if let Some(bearer) = bearer.filter(|value| !value.trim().is_empty()) {
            request = request.bearer_auth(bearer);
        }
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                FetchError::Timeout
            } else {
                FetchError::Request
            }
        })?;
        if !response.status().is_success() {
            return Err(FetchError::Http(response.status().as_u16()));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                if error.is_timeout() {
                    FetchError::Timeout
                } else {
                    FetchError::Request
                }
            })?;
            if body.len().saturating_add(chunk.len()) > maximum_bytes {
                return Err(FetchError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };

    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(FetchError::Cancelled),
        result = timeout_at(deadline, timeout(request_timeout, fetch)) => match result {
            Err(_) => Err(FetchError::Deadline),
            Ok(Err(_)) => Err(FetchError::Timeout),
            Ok(Ok(result)) => result,
        },
    }
}

#[cfg(test)]
#[derive(Debug)]
struct FixtureResolver {
    answers: Arc<BTreeMap<String, Vec<SocketAddr>>>,
    delay: Duration,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl HostResolver for FixtureResolver {
    fn resolve<'a>(&'a self, hostname: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(self.delay).await;
            self.answers.get(hostname).cloned().ok_or(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
        sync::atomic::Ordering,
        time::Duration,
    };

    use reqwest::Url;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::Instant,
    };
    use tokio_util::sync::CancellationToken;

    use super::{FetchError, PinnedClients, get_bounded, ipv6_is_nat64, validated_destinations};

    fn answer(hostname: &str, addresses: Vec<SocketAddr>) -> BTreeMap<String, Vec<SocketAddr>> {
        BTreeMap::from([(hostname.to_owned(), addresses)])
    }

    fn socket(address: &str) -> SocketAddr {
        SocketAddr::new(
            IpAddr::from_str(address).unwrap_or_else(|error| panic!("{error}")),
            443,
        )
    }

    #[test]
    fn destination_policy_rejects_non_public_and_suspicious_answers() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "64:ff9b:1::808:808",
        ] {
            assert_eq!(
                validated_destinations(
                    vec![socket(address)],
                    super::ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect,
                ),
                Err(FetchError::Destination),
                "{address}"
            );
        }
        assert_eq!(
            validated_destinations(
                vec![socket("8.8.8.8"), socket("127.0.0.1")],
                super::ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect,
            ),
            Err(FetchError::Destination)
        );
        assert_eq!(
            validated_destinations(
                Vec::new(),
                super::ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect,
            ),
            Err(FetchError::Resolution)
        );
        assert_eq!(
            validated_destinations(
                (1..=9)
                    .map(|last| socket(&format!("8.8.8.{last}")))
                    .collect(),
                super::ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect,
            ),
            Err(FetchError::Resolution)
        );
    }

    #[test]
    fn destinations_are_sorted_deduplicated_and_port_neutral() {
        let addresses = validated_destinations(
            vec![socket("9.9.9.9"), socket("8.8.8.8"), socket("9.9.9.9")],
            super::ClientPolicy::PublicHttpsPinnedDnsNoProxyNoRedirect,
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(
            addresses,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 0),
            ]
        );
    }

    #[test]
    fn nat64_prefix_boundaries_are_exact() {
        for address in [
            "64:ff9b::",
            "64:ff9b::ffff:ffff",
            "64:ff9b:1::",
            "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(ipv6_is_nat64(address.parse().unwrap()));
        }
        for address in [
            "64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff",
            "64:ff9b:0:0:0:1::",
            "64:ff9b:0:ffff:ffff:ffff:ffff:ffff",
            "64:ff9b:2::",
        ] {
            assert!(!ipv6_is_nat64(address.parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn resolution_obeys_timeout_deadline_and_cancellation() {
        let url =
            Url::parse("https://rdap.test/ip/8.8.8.8").unwrap_or_else(|error| panic!("{error}"));
        let public = answer("rdap.test", vec![socket("8.8.8.8")]);

        let (mut timeout_clients, _) = PinnedClients::strict_fixture(
            Duration::from_millis(5),
            public.clone(),
            Duration::from_millis(50),
        );
        assert!(matches!(
            timeout_clients
                .client_for(
                    &url,
                    Instant::now() + Duration::from_secs(1),
                    &CancellationToken::new()
                )
                .await,
            Err(FetchError::Timeout)
        ));

        let (mut deadline_clients, _) = PinnedClients::strict_fixture(
            Duration::from_secs(1),
            public.clone(),
            Duration::from_millis(50),
        );
        assert!(matches!(
            deadline_clients
                .client_for(
                    &url,
                    Instant::now() + Duration::from_millis(5),
                    &CancellationToken::new()
                )
                .await,
            Err(FetchError::Deadline)
        ));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (mut cancelled_clients, _) = PinnedClients::strict_fixture(
            Duration::from_secs(1),
            public,
            Duration::from_millis(50),
        );
        assert!(matches!(
            cancelled_clients
                .client_for(&url, Instant::now() + Duration::from_secs(1), &cancellation)
                .await,
            Err(FetchError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn strict_resolver_rejects_injected_private_destination() {
        let url =
            Url::parse("https://rdap.test/ip/8.8.8.8").unwrap_or_else(|error| panic!("{error}"));
        let (mut clients, _) = PinnedClients::strict_fixture(
            Duration::from_secs(1),
            answer("rdap.test", vec![socket("127.0.0.1")]),
            Duration::ZERO,
        );
        assert!(matches!(
            clients
                .client_for(
                    &url,
                    Instant::now() + Duration::from_secs(1),
                    &CancellationToken::new()
                )
                .await,
            Err(FetchError::Destination)
        ));
    }

    #[tokio::test]
    async fn request_uses_cached_pin_and_preserves_host() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let listener_address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1_024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream
                    .read(&mut chunk)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            String::from_utf8_lossy(&request).into_owned()
        });
        let hostname = "rdap.test";
        let url = Url::parse(&format!(
            "http://{hostname}:{}/rdap/ip/8.8.8.8",
            listener_address.port()
        ))
        .unwrap_or_else(|error| panic!("{error}"));
        let (mut clients, calls) = PinnedClients::fixture_with_delay(
            Duration::from_secs(1),
            answer(hostname, vec![listener_address]),
            Duration::ZERO,
            false,
        );
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        let client = clients
            .client_for(&url, deadline, &cancellation)
            .await
            .unwrap_or_else(|error| panic!("{error:?}"));
        let _cached = clients
            .client_for(&url, deadline, &cancellation)
            .await
            .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(
            get_bounded(
                &client,
                url,
                64,
                Duration::from_secs(1),
                deadline,
                &cancellation
            )
            .await,
            Ok(b"{}".to_vec())
        );
        let request = server.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(request.starts_with("GET /rdap/ip/8.8.8.8 HTTP/1.1\r\n"));
        assert!(request.to_ascii_lowercase().contains(&format!(
            "\r\nhost: {hostname}:{}\r\n",
            listener_address.port()
        )));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
