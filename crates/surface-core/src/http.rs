//! Bounded HTTP endpoint inspection without crawling.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use reqwest::header::{HeaderMap, LOCATION, SET_COOKIE};
use reqwest::{Client, StatusCode, Url, redirect};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::{NormalizedTarget, ServiceKind, ServiceObservation};

// Rust guideline compliant 2026-02-21

const MAX_BODY_BYTES: usize = 131_072;
const MAX_COOKIES: usize = 64;
const MAX_HEADER_BYTES: usize = 4_096;
const MAX_REDIRECTS: usize = 5;
const USER_AGENT: &str = "Surface/0.1 (+authorized-security-assessment)";
const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "x-frame-options",
    "server",
    "x-powered-by",
    "content-type",
];

/// Parsed security-relevant cookie attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieObservation {
    /// Cookie name only; values are intentionally omitted.
    pub name: String,
    /// Secure transport requirement.
    pub secure: bool,
    /// Script-access restriction.
    pub http_only: bool,
    /// `SameSite` attribute when present.
    pub same_site: Option<String>,
    /// Domain attribute when present.
    pub domain: Option<String>,
    /// Path attribute when present.
    pub path: Option<String>,
}

/// One observed HTTP redirect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectObservation {
    /// Source URL.
    pub from: String,
    /// Response status.
    pub status: u16,
    /// Absolute destination URL.
    pub to: String,
}

/// Bounded HTTP endpoint evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpObservation {
    /// Connected socket address.
    pub address: SocketAddr,
    /// Initial URL.
    pub url: String,
    /// Final same-host URL.
    pub final_url: Option<String>,
    /// Final status code.
    pub status: Option<u16>,
    /// HTTP protocol version.
    pub version: Option<String>,
    /// Request latency in milliseconds.
    pub latency_ms: Option<u64>,
    /// Redirect chain, capped at five hops.
    pub redirects: Vec<RedirectObservation>,
    /// Selected capped response headers.
    pub headers: BTreeMap<String, String>,
    /// Cookies without values.
    pub cookies: Vec<CookieObservation>,
    /// Safely extracted page title.
    pub title: Option<String>,
    /// Number of retained response-body bytes.
    pub body_bytes: usize,
    /// Whether the body exceeded the retention limit.
    pub body_truncated: bool,
    /// `/robots.txt` presence.
    pub robots_txt: Option<bool>,
    /// `/.well-known/security.txt` presence.
    pub security_txt: Option<bool>,
    /// `/sitemap.xml` presence.
    pub sitemap_xml: Option<bool>,
    /// Concise request error.
    pub error: Option<String>,
}

/// Inspects discovered HTTP candidates with bounded concurrency.
#[must_use]
pub async fn analyze_http(
    target: &NormalizedTarget,
    services: &[ServiceObservation],
    concurrency: usize,
    request_timeout: Duration,
    cancellation: &CancellationToken,
) -> Vec<HttpObservation> {
    let candidates = services.iter().filter(|service| {
        service.transport == crate::TransportProtocol::Tcp
            && (matches!(service.service, ServiceKind::Http | ServiceKind::Https)
                || matches!(service.address.port(), 80 | 443 | 8000 | 8080 | 8443))
    });
    let mut observations = stream::iter(candidates)
        .map(|service| inspect(target, service, request_timeout, cancellation.clone()))
        .buffer_unordered(concurrency.clamp(1, 16))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    observations.sort_by_key(|observation| observation.address);
    observations
}

async fn inspect(
    target: &NormalizedTarget,
    service: &ServiceObservation,
    request_timeout: Duration,
    cancellation: CancellationToken,
) -> Option<HttpObservation> {
    tokio::select! {
        () = cancellation.cancelled() => None,
        observation = inspect_inner(target, service, request_timeout) => Some(observation),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded request flow retains redirect and body state"
)]
async fn inspect_inner(
    target: &NormalizedTarget,
    service: &ServiceObservation,
    request_timeout: Duration,
) -> HttpObservation {
    let scheme =
        if service.service == ServiceKind::Https || matches!(service.address.port(), 443 | 8443) {
            "https"
        } else {
            "http"
        };
    let hostname = target.hostname.as_deref().unwrap_or_else(|| {
        if service.address.is_ipv6() {
            "[::1]"
        } else {
            "127.0.0.1"
        }
    });
    let path = target.initial_path.as_deref().unwrap_or("/");
    let url_text = format!(
        "{scheme}://{}:{}{path}",
        url_host(hostname),
        service.address.port()
    );
    let Ok(initial_url) = Url::parse(&url_text) else {
        return error_observation(
            service.address,
            url_text,
            "could not construct endpoint URL",
        );
    };
    let mut builder = Client::builder()
        .no_proxy()
        .user_agent(USER_AGENT)
        .timeout(request_timeout)
        .redirect(redirect::Policy::none());
    if target.explicit_ip.is_none() {
        builder = builder.resolve(hostname, service.address);
    }
    let Ok(client) = builder.build() else {
        return error_observation(
            service.address,
            url_text,
            "could not initialize HTTP client",
        );
    };

    let started = Instant::now();
    let mut current = initial_url.clone();
    let mut redirects = Vec::new();
    let response = loop {
        let result = client.get(current.clone()).send().await;
        let Ok(response) = result else {
            let message = result.err().map_or_else(
                || "HTTP request failed".to_owned(),
                |error| error.to_string(),
            );
            return error_observation(
                service.address,
                initial_url.to_string(),
                &sanitize(&message),
            );
        };
        if !response.status().is_redirection() || redirects.len() >= MAX_REDIRECTS {
            break response;
        }
        let Some(location) = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
        else {
            break response;
        };
        let Ok(next) = current.join(location) else {
            break response;
        };
        redirects.push(RedirectObservation {
            from: current.to_string(),
            status: response.status().as_u16(),
            to: next.to_string(),
        });
        if !same_origin(&initial_url, &next) {
            break response;
        }
        current = next;
    };

    let status = response.status();
    let version = format!("{:?}", response.version());
    let headers = selected_headers(response.headers());
    let cookies = parse_cookies(response.headers());
    let mut body = Vec::new();
    let mut truncated = false;
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let Ok(chunk) = chunk else { break };
        let remaining = MAX_BODY_BYTES.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let title = extract_title(&body);
    let robots_txt = check_path(&client, &initial_url, "/robots.txt").await;
    let security_txt = check_path(&client, &initial_url, "/.well-known/security.txt").await;
    let sitemap_xml = check_path(&client, &initial_url, "/sitemap.xml").await;

    HttpObservation {
        address: service.address,
        url: initial_url.to_string(),
        final_url: Some(current.to_string()),
        status: Some(status.as_u16()),
        version: Some(version),
        latency_ms: u64::try_from(started.elapsed().as_millis()).ok(),
        redirects,
        headers,
        cookies,
        title,
        body_bytes: body.len(),
        body_truncated: truncated,
        robots_txt,
        security_txt,
        sitemap_xml,
        error: None,
    }
}

async fn check_path(client: &Client, base: &Url, path: &str) -> Option<bool> {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    client
        .head(url)
        .send()
        .await
        .ok()
        .map(|response| response.status() != StatusCode::NOT_FOUND)
}

fn selected_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    SECURITY_HEADERS
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .and_then(|value| value.to_str().ok())
                .map(|value| ((*name).to_owned(), cap(value, MAX_HEADER_BYTES)))
        })
        .collect()
}

fn parse_cookies(headers: &HeaderMap) -> Vec<CookieObservation> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(parse_cookie)
        .take(MAX_COOKIES)
        .collect()
}

fn parse_cookie(value: &str) -> Option<CookieObservation> {
    let mut parts = value.split(';').map(str::trim);
    let name = parts.next()?.split_once('=')?.0.trim();
    if name.is_empty() {
        return None;
    }
    let mut cookie = CookieObservation {
        name: cap(name, 256),
        secure: false,
        http_only: false,
        same_site: None,
        domain: None,
        path: None,
    };
    for attribute in parts {
        let (name, value) = attribute.split_once('=').unwrap_or((attribute, ""));
        match name.to_ascii_lowercase().as_str() {
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = Some(cap(value, 64)),
            "domain" => cookie.domain = Some(cap(value, 256)),
            "path" => cookie.path = Some(cap(value, 256)),
            _ => {}
        }
    }
    Some(cookie)
}

fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lowercase = text.to_ascii_lowercase();
    let start = lowercase.find("<title")?;
    let content_start = start + lowercase[start..].find('>')? + 1;
    let end = content_start + lowercase[content_start..].find("</title>")?;
    let title = text[content_start..end]
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!title.is_empty()).then(|| cap(&title, 512))
}

fn same_origin(initial: &Url, next: &Url) -> bool {
    initial.scheme() == next.scheme()
        && initial.host_str() == next.host_str()
        && initial.port_or_known_default() == next.port_or_known_default()
}

fn url_host(hostname: &str) -> String {
    if hostname.contains(':') && !hostname.starts_with('[') {
        format!("[{hostname}]")
    } else {
        hostname.to_owned()
    }
}

fn error_observation(address: SocketAddr, url: String, message: &str) -> HttpObservation {
    HttpObservation {
        address,
        url,
        final_url: None,
        status: None,
        version: None,
        latency_ms: None,
        redirects: Vec::new(),
        headers: BTreeMap::new(),
        cookies: Vec::new(),
        title: None,
        body_bytes: 0,
        body_truncated: false,
        robots_txt: None,
        security_txt: None,
        sitemap_xml: None,
        error: Some(sanitize(message)),
    }
}

fn cap(value: &str, max: usize) -> String {
    value
        .chars()
        .take(max)
        .filter(|character| !character.is_control())
        .collect()
}

fn sanitize(value: &str) -> String {
    cap(value, 512)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::{analyze_http, extract_title, parse_cookie, same_origin};
    use crate::{DetectionConfidence, ServiceKind, ServiceObservation, normalize_target};

    #[test]
    fn parses_cookie_flags_without_retaining_values() {
        let cookie = parse_cookie("session=secret; Secure; HttpOnly; SameSite=Lax; Path=/")
            .unwrap_or_else(|| panic!("cookie should parse"));
        assert_eq!(cookie.name, "session");
        assert!(cookie.secure && cookie.http_only);
        assert_eq!(cookie.same_site.as_deref(), Some("Lax"));
    }

    #[test]
    fn redirects_cannot_expand_endpoint_scope() {
        let initial =
            reqwest::Url::parse("http://127.0.0.1:8080/").unwrap_or_else(|error| panic!("{error}"));
        let other_port =
            reqwest::Url::parse("http://127.0.0.1:9090/").unwrap_or_else(|error| panic!("{error}"));
        let https = reqwest::Url::parse("https://127.0.0.1:8080/")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!same_origin(&initial, &other_port));
        assert!(!same_origin(&initial, &https));
    }

    #[test]
    fn extracts_bounded_plain_title() {
        assert_eq!(
            extract_title(b"<html><title> Surface  Test </title></html>").as_deref(),
            Some("Surface Test")
        );
        assert!(extract_title(b"no title").is_none());
    }

    #[tokio::test]
    async fn inspects_local_http_with_bounded_metadata() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let mut request = [0_u8; 2_048];
                let length = stream
                    .read(&mut request)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let request = String::from_utf8_lossy(&request[..length]);
                let missing = request.contains("/.well-known/security.txt");
                let status = if missing { "404 Not Found" } else { "200 OK" };
                let body = if request.starts_with("HEAD") {
                    ""
                } else {
                    "<title>Local Fixture</title>"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Security-Policy: default-src 'none'\r\nSet-Cookie: session=secret; HttpOnly; SameSite=Lax\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
            }
        });
        let target = normalize_target("localhost").unwrap_or_else(|error| panic!("{error}"));
        let service = ServiceObservation {
            transport: crate::TransportProtocol::Tcp,
            address,
            service: ServiceKind::Http,
            confidence: DetectionConfidence::High,
            banner: None,
            protocol_details: BTreeMap::new(),
        };
        let observations = analyze_http(
            &target,
            &[service],
            1,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        server.await.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(observations[0].status, Some(200));
        assert_eq!(observations[0].title.as_deref(), Some("Local Fixture"));
        assert_eq!(observations[0].security_txt, Some(false));
        assert_eq!(observations[0].cookies[0].name, "session");
    }

    #[tokio::test]
    async fn cancellation_aborts_in_progress_body_request() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut request = [0_u8; 2_048];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });
        let service = ServiceObservation {
            transport: crate::TransportProtocol::Tcp,
            address,
            service: ServiceKind::Http,
            confidence: DetectionConfidence::High,
            banner: None,
            protocol_details: BTreeMap::new(),
        };
        let observations = analyze_http(
            &normalize_target("localhost").unwrap_or_else(|error| panic!("{error}")),
            &[service],
            1,
            Duration::from_secs(10),
            &cancellation,
        )
        .await;
        server.abort();
        assert!(observations.is_empty());
    }
}
