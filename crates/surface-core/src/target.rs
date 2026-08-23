//! Target input parsing and normalization.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

// Rust guideline compliant 2026-02-21

/// A normalized domain, URL, or IP target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedTarget {
    /// Original user input.
    pub original: String,
    /// Canonical ASCII hostname, including IP literals.
    pub hostname: Option<String>,
    /// Explicit IP when the input identifies one directly.
    pub explicit_ip: Option<IpAddr>,
    /// Explicit HTTP scheme for URL inputs.
    pub scheme: Option<String>,
    /// Explicit URL port.
    pub explicit_port: Option<u16>,
    /// Initial URL path and query.
    pub initial_path: Option<String>,
}

impl NormalizedTarget {
    /// Reports whether active scanning may proceed without acknowledgement.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.explicit_ip.is_some_and(|ip| ip.is_loopback())
            || self.hostname.as_deref() == Some("localhost")
    }

    /// Returns the canonical target identity.
    #[must_use]
    pub fn identity(&self) -> String {
        self.hostname
            .clone()
            .or_else(|| self.explicit_ip.map(|ip| ip.to_string()))
            .unwrap_or_else(|| self.original.clone())
    }
}

/// Describes invalid target input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetError {
    message: String,
}

impl TargetError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TargetError {}

/// Parses and normalizes a target without performing network access.
///
/// # Errors
///
/// Returns an error for empty, malformed, or unsupported target input.
pub fn normalize_target(input: impl AsRef<str>) -> Result<NormalizedTarget, TargetError> {
    let input = input.as_ref();
    if input.is_empty() || input.trim() != input || input.chars().any(char::is_control) {
        return Err(TargetError::new(
            "target must be non-empty and contain no surrounding whitespace",
        ));
    }

    let unbracketed = input
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(input);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(ip_target(input, ip));
    }

    if input.contains("://") {
        return normalize_url(input);
    }

    if input.contains(['/', '?', '#', '@', ':']) {
        return Err(TargetError::new(
            "bare target must be a hostname or IP address",
        ));
    }

    let hostname = input.trim_end_matches('.');
    if hostname.is_empty() {
        return Err(TargetError::new("hostname must not be empty"));
    }

    match Host::parse(hostname)
        .map_err(|error| TargetError::new(format!("invalid hostname: {error}")))?
    {
        Host::Domain(domain) => {
            let domain = domain.to_lowercase();
            validate_domain(&domain)?;
            Ok(NormalizedTarget {
                original: input.to_owned(),
                hostname: Some(domain),
                explicit_ip: None,
                scheme: None,
                explicit_port: None,
                initial_path: None,
            })
        }
        Host::Ipv4(ip) => Ok(ip_target(input, IpAddr::V4(ip))),
        Host::Ipv6(ip) => Ok(ip_target(input, IpAddr::V6(ip))),
    }
}

fn normalize_url(input: &str) -> Result<NormalizedTarget, TargetError> {
    let url =
        Url::parse(input).map_err(|error| TargetError::new(format!("invalid URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(TargetError::new(format!(
            "unsupported URL scheme '{}'; use http or https",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TargetError::new("target URLs must not contain credentials"));
    }

    let host = url
        .host()
        .ok_or_else(|| TargetError::new("URL must contain a hostname or IP address"))?;
    let (hostname, explicit_ip) = match host {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_lowercase();
            validate_domain(&domain)?;
            (domain, None)
        }
        Host::Ipv4(ip) => (ip.to_string(), Some(IpAddr::V4(ip))),
        Host::Ipv6(ip) => (ip.to_string(), Some(IpAddr::V6(ip))),
    };
    let mut initial_path = url.path().to_owned();
    if let Some(query) = url.query() {
        initial_path.push('?');
        initial_path.push_str(query);
    }

    Ok(NormalizedTarget {
        original: input.to_owned(),
        hostname: Some(hostname),
        explicit_ip,
        scheme: Some(url.scheme().to_owned()),
        explicit_port: url.port(),
        initial_path: Some(initial_path),
    })
}

fn validate_domain(domain: &str) -> Result<(), TargetError> {
    if domain.len() > 253 {
        return Err(TargetError::new("hostname exceeds 253 ASCII bytes"));
    }
    for label in domain.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if !valid {
            return Err(TargetError::new(format!(
                "invalid hostname label '{label}'"
            )));
        }
    }
    Ok(())
}

fn ip_target(original: &str, ip: IpAddr) -> NormalizedTarget {
    NormalizedTarget {
        original: original.to_owned(),
        hostname: Some(ip.to_string()),
        explicit_ip: Some(ip),
        scheme: None,
        explicit_port: None,
        initial_path: None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::normalize_target;

    #[test]
    fn normalizes_domains_urls_and_ips() {
        let domain = normalize_target("BÜCHER.Example.").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(domain.hostname.as_deref(), Some("xn--bcher-kva.example"));

        let url = normalize_target("https://EXAMPLE.com:8443/a?q=1#ignored")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(url.hostname.as_deref(), Some("example.com"));
        assert_eq!(url.explicit_port, Some(8443));
        assert_eq!(url.initial_path.as_deref(), Some("/a?q=1"));

        let ipv6 = normalize_target("2001:db8::10").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            ipv6.explicit_ip,
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10
            )))
        );
    }

    #[test]
    fn rejects_unsupported_or_malformed_targets() {
        for input in [
            "",
            " example.com",
            "ftp://example.com",
            "https://example.com:99999",
            "user@example.com",
            ".example",
            "foo..bar",
            "a_b.example",
            "foo-.example",
        ] {
            assert!(normalize_target(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn identifies_local_targets() {
        assert!(normalize_target("localhost").is_ok_and(|target| target.is_local()));
        assert!(normalize_target("127.0.0.1").is_ok_and(|target| target.is_local()));
        assert!(normalize_target("127.0.0.2").is_ok_and(|target| target.is_local()));
        assert!(!normalize_target("192.0.2.1").is_ok_and(|target| target.is_local()));
    }
}
