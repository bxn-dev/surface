//! Port selection parsing.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// Rust guideline compliant 2026-02-21

/// Conservative ports used by both initial named presets.
const MAX_SELECTED_PORTS: usize = 10_000;

const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521,
    2049, 2375, 2376, 3306, 3389, 5432, 5672, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
];

/// A sorted, deduplicated TCP port selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSelection {
    ports: Vec<u16>,
}

impl PortSelection {
    /// Returns selected ports in ascending order.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.ports
    }
}

/// Describes an invalid port specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpecError {
    message: String,
}

impl PortSpecError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PortSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PortSpecError {}

/// Parses a named, listed, or ranged TCP port specification.
///
/// # Errors
///
/// Returns an error for malformed, zero, reversed, or out-of-range ports.
pub fn parse_ports(specification: impl AsRef<str>) -> Result<PortSelection, PortSpecError> {
    let specification = specification.as_ref();
    if matches!(specification, "common" | "top-100") {
        return Ok(PortSelection {
            ports: COMMON_PORTS.to_vec(),
        });
    }
    if specification.is_empty() {
        return Err(PortSpecError::new("port specification must not be empty"));
    }

    let mut ports = BTreeSet::new();
    for item in specification.split(',') {
        if item.is_empty() || item.trim() != item {
            return Err(PortSpecError::new(
                "port items must be non-empty and contain no whitespace",
            ));
        }
        if let Some((start, end)) = item.split_once('-') {
            if end.contains('-') {
                return Err(PortSpecError::new(format!("invalid port range '{item}'")));
            }
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(PortSpecError::new(format!("reversed port range '{item}'")));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(item)?);
        }
    }

    if ports.len() > MAX_SELECTED_PORTS {
        return Err(PortSpecError::new(format!(
            "port specification selects more than {MAX_SELECTED_PORTS} ports"
        )));
    }
    Ok(PortSelection {
        ports: ports.into_iter().collect(),
    })
}

fn parse_port(value: &str) -> Result<u16, PortSpecError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| PortSpecError::new(format!("invalid TCP port '{value}'")))?;
    if port == 0 {
        return Err(PortSpecError::new("TCP port must be between 1 and 65535"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::parse_ports;

    #[test]
    fn parses_sorts_and_deduplicates_ports() {
        let selection =
            parse_ports("443,80,8000-8002,80").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(selection.as_slice(), &[80, 443, 8000, 8001, 8002]);
        assert_eq!(parse_ports("common").ok(), parse_ports("top-100").ok());
    }

    #[test]
    fn rejects_invalid_ports() {
        for input in [
            "", "0", "65536", "80-22", "22-", "1-2-3", "22, 80", "1-10001",
        ] {
            assert!(parse_ports(input).is_err(), "accepted {input:?}");
        }
    }
}
