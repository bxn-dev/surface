//! Bounded SSH identification and KEXINIT posture analysis.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use futures::{StreamExt, stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    PartialSshAlgorithmSelections, ServiceKind, ServiceObservation, SshAlgorithmSelections,
    SshIdentification, SshPosture, SshPostureOutcome, TransportProtocol,
};

// Rust guideline compliant 2026-02-21

/// RFC 4253 section 4.2 caps an identification line at 255 bytes, including CRLF.
const MAX_IDENTIFICATION_BYTES: usize = 255;
/// Surface accepts at most 50 informational lines, excluding the identification line.
const MAX_PRE_BANNER_LINES: usize = 50;
/// Surface accepts 4 KiB of informational lines, including each line's CRLF.
const MAX_PRE_BANNER_BYTES: usize = 4 * 1024;
/// RFC 4253 section 6.1 caps the complete binary packet at 35,000 bytes.
const MAX_TOTAL_PACKET_BYTES: usize = 35_000;
/// The RFC `packet_length` field excludes its own four bytes.
const PACKET_LENGTH_FIELD_BYTES: usize = 4;
/// Largest `packet_length` whose unencrypted packet totals at most 35,000 bytes.
const MAX_PACKET_LENGTH_FIELD_VALUE: usize = MAX_TOTAL_PACKET_BYTES - PACKET_LENGTH_FIELD_BYTES;
/// Each externally supplied SSH name-list is capped at 8 KiB.
const MAX_NAME_LIST_BYTES: usize = 8 * 1024;
/// Each externally supplied SSH name-list is capped at 128 entries.
const MAX_ALGORITHM_NAMES: usize = 128;
const SSH_MSG_KEXINIT: u8 = 20;
pub(crate) const CLIENT_IDENTIFICATION: &[u8] = b"SSH-2.0-Surface_0.3\r\n";

// Strong-first standards-track algorithms followed by a bounded exact legacy tail.
// RFCs 4253, 4345, 6151, 8332, 8758, and 9142 define or update these names.
const KEX_ALGORITHMS: &[&str] = &[
    "curve25519-sha256",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
];
const HOST_KEY_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
];
const CIPHER_ALGORITHMS: &[&str] = &[
    "aes256-ctr",
    "aes128-ctr",
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
];
const MAC_ALGORITHMS: &[&str] = &[
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1",
    "hmac-md5",
    "hmac-md5-96",
];
const COMPRESSION_ALGORITHMS: &[&str] = &["none"];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SshAnalysisState {
    Completed,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
struct EndpointAnalysis {
    address: SocketAddr,
    posture: SshPosture,
    state: SshAnalysisState,
}

#[derive(Debug)]
struct Identification {
    protocol: &'static str,
    software: String,
}

impl From<&Identification> for SshIdentification {
    fn from(value: &Identification) -> Self {
        Self {
            protocol: value.protocol.to_owned(),
            software: value.software.clone(),
        }
    }
}

#[derive(Debug)]
struct KexInit {
    lists: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Copy)]
struct ProtocolError(&'static str);

#[derive(Debug)]
struct ExchangeError {
    reason: &'static str,
    identification: Option<SshIdentification>,
}

impl ExchangeError {
    fn new(reason: &'static str) -> Self {
        Self {
            reason,
            identification: None,
        }
    }

    fn identified(reason: &'static str, identification: &Identification) -> Self {
        Self {
            reason,
            identification: Some(identification.into()),
        }
    }
}

/// Enriches existing SSH services without adding or expanding endpoints.
pub(crate) async fn analyze_ssh(
    services: &mut [ServiceObservation],
    concurrency: usize,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> SshAnalysisState {
    let addresses = services
        .iter()
        .filter(|service| {
            service.transport == TransportProtocol::Tcp && service.service == ServiceKind::Ssh
        })
        .map(|service| service.address)
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() {
        return SshAnalysisState::Completed;
    }

    let mut analyses = stream::iter(addresses)
        .map(|address| inspect(address, request_timeout, deadline, cancellation.clone()))
        .buffer_unordered(concurrency.clamp(1, 16))
        .collect::<Vec<_>>()
        .await;
    analyses.sort_by_key(|analysis| analysis.address);

    let state = if analyses
        .iter()
        .any(|analysis| analysis.state == SshAnalysisState::Cancelled)
    {
        SshAnalysisState::Cancelled
    } else if analyses
        .iter()
        .any(|analysis| analysis.state == SshAnalysisState::TimedOut)
    {
        SshAnalysisState::TimedOut
    } else {
        SshAnalysisState::Completed
    };

    for service in services.iter_mut().filter(|service| {
        service.transport == TransportProtocol::Tcp && service.service == ServiceKind::Ssh
    }) {
        if let Some(analysis) = analyses
            .iter()
            .find(|analysis| analysis.address == service.address)
        {
            service.ssh = Some(analysis.posture.clone());
        }
    }
    state
}

async fn inspect(
    address: SocketAddr,
    request_timeout: Duration,
    deadline: Instant,
    cancellation: CancellationToken,
) -> EndpointAnalysis {
    let result = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            return indeterminate(address, "cancelled", SshAnalysisState::Cancelled);
        }
        result = timeout_at(deadline, timeout(request_timeout, inspect_inner(address))) => result,
    };
    match result {
        Ok(Ok(Ok(posture))) => EndpointAnalysis {
            address,
            posture,
            state: SshAnalysisState::Completed,
        },
        Ok(Ok(Err(error))) => indeterminate_with_details(
            address,
            error.reason,
            SshAnalysisState::Completed,
            error.identification,
        ),
        Ok(Err(_)) => indeterminate(address, "request timeout", SshAnalysisState::Completed),
        Err(_) => indeterminate(
            address,
            "caller deadline exceeded",
            SshAnalysisState::TimedOut,
        ),
    }
}

async fn inspect_inner(address: SocketAddr) -> Result<SshPosture, ExchangeError> {
    let mut socket = TcpStream::connect(address)
        .await
        .map_err(|_| ExchangeError::new("TCP connection failed"))?;
    socket
        .write_all(CLIENT_IDENTIFICATION)
        .await
        .map_err(|_| ExchangeError::new("client identification write failed"))?;
    let identification = read_identification(&mut socket)
        .await
        .map_err(|error| ExchangeError::new(error.0))?;
    let packet = client_kexinit_packet();
    socket
        .write_all(&packet)
        .await
        .map_err(|_| ExchangeError::identified("client KEXINIT write failed", &identification))?;
    let kexinit = read_server_kexinit(&mut socket)
        .await
        .map_err(|error| ExchangeError::identified(error.0, &identification))?;
    Ok(inferred_posture(&identification, &kexinit))
}

fn indeterminate(
    address: SocketAddr,
    reason: &'static str,
    state: SshAnalysisState,
) -> EndpointAnalysis {
    indeterminate_with_details(address, reason, state, None)
}

fn indeterminate_with_details(
    address: SocketAddr,
    reason: &'static str,
    state: SshAnalysisState,
    identification: Option<SshIdentification>,
) -> EndpointAnalysis {
    EndpointAnalysis {
        address,
        posture: SshPosture {
            identification,
            outcome: SshPostureOutcome::Indeterminate {
                reason: reason.to_owned(),
            },
        },
        state,
    }
}

async fn read_identification(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<Identification, ProtocolError> {
    let mut line = [0_u8; MAX_PRE_BANNER_BYTES + 1];
    let mut line_length = 0_usize;
    let mut pre_banner_lines = 0_usize;
    let mut pre_banner_bytes = 0_usize;

    loop {
        let mut byte = [0_u8; 1];
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|_| ProtocolError("server identification truncated"))?;
        if line_length == line.len() {
            return Err(ProtocolError("pre-banner byte limit exceeded"));
        }
        if line_length != 0 && line[line_length - 1] == b'\r' && byte[0] != b'\n' {
            return Err(ProtocolError("SSH line contains bare carriage return"));
        }
        if byte[0] != b'\r' && byte[0] != b'\n' && byte[0].is_ascii_control() {
            return Err(ProtocolError("SSH line contains a control character"));
        }
        line[line_length] = byte[0];
        line_length += 1;

        let current_line = &line[..line_length];
        let could_be_identification =
            b"SSH-".starts_with(current_line) || current_line.starts_with(b"SSH-");
        if current_line.starts_with(b"SSH-") && line_length > MAX_IDENTIFICATION_BYTES {
            return Err(ProtocolError("server identification exceeds 255 bytes"));
        }
        if !could_be_identification
            && pre_banner_bytes.saturating_add(line_length) > MAX_PRE_BANNER_BYTES
        {
            return Err(ProtocolError("pre-banner byte limit exceeded"));
        }
        if byte[0] != b'\n' {
            continue;
        }
        if line_length < 2 || line[line_length - 2] != b'\r' {
            return Err(ProtocolError("SSH line requires CRLF"));
        }

        let complete_line = &line[..line_length];
        if complete_line.starts_with(b"SSH-") {
            return parse_identification(complete_line);
        }

        pre_banner_lines += 1;
        pre_banner_bytes = pre_banner_bytes
            .checked_add(line_length)
            .ok_or(ProtocolError("pre-banner byte limit exceeded"))?;
        if pre_banner_lines > MAX_PRE_BANNER_LINES {
            return Err(ProtocolError("pre-banner line limit exceeded"));
        }
        if pre_banner_bytes > MAX_PRE_BANNER_BYTES {
            return Err(ProtocolError("pre-banner byte limit exceeded"));
        }
        line_length = 0;
    }
}

fn parse_identification(line: &[u8]) -> Result<Identification, ProtocolError> {
    if line.len() > MAX_IDENTIFICATION_BYTES {
        return Err(ProtocolError("server identification exceeds 255 bytes"));
    }
    let content = line
        .strip_suffix(b"\r\n")
        .ok_or(ProtocolError("server identification requires CRLF"))?;
    if content.contains(&0) {
        return Err(ProtocolError("server identification contains NUL"));
    }
    let text = std::str::from_utf8(content)
        .map_err(|_| ProtocolError("server identification is not valid ASCII"))?;
    if !text.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
        return Err(ProtocolError(
            "server identification contains invalid ASCII",
        ));
    }
    let rest = text
        .strip_prefix("SSH-")
        .ok_or(ProtocolError("invalid server identification prefix"))?;
    let (protocol, software_and_comment) = rest
        .split_once('-')
        .ok_or(ProtocolError("invalid server identification fields"))?;
    let protocol = match protocol {
        "2.0" => "2.0",
        "1.99" => "1.99",
        _ => return Err(ProtocolError("unsupported SSH protocol version")),
    };
    let (software, comment) = software_and_comment
        .split_once(' ')
        .map_or((software_and_comment, None), |(software, comment)| {
            (software, Some(comment))
        });
    if software.is_empty() || !software.bytes().all(|byte| (b'!'..=b'~').contains(&byte)) {
        return Err(ProtocolError("invalid SSH software version"));
    }
    let software = match comment.filter(|comment| !comment.is_empty()) {
        Some(comment) => format!("{software} {}", sanitize_text(comment)),
        None => software.to_owned(),
    };
    Ok(Identification {
        protocol,
        software: sanitize_text(&software),
    })
}

fn sanitize_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_IDENTIFICATION_BYTES)
        .collect()
}

fn client_kexinit_packet() -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.push(SSH_MSG_KEXINIT);
    payload.extend_from_slice(Uuid::new_v4().as_bytes());
    for algorithms in [
        KEX_ALGORITHMS,
        HOST_KEY_ALGORITHMS,
        CIPHER_ALGORITHMS,
        CIPHER_ALGORITHMS,
        MAC_ALGORITHMS,
        MAC_ALGORITHMS,
        COMPRESSION_ALGORITHMS,
        COMPRESSION_ALGORITHMS,
        &[],
        &[],
    ] {
        append_name_list(&mut payload, algorithms);
    }
    payload.push(0);
    payload.extend_from_slice(&0_u32.to_be_bytes());

    let mut padding_length = 8 - ((4 + 1 + payload.len()) % 8);
    if padding_length < 4 {
        padding_length += 8;
    }
    let packet_length = 1 + payload.len() + padding_length;
    let mut packet = Vec::with_capacity(4 + packet_length);
    packet.extend_from_slice(
        &u32::try_from(packet_length)
            .expect("fixed client KEXINIT packet length fits u32")
            .to_be_bytes(),
    );
    packet.push(u8::try_from(padding_length).expect("SSH padding length fits u8"));
    packet.extend_from_slice(&payload);
    let random_padding = Uuid::new_v4();
    packet.extend_from_slice(&random_padding.as_bytes()[..padding_length]);
    packet
}

fn append_name_list(payload: &mut Vec<u8>, names: &[&str]) {
    let value = names.join(",");
    payload.extend_from_slice(
        &u32::try_from(value.len())
            .expect("fixed SSH client name-list length fits u32")
            .to_be_bytes(),
    );
    payload.extend_from_slice(value.as_bytes());
}

async fn read_server_kexinit(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<KexInit, ProtocolError> {
    let mut encoded_length = [0_u8; 4];
    reader
        .read_exact(&mut encoded_length)
        .await
        .map_err(|_| ProtocolError("server packet length truncated"))?;
    let packet_length = usize::try_from(u32::from_be_bytes(encoded_length))
        .map_err(|_| ProtocolError("server packet length is invalid"))?;
    if packet_length > MAX_PACKET_LENGTH_FIELD_VALUE {
        return Err(ProtocolError("server packet exceeds 35,000 bytes total"));
    }
    if packet_length < 12 || (packet_length + 4) % 8 != 0 {
        return Err(ProtocolError("invalid server packet length"));
    }
    let mut packet = vec![0_u8; packet_length];
    reader
        .read_exact(&mut packet)
        .await
        .map_err(|_| ProtocolError("server packet truncated"))?;
    let padding_length = usize::from(packet[0]);
    if padding_length < 4 || padding_length >= packet_length - 1 {
        return Err(ProtocolError("invalid server packet padding"));
    }
    let payload_end = packet_length - padding_length;
    let payload = &packet[1..payload_end];
    parse_kexinit(payload)
}

fn parse_kexinit(payload: &[u8]) -> Result<KexInit, ProtocolError> {
    let mut cursor = Cursor::new(payload);
    if cursor.byte()? != SSH_MSG_KEXINIT {
        return Err(ProtocolError("server packet is not KEXINIT"));
    }
    cursor.take(16)?;
    let mut lists = Vec::with_capacity(10);
    for _ in 0..10 {
        lists.push(cursor.name_list()?);
    }
    if !matches!(cursor.byte()?, 0 | 1) {
        return Err(ProtocolError("invalid KEXINIT boolean"));
    }
    if cursor.u32()? != 0 {
        return Err(ProtocolError("invalid KEXINIT reserved field"));
    }
    if cursor.remaining() != 0 {
        return Err(ProtocolError("KEXINIT contains trailing payload bytes"));
    }
    Ok(KexInit { lists })
}

#[derive(Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError("KEXINIT field length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError("KEXINIT payload truncated"))?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = <[u8; 4]>::try_from(self.take(4)?)
            .map_err(|_| ProtocolError("KEXINIT uint32 truncated"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn name_list(&mut self) -> Result<Vec<String>, ProtocolError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ProtocolError("KEXINIT name-list length is invalid"))?;
        if length > MAX_NAME_LIST_BYTES {
            return Err(ProtocolError("KEXINIT name-list exceeds 8 KiB"));
        }
        let bytes = self.take(length)?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ProtocolError("KEXINIT name-list is not ASCII"))?;
        let names = text.split(',').collect::<Vec<_>>();
        if names.len() > MAX_ALGORITHM_NAMES {
            return Err(ProtocolError("KEXINIT name-list exceeds 128 names"));
        }
        if names.iter().any(|name| !valid_algorithm_name(name)) {
            return Err(ProtocolError("KEXINIT contains an invalid algorithm name"));
        }
        Ok(names.into_iter().map(str::to_owned).collect())
    }
}

fn valid_algorithm_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| (b'!'..=b'~').contains(&byte) && byte != b',')
    {
        return false;
    }
    let mut parts = name.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let domain = parts.next();
    if parts.next().is_some() || local.is_empty() {
        return false;
    }
    domain.is_none_or(valid_domain_name)
}

fn valid_domain_name(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn inferred_posture(identification: &Identification, kexinit: &KexInit) -> SshPosture {
    let required = [
        ("kex", KEX_ALGORITHMS, 0_usize),
        ("host_key", HOST_KEY_ALGORITHMS, 1),
        ("cipher_c2s", CIPHER_ALGORITHMS, 2),
        ("cipher_s2c", CIPHER_ALGORITHMS, 3),
        ("mac_c2s", MAC_ALGORITHMS, 4),
        ("mac_s2c", MAC_ALGORITHMS, 5),
        ("compression_c2s", COMPRESSION_ALGORITHMS, 6),
        ("compression_s2c", COMPRESSION_ALGORITHMS, 7),
    ];
    let mut missing = None;
    let mut selections = PartialSshAlgorithmSelections::default();
    for (key, client, index) in required {
        let selected = select_algorithm(client, &kexinit.lists[index]);
        if let Some(selected) = selected {
            match key {
                "kex" => selections.kex = Some(selected.to_owned()),
                "host_key" => selections.host_key = Some(selected.to_owned()),
                "cipher_c2s" => selections.cipher_c2s = Some(selected.to_owned()),
                "cipher_s2c" => selections.cipher_s2c = Some(selected.to_owned()),
                "mac_c2s" => selections.mac_c2s = Some(selected.to_owned()),
                "mac_s2c" => selections.mac_s2c = Some(selected.to_owned()),
                _ => {}
            }
        } else if missing.is_none() {
            missing = Some(key);
        }
    }
    let PartialSshAlgorithmSelections {
        kex,
        host_key,
        cipher_c2s,
        cipher_s2c,
        mac_c2s,
        mac_s2c,
    } = selections;
    let outcome = match (
        missing, kex, host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c,
    ) {
        (
            None,
            Some(kex),
            Some(host_key),
            Some(cipher_c2s),
            Some(cipher_s2c),
            Some(mac_c2s),
            Some(mac_s2c),
        ) => SshPostureOutcome::Complete {
            selections: SshAlgorithmSelections {
                kex,
                host_key,
                cipher_c2s,
                cipher_s2c,
                mac_c2s,
                mac_s2c,
            },
        },
        (missing, kex, host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c) => {
            SshPostureOutcome::Partial {
                selections: PartialSshAlgorithmSelections {
                    kex,
                    host_key,
                    cipher_c2s,
                    cipher_s2c,
                    mac_c2s,
                    mac_s2c,
                },
                reason: missing.map_or_else(
                    || "incomplete required algorithm selection".to_owned(),
                    |missing| format!("no common required algorithm: {missing}"),
                ),
            }
        }
    };
    SshPosture {
        identification: Some(identification.into()),
        outcome,
    }
}

fn select_algorithm<'a>(client: &[&'a str], server: &[String]) -> Option<&'a str> {
    client
        .iter()
        .copied()
        .find(|candidate| server.iter().any(|name| name == candidate))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Instant, sleep, timeout};
    use tokio_util::sync::CancellationToken;
    use uuid::{Uuid, Version};

    use super::{
        CIPHER_ALGORITHMS, CLIENT_IDENTIFICATION, HOST_KEY_ALGORITHMS, Identification,
        KEX_ALGORITHMS, MAC_ALGORITHMS, MAX_IDENTIFICATION_BYTES, MAX_PACKET_LENGTH_FIELD_VALUE,
        MAX_PRE_BANNER_BYTES, SshAnalysisState, analyze_ssh, inferred_posture,
        parse_identification, parse_kexinit, read_identification, read_server_kexinit,
    };
    use crate::{
        DetectionConfidence, ServiceKind, ServiceObservation, SshAlgorithmSelections, SshPosture,
        SshPostureOutcome, TransportProtocol,
    };

    const VALID_LISTS: [&str; 10] = [
        "diffie-hellman-group14-sha1,curve25519-sha256",
        "ssh-rsa,rsa-sha2-256",
        "3des-cbc,aes128-ctr",
        "3des-cbc,aes256-ctr",
        "hmac-sha1,hmac-sha2-256",
        "hmac-sha1,hmac-sha2-512",
        "none",
        "none",
        "",
        "",
    ];

    fn service(address: std::net::SocketAddr, kind: ServiceKind) -> ServiceObservation {
        ServiceObservation {
            transport: TransportProtocol::Tcp,
            address,
            service: kind,
            confidence: DetectionConfidence::High,
            banner: Some("SSH-2.0-fixture".to_owned()),
            protocol_details: BTreeMap::new(),
            ssh: None,
        }
    }

    fn selection<'a>(selections: &'a SshAlgorithmSelections, key: &str) -> &'a str {
        match key {
            "ssh_kex" => &selections.kex,
            "ssh_host_key_algorithm" => &selections.host_key,
            "ssh_cipher_c2s" => &selections.cipher_c2s,
            "ssh_cipher_s2c" => &selections.cipher_s2c,
            "ssh_mac_c2s" => &selections.mac_c2s,
            "ssh_mac_s2c" => &selections.mac_s2c,
            _ => panic!("unknown SSH selection field"),
        }
    }

    fn indeterminate_reason(posture: &SshPosture) -> Option<&str> {
        match &posture.outcome {
            SshPostureOutcome::Indeterminate { reason }
            | SshPostureOutcome::Partial { reason, .. } => Some(reason),
            SshPostureOutcome::Complete { .. } => None,
        }
    }

    fn kex_payload(
        lists: [&str; 10],
        message: u8,
        boolean: u8,
        reserved: u32,
        trailing: &[u8],
    ) -> Vec<u8> {
        let mut payload = vec![message];
        payload.extend_from_slice(&[7_u8; 16]);
        for list in lists {
            payload.extend_from_slice(
                &u32::try_from(list.len())
                    .unwrap_or_else(|error| panic!("{error}"))
                    .to_be_bytes(),
            );
            payload.extend_from_slice(list.as_bytes());
        }
        payload.push(boolean);
        payload.extend_from_slice(&reserved.to_be_bytes());
        payload.extend_from_slice(trailing);
        payload
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut padding_length = 8 - ((4 + 1 + payload.len()) % 8);
        if padding_length < 4 {
            padding_length += 8;
        }
        let packet_length = 1 + payload.len() + padding_length;
        let mut packet = Vec::new();
        packet.extend_from_slice(
            &u32::try_from(packet_length)
                .unwrap_or_else(|error| panic!("{error}"))
                .to_be_bytes(),
        );
        packet.push(u8::try_from(padding_length).unwrap_or_else(|error| panic!("{error}")));
        packet.extend_from_slice(payload);
        packet.resize(4 + packet_length, 0);
        packet
    }

    async fn read_client_packet(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut length = [0_u8; 4];
        socket
            .read_exact(&mut length)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let length =
            usize::try_from(u32::from_be_bytes(length)).unwrap_or_else(|error| panic!("{error}"));
        let mut body = vec![0_u8; length];
        socket
            .read_exact(&mut body)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        body
    }

    async fn hanging_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut identification = vec![0_u8; CLIENT_IDENTIFICATION.len()];
            socket
                .read_exact(&mut identification)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(identification, CLIENT_IDENTIFICATION);
            let mut byte = [0_u8; 1];
            let _ = socket.read(&mut byte).await;
        });
        (address, task)
    }

    #[tokio::test]
    async fn valid_exchange_uses_client_first_intersections_and_disconnects_after_kexinit() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let fixture = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut identification = vec![0_u8; CLIENT_IDENTIFICATION.len()];
            socket
                .read_exact(&mut identification)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(identification, CLIENT_IDENTIFICATION);
            socket
                .write_all(b"SSH-2.0-OpenSSH_9.9 fixture\r\n")
                .await
                .unwrap_or_else(|error| panic!("{error}"));

            let client_packet = read_client_packet(&mut socket).await;
            assert!(client_packet[0] >= 4);
            assert_eq!(client_packet[1], 20);
            let cookie =
                Uuid::from_slice(&client_packet[2..18]).unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(cookie.get_version(), Some(Version::Random));

            let server_packet = packet(&kex_payload(VALID_LISTS, 20, 0, 0, &[]));
            socket
                .write_all(&server_packet)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut unexpected = [0_u8; 1];
            let read = timeout(Duration::from_secs(1), socket.read(&mut unexpected))
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(read, 0, "client sent data after server KEXINIT");
        });

        let duplicate = service(address, ServiceKind::Ssh);
        let mut services = vec![duplicate.clone(), duplicate];
        let state = analyze_ssh(
            &mut services,
            64,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(state, SshAnalysisState::Completed);
        fixture.await.unwrap_or_else(|error| panic!("{error}"));
        for posture in services
            .iter()
            .filter_map(|observation| observation.ssh.as_ref())
        {
            assert_eq!(
                posture
                    .identification
                    .as_ref()
                    .map(|value| value.protocol.as_str()),
                Some("2.0")
            );
            assert_eq!(
                posture
                    .identification
                    .as_ref()
                    .map(|value| value.software.as_str()),
                Some("OpenSSH_9.9 fixture")
            );
            let SshPostureOutcome::Complete { selections } = &posture.outcome else {
                panic!("expected complete SSH posture");
            };
            assert_eq!(selections.kex, "curve25519-sha256");
            assert_eq!(selections.host_key, "rsa-sha2-256");
            assert_eq!(selections.cipher_c2s, "aes128-ctr");
            assert_eq!(selections.cipher_s2c, "aes256-ctr");
            assert_eq!(selections.mac_c2s, "hmac-sha2-256");
            assert_eq!(selections.mac_s2c, "hmac-sha2-512");
        }
    }

    #[tokio::test]
    async fn malformed_kexinit_retains_sanitized_json_safe_identification() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let fixture = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut client_identification = vec![0_u8; CLIENT_IDENTIFICATION.len()];
            socket
                .read_exact(&mut client_identification)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            socket
                .write_all(b"SSH-2.0-server\"\\fixture\r\n")
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            drop(read_client_packet(&mut socket).await);
            socket
                .write_all(&packet(&kex_payload(VALID_LISTS, 19, 0, 0, &[])))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        });
        let mut services = vec![service(address, ServiceKind::Ssh)];
        let state = analyze_ssh(
            &mut services,
            1,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        fixture.await.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(state, SshAnalysisState::Completed);
        let posture = services[0].ssh.as_ref().expect("SSH posture");
        assert_eq!(
            posture
                .identification
                .as_ref()
                .map(|value| value.software.as_str()),
            Some("server\"\\fixture")
        );
        assert_eq!(
            posture.outcome,
            SshPostureOutcome::Indeterminate {
                reason: "server packet is not KEXINIT".to_owned()
            }
        );
        let json = serde_json::to_string(&services[0]).unwrap_or_else(|error| panic!("{error}"));
        let round_trip: ServiceObservation =
            serde_json::from_str(&json).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(round_trip, services[0]);
        assert!(!json.contains('\u{1b}'));
    }

    #[tokio::test]
    async fn accepts_identification_and_pre_banner_boundaries() {
        let accepted = parse_identification(b"SSH-1.99-legacy fixture\r\n")
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(accepted.protocol, "1.99");
        assert_eq!(accepted.software, "legacy fixture");

        let mut maximum_identification = b"SSH-2.0-".to_vec();
        maximum_identification.resize(MAX_IDENTIFICATION_BYTES - 2, b'x');
        maximum_identification.extend_from_slice(b"\r\n");
        assert_eq!(maximum_identification.len(), MAX_IDENTIFICATION_BYTES);
        parse_identification(&maximum_identification).unwrap_or_else(|error| panic!("{}", error.0));

        let mut fifty_lines = b"ok\r\n".repeat(50);
        fifty_lines.extend_from_slice(b"SSH-2.0-server\r\n");
        let parsed = read_identification(&mut fifty_lines.as_slice())
            .await
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(parsed.protocol, "2.0");

        let mut maximum_pre_banner = vec![b'x'; MAX_PRE_BANNER_BYTES - 2];
        maximum_pre_banner.extend_from_slice(b"\r\nSSH-2.0-server\r\n");
        let parsed = read_identification(&mut maximum_pre_banner.as_slice())
            .await
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(parsed.protocol, "2.0");
    }

    #[tokio::test]
    async fn accepts_ssh_1_99_after_valid_pre_banner() {
        let mut input = b"Authorized access only\r\nSSH-1.99-legacy fixture\r\n".as_slice();
        let parsed = read_identification(&mut input)
            .await
            .unwrap_or_else(|error| panic!("{}", error.0));
        assert_eq!(parsed.protocol, "1.99");
        assert_eq!(parsed.software, "legacy fixture");
    }

    #[tokio::test]
    async fn rejects_non_crlf_controlled_or_overlong_ssh_lines() {
        let mut fifty_one_lines = b"ok\r\n".repeat(51);
        fifty_one_lines.extend_from_slice(b"SSH-2.0-server\r\n");

        let mut oversized_pre_banner = vec![b'x'; MAX_PRE_BANNER_BYTES - 1];
        oversized_pre_banner.extend_from_slice(b"\r\nSSH-2.0-server\r\n");

        let mut oversized_identification = b"SSH-2.0-".to_vec();
        oversized_identification.resize(MAX_IDENTIFICATION_BYTES - 1, b'x');
        oversized_identification.extend_from_slice(b"\r\n");

        let cases = [
            b"notice\nSSH-2.0-server\r\n".to_vec(),
            b"notice\rSSH-2.0-server\r\n".to_vec(),
            b"notice\r".to_vec(),
            b"notice\0text\r\nSSH-2.0-server\r\n".to_vec(),
            b"notice\x1btext\r\nSSH-2.0-server\r\n".to_vec(),
            b"SSH-2.0-server\n".to_vec(),
            b"SSH-2.0-server\r".to_vec(),
            b"SSH-1.99-server\n".to_vec(),
            fifty_one_lines,
            oversized_pre_banner,
            oversized_identification,
        ];
        for case in cases {
            assert!(
                read_identification(&mut case.as_slice()).await.is_err(),
                "accepted {case:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_identification() {
        let cases = [
            b"SSH-3.0-server\r\n".to_vec(),
            b"SSH-2.0-\r\n".to_vec(),
            b"SSH-2.0-bad\0software\r\n".to_vec(),
            b"SSH-2.0-bad\x1bcomment\r\n".to_vec(),
            b"SSH-2.0-bad\xff\r\n".to_vec(),
        ];
        for case in cases {
            assert!(parse_identification(&case).is_err(), "accepted {case:?}");
        }
    }

    #[tokio::test]
    async fn enforces_total_packet_boundary_before_body_read() {
        assert_eq!(MAX_PACKET_LENGTH_FIELD_VALUE, 34_996);
        let maximum = Vec::from(34_996_u32.to_be_bytes());
        let error = read_server_kexinit(&mut maximum.as_slice())
            .await
            .expect_err("the maximum structural length must attempt a body read");
        assert_eq!(error.0, "server packet truncated");

        let oversized = Vec::from(34_997_u32.to_be_bytes());
        let error = read_server_kexinit(&mut oversized.as_slice())
            .await
            .expect_err("oversized packet must fail before reading its body");
        assert_eq!(error.0, "server packet exceeds 35,000 bytes total");
    }

    #[tokio::test]
    async fn rejects_truncated_and_invalidly_padded_packets() {
        let valid = packet(&kex_payload(VALID_LISTS, 20, 0, 0, &[]));
        let error = read_server_kexinit(&mut valid[..valid.len() - 1].as_ref())
            .await
            .expect_err("truncated packet must fail");
        assert_eq!(error.0, "server packet truncated");

        let mut invalid_padding = valid;
        invalid_padding[4] = 3;
        let error = read_server_kexinit(&mut invalid_padding.as_slice())
            .await
            .expect_err("short padding must fail");
        assert_eq!(error.0, "invalid server packet padding");
    }

    #[test]
    fn strictly_rejects_malformed_kexinit_fields() {
        let mut overlong_list = VALID_LISTS;
        let oversized = "a".repeat(8 * 1024 + 1);
        overlong_list[0] = &oversized;

        let many_names = (0..129)
            .map(|index| format!("a{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut too_many = VALID_LISTS;
        too_many[0] = &many_names;

        let mut non_ascii = kex_payload(VALID_LISTS, 20, 0, 0, &[]);
        let first_list_start = 1 + 16 + 4;
        non_ascii[first_list_start] = 0xff;

        let mut invalid_name = VALID_LISTS;
        invalid_name[0] = "ok,,empty";

        let cases = [
            kex_payload(VALID_LISTS, 19, 0, 0, &[]),
            kex_payload(overlong_list, 20, 0, 0, &[]),
            kex_payload(too_many, 20, 0, 0, &[]),
            non_ascii,
            kex_payload(invalid_name, 20, 0, 0, &[]),
            kex_payload(VALID_LISTS, 20, 2, 0, &[]),
            kex_payload(VALID_LISTS, 20, 0, 1, &[]),
            kex_payload(VALID_LISTS, 20, 0, 0, &[0]),
        ];
        for payload in cases {
            assert!(parse_kexinit(&payload).is_err());
        }
        let truncated = kex_payload(VALID_LISTS, 20, 0, 0, &[]);
        assert!(parse_kexinit(&truncated[..truncated.len() - 1]).is_err());
    }

    #[test]
    fn legacy_fallbacks_are_offered_last_and_inferred_exactly() {
        assert_eq!(
            &KEX_ALGORITHMS[KEX_ALGORITHMS.len() - 2..],
            ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]
        );
        assert_eq!(
            &HOST_KEY_ALGORITHMS[HOST_KEY_ALGORITHMS.len() - 2..],
            ["ssh-rsa", "ssh-dss"]
        );
        assert_eq!(
            &CIPHER_ALGORITHMS[CIPHER_ALGORITHMS.len() - 4..],
            ["3des-cbc", "arcfour", "arcfour128", "arcfour256"]
        );
        assert_eq!(
            &MAC_ALGORITHMS[MAC_ALGORITHMS.len() - 3..],
            ["hmac-sha1", "hmac-md5", "hmac-md5-96"]
        );

        let cases = [
            (0, "ssh_kex", "diffie-hellman-group14-sha1"),
            (0, "ssh_kex", "diffie-hellman-group1-sha1"),
            (1, "ssh_host_key_algorithm", "ssh-rsa"),
            (1, "ssh_host_key_algorithm", "ssh-dss"),
            (2, "ssh_cipher_c2s", "3des-cbc"),
            (2, "ssh_cipher_c2s", "arcfour"),
            (2, "ssh_cipher_c2s", "arcfour128"),
            (2, "ssh_cipher_c2s", "arcfour256"),
            (3, "ssh_cipher_s2c", "3des-cbc"),
            (3, "ssh_cipher_s2c", "arcfour"),
            (3, "ssh_cipher_s2c", "arcfour128"),
            (3, "ssh_cipher_s2c", "arcfour256"),
            (4, "ssh_mac_c2s", "hmac-sha1"),
            (4, "ssh_mac_c2s", "hmac-md5"),
            (4, "ssh_mac_c2s", "hmac-md5-96"),
            (5, "ssh_mac_s2c", "hmac-sha1"),
            (5, "ssh_mac_s2c", "hmac-md5"),
            (5, "ssh_mac_s2c", "hmac-md5-96"),
        ];
        for (index, key, algorithm) in cases {
            let mut lists = [
                "curve25519-sha256",
                "ssh-ed25519",
                "aes128-ctr",
                "aes128-ctr",
                "hmac-sha2-256",
                "hmac-sha2-256",
                "none",
                "none",
                "",
                "",
            ];
            lists[index] = algorithm;
            let kexinit = parse_kexinit(&kex_payload(lists, 20, 0, 0, &[]))
                .unwrap_or_else(|error| panic!("{}", error.0));
            let posture = inferred_posture(
                &Identification {
                    protocol: "2.0",
                    software: "legacy-fixture".to_owned(),
                },
                &kexinit,
            );
            let SshPostureOutcome::Complete { selections } = posture.outcome else {
                panic!("expected complete SSH posture");
            };
            assert_eq!(selection(&selections, key), algorithm);
        }
    }

    #[test]
    fn no_common_required_algorithm_retains_partial_selections() {
        let mut lists = VALID_LISTS;
        lists[0] = "unsupported-kex";
        let payload = kex_payload(lists, 20, 1, 0, &[]);
        let kexinit = parse_kexinit(&payload).unwrap_or_else(|error| panic!("{}", error.0));
        let posture = inferred_posture(
            &Identification {
                protocol: "2.0",
                software: "fixture".to_owned(),
            },
            &kexinit,
        );
        let SshPostureOutcome::Partial { selections, reason } = posture.outcome else {
            panic!("expected partial SSH posture");
        };
        assert_eq!(reason, "no common required algorithm: kex");
        assert_eq!(selections.kex, None);
        assert_eq!(selections.host_key.as_deref(), Some("rsa-sha2-256"));
        assert_eq!(KEX_ALGORITHMS.last(), Some(&"diffie-hellman-group1-sha1"));

        let legacy_lists = [
            "diffie-hellman-group1-sha1",
            "ssh-dss",
            "arcfour",
            "arcfour128",
            "hmac-md5",
            "hmac-md5-96",
            "none",
            "none",
            "",
            "",
        ];
        let payload = kex_payload(legacy_lists, 20, 0, 0, &[]);
        let kexinit = parse_kexinit(&payload).unwrap_or_else(|error| panic!("{}", error.0));
        let posture = inferred_posture(
            &Identification {
                protocol: "2.0",
                software: "legacy-fixture".to_owned(),
            },
            &kexinit,
        );
        let SshPostureOutcome::Complete { selections } = posture.outcome else {
            panic!("expected complete SSH posture");
        };
        assert_eq!(selections.kex, "diffie-hellman-group1-sha1");
        assert_eq!(selections.host_key, "ssh-dss");
        assert_eq!(selections.cipher_c2s, "arcfour");
        assert_eq!(selections.mac_s2c, "hmac-md5-96");
    }

    #[tokio::test]
    async fn timeout_cancellation_and_absolute_deadline_are_distinct() {
        let (address, fixture) = hanging_fixture().await;
        let mut services = vec![service(address, ServiceKind::Ssh)];
        let state = analyze_ssh(
            &mut services,
            1,
            Duration::from_millis(20),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(state, SshAnalysisState::Completed);
        assert_eq!(
            services[0].ssh.as_ref().and_then(indeterminate_reason),
            Some("request timeout")
        );
        fixture.await.unwrap_or_else(|error| panic!("{error}"));

        let (address, fixture) = hanging_fixture().await;
        let mut services = vec![service(address, ServiceKind::Ssh)];
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            cancel.cancel();
        });
        let state = analyze_ssh(
            &mut services,
            1,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &cancellation,
        )
        .await;
        assert_eq!(state, SshAnalysisState::Cancelled);
        assert_eq!(
            services[0].ssh.as_ref().and_then(indeterminate_reason),
            Some("cancelled")
        );
        fixture.await.unwrap_or_else(|error| panic!("{error}"));

        let (address, fixture) = hanging_fixture().await;
        let mut services = vec![service(address, ServiceKind::Ssh)];
        let state = analyze_ssh(
            &mut services,
            1,
            Duration::from_secs(1),
            Instant::now() + Duration::from_millis(20),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(state, SshAnalysisState::TimedOut);
        assert_eq!(
            services[0].ssh.as_ref().and_then(indeterminate_reason),
            Some("caller deadline exceeded")
        );
        fixture.await.unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn non_ssh_services_are_not_connected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut services = vec![service(address, ServiceKind::Http)];
        let state = analyze_ssh(
            &mut services,
            16,
            Duration::from_millis(20),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(state, SshAnalysisState::Completed);
        assert!(services[0].protocol_details.is_empty());
        assert!(services[0].ssh.is_none());
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn concurrency_is_capped_at_sixteen() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut services = Vec::new();
        let mut fixtures = Vec::new();
        for _ in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let address = listener
                .local_addr()
                .unwrap_or_else(|error| panic!("{error}"));
            services.push(service(address, ServiceKind::Ssh));
            let active = active.clone();
            let maximum = maximum.clone();
            fixtures.push(tokio::spawn(async move {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                let mut bytes = [0_u8; 64];
                while socket
                    .read(&mut bytes)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"))
                    != 0
                {}
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        let state = analyze_ssh(
            &mut services,
            usize::MAX,
            Duration::from_millis(40),
            Instant::now() + Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(state, SshAnalysisState::Completed);
        for fixture in fixtures {
            fixture.await.unwrap_or_else(|error| panic!("{error}"));
        }
        assert_eq!(maximum.load(Ordering::SeqCst), 16);
    }
}
