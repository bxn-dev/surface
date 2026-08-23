//! Validating TLS handshake and certificate inspection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{StreamExt, stream};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::ServiceObservation;

// Rust guideline compliant 2026-02-21

/// Validated TLS endpoint evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsObservation {
    /// Connected socket address.
    pub address: SocketAddr,
    /// SNI or IP identity used for verification.
    pub server_name: String,
    /// Whether a validating handshake succeeded.
    pub handshake_succeeded: bool,
    /// Whether the configured root store trusted the chain.
    pub certificate_trusted: Option<bool>,
    /// Whether certificate identity validation succeeded.
    pub hostname_matches: Option<bool>,
    /// Negotiated TLS version.
    pub protocol_version: Option<String>,
    /// Negotiated application protocol.
    pub alpn: Option<String>,
    /// Leaf subject.
    pub subject: Option<String>,
    /// Leaf issuer.
    pub issuer: Option<String>,
    /// Leaf serial number.
    pub serial_number: Option<String>,
    /// Unix validity-start timestamp.
    pub valid_from_unix: Option<i64>,
    /// Unix validity-end timestamp.
    pub valid_until_unix: Option<i64>,
    /// DNS and IP subject alternative names.
    pub subject_alt_names: Vec<String>,
    /// Public-key algorithm object identifier.
    pub public_key_algorithm: Option<String>,
    /// Signature algorithm object identifier.
    pub signature_algorithm: Option<String>,
    /// Concise validating-handshake errors.
    pub errors: Vec<String>,
}

/// Attempts validating TLS handshakes against every open service.
#[must_use]
pub async fn analyze_tls(
    services: &[ServiceObservation],
    server_name: &str,
    concurrency: usize,
    handshake_timeout: Duration,
    cancellation: &CancellationToken,
) -> Vec<TlsObservation> {
    let root_store = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<RootCertStore>();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let Ok(builder) =
        ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()
    else {
        return Vec::new();
    };
    let mut config = builder
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let addresses = services
        .iter()
        .filter(|service| service.transport == crate::TransportProtocol::Tcp)
        .map(|service| service.address);
    let mut observations = stream::iter(addresses)
        .map(|address| {
            inspect(
                connector.clone(),
                address,
                server_name.to_owned(),
                handshake_timeout,
                cancellation.clone(),
            )
        })
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
    connector: TlsConnector,
    address: SocketAddr,
    server_name: String,
    handshake_timeout: Duration,
    cancellation: CancellationToken,
) -> Option<TlsObservation> {
    tokio::select! {
        () = cancellation.cancelled() => None,
        result = timeout(handshake_timeout, inspect_inner(connector, address, server_name.clone())) => {
            match result {
                Ok(Ok(observation)) => Some(observation),
                Ok(Err(error)) => Some(failed(address, server_name, &error)),
                Err(_) => Some(failed(address, server_name, "TLS handshake timed out")),
            }
        }
    }
}

async fn inspect_inner(
    connector: TlsConnector,
    address: SocketAddr,
    server_name: String,
) -> Result<TlsObservation, String> {
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| sanitize(&error.to_string()))?;
    let identity = ServerName::try_from(server_name.clone())
        .map_err(|error| format!("invalid TLS server name: {error}"))?;
    let tls = connector
        .connect(identity, stream)
        .await
        .map_err(|error| sanitize(&error.to_string()))?;
    let connection = tls.get_ref().1;
    let certificate = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| "TLS peer supplied no certificate".to_owned())?;
    let (_, certificate) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|error| format!("could not parse leaf certificate: {error}"))?;
    let subject_alt_names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some((*name).to_owned()),
                    GeneralName::IPAddress(bytes) if bytes.len() == 4 => Some(format!(
                        "{}.{}.{}.{}",
                        bytes[0], bytes[1], bytes[2], bytes[3]
                    )),
                    GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                        let octets: [u8; 16] = (*bytes).try_into().ok()?;
                        Some(std::net::Ipv6Addr::from(octets).to_string())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(TlsObservation {
        address,
        server_name,
        handshake_succeeded: true,
        certificate_trusted: Some(true),
        hostname_matches: Some(true),
        protocol_version: connection
            .protocol_version()
            .map(|version| format!("{version:?}")),
        alpn: connection
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).into_owned()),
        subject: Some(certificate.subject().to_string()),
        issuer: Some(certificate.issuer().to_string()),
        serial_number: Some(certificate.raw_serial_as_string()),
        valid_from_unix: Some(certificate.validity().not_before.timestamp()),
        valid_until_unix: Some(certificate.validity().not_after.timestamp()),
        subject_alt_names,
        public_key_algorithm: Some(certificate.public_key().algorithm.algorithm.to_id_string()),
        signature_algorithm: Some(certificate.signature_algorithm.algorithm.to_id_string()),
        errors: Vec::new(),
    })
}

fn failed(address: SocketAddr, server_name: String, error: &str) -> TlsObservation {
    TlsObservation {
        address,
        server_name,
        handshake_succeeded: false,
        certificate_trusted: None,
        hostname_matches: None,
        protocol_version: None,
        alpn: None,
        subject: None,
        issuer: None,
        serial_number: None,
        valid_from_unix: None,
        valid_until_unix: None,
        subject_alt_names: Vec::new(),
        public_key_algorithm: None,
        signature_algorithm: None,
        errors: vec![sanitize(error)],
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::ServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_util::sync::CancellationToken;

    use super::analyze_tls;
    use crate::{DetectionConfidence, ServiceKind, ServiceObservation};

    #[tokio::test]
    async fn reports_self_signed_certificate_validation_failure() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()])
                .unwrap_or_else(|error| panic!("{error}"));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|error| panic!("{error}"));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let config = builder
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap_or_else(|error| panic!("{error}"));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let _ = acceptor.accept(stream).await;
        });
        let service = ServiceObservation {
            transport: crate::TransportProtocol::Tcp,
            address,
            service: ServiceKind::Https,
            confidence: DetectionConfidence::High,
            banner: None,
            protocol_details: BTreeMap::new(),
        };
        let observations = analyze_tls(
            &[service],
            "localhost",
            1,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await;
        server.await.unwrap_or_else(|error| panic!("{error}"));
        assert!(!observations[0].handshake_succeeded);
        assert!(!observations[0].errors.is_empty());
    }
}
