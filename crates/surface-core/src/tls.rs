//! Validating TLS handshake and certificate inspection.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{StreamExt, stream};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use x509_parser::asn1_rs::Oid;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::{ServiceKind, ServiceObservation, TransportProtocol};

// Rust guideline compliant 2026-02-21

/// Maximum peer certificates inspected after one validated handshake.
const MAX_CERTIFICATES: usize = 16;
/// Maximum cumulative certificate DER inspected after one validated handshake.
const MAX_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;
/// Maximum normalized DNS and IP SAN entries retained from the leaf certificate.
const MAX_SUBJECT_ALT_NAMES: usize = 128;

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
    /// Negotiated cipher suite identifier.
    #[serde(default)]
    pub cipher_suite: Option<String>,
    /// Negotiated application protocol.
    pub alpn: Option<String>,
    /// Number of certificates supplied by the peer.
    #[serde(default)]
    pub certificate_chain_length: Option<usize>,
    /// Lowercase hexadecimal SHA-256 fingerprint of the leaf DER.
    #[serde(default)]
    pub leaf_certificate_sha256: Option<String>,
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
    /// Whether additional normalized subject alternative names were omitted.
    #[serde(default)]
    pub subject_alt_names_truncated: bool,
    /// Public-key algorithm object identifier.
    pub public_key_algorithm: Option<String>,
    /// Reliably parsed public-key size in bits.
    #[serde(default)]
    pub public_key_bits: Option<usize>,
    /// Signature algorithm object identifier.
    pub signature_algorithm: Option<String>,
    /// Concise validating-handshake errors.
    pub errors: Vec<String>,
}

/// Attempts one validating handshake per applicable implicit-TLS endpoint.
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
    analyze_tls_with_connector(
        services,
        server_name,
        concurrency,
        handshake_timeout,
        cancellation,
        TlsConnector::from(Arc::new(config)),
    )
    .await
}

async fn analyze_tls_with_connector(
    services: &[ServiceObservation],
    server_name: &str,
    concurrency: usize,
    handshake_timeout: Duration,
    cancellation: &CancellationToken,
    connector: TlsConnector,
) -> Vec<TlsObservation> {
    let addresses = services
        .iter()
        .filter(|service| is_implicit_tls_candidate(service))
        .map(|service| service.address)
        .collect::<BTreeSet<_>>();
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

fn is_implicit_tls_candidate(service: &ServiceObservation) -> bool {
    if service.transport != TransportProtocol::Tcp {
        return false;
    }
    matches!(
        (service.service, service.address.port()),
        (
            ServiceKind::Https
                | ServiceKind::Smtps
                | ServiceKind::Imaps
                | ServiceKind::Pop3s
                | ServiceKind::Tls,
            _
        ) | (ServiceKind::Oracle, 2484)
            | (ServiceKind::Mqtt, 8883)
            | (ServiceKind::Docker, 2376)
            | (ServiceKind::Rabbitmq, 5671 | 15671)
            | (ServiceKind::Kubernetes, 6443)
    )
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
    let mut observation = TlsObservation {
        address,
        server_name,
        handshake_succeeded: true,
        certificate_trusted: Some(true),
        hostname_matches: Some(true),
        protocol_version: connection
            .protocol_version()
            .map(|version| format!("{version:?}")),
        cipher_suite: connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        alpn: connection
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).into_owned()),
        certificate_chain_length: None,
        leaf_certificate_sha256: None,
        subject: None,
        issuer: None,
        serial_number: None,
        valid_from_unix: None,
        valid_until_unix: None,
        subject_alt_names: Vec::new(),
        subject_alt_names_truncated: false,
        public_key_algorithm: None,
        public_key_bits: None,
        signature_algorithm: None,
        errors: Vec::new(),
    };
    inspect_certificates(
        connection
            .peer_certificates()
            .ok_or_else(|| "TLS peer supplied no certificate".to_owned())?,
        &mut observation,
    )?;
    Ok(observation)
}

fn inspect_certificates(
    certificates: &[CertificateDer<'_>],
    observation: &mut TlsObservation,
) -> Result<(), String> {
    let leaf = certificates
        .first()
        .ok_or_else(|| "TLS peer supplied no certificate".to_owned())?;
    observation.certificate_chain_length = Some(certificates.len());
    if certificates.len() > MAX_CERTIFICATES {
        observation.errors.push(format!(
            "certificate inspection limited to the first {MAX_CERTIFICATES} of {} peer certificates",
            certificates.len()
        ));
    }

    let mut cumulative_der_bytes = 0_usize;
    let mut inspected_certificates = 0_usize;
    for certificate in certificates.iter().take(MAX_CERTIFICATES) {
        let Some(next_bytes) = cumulative_der_bytes.checked_add(certificate.as_ref().len()) else {
            observation.errors.push(format!(
                "certificate DER inspection limited to {MAX_CERTIFICATE_DER_BYTES} cumulative bytes"
            ));
            break;
        };
        if next_bytes > MAX_CERTIFICATE_DER_BYTES {
            observation.errors.push(format!(
                "certificate DER inspection limited to {MAX_CERTIFICATE_DER_BYTES} cumulative bytes"
            ));
            break;
        }
        cumulative_der_bytes = next_bytes;
        inspected_certificates += 1;
    }
    if inspected_certificates == 0 {
        return Ok(());
    }

    let (_, certificate) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|error| format!("could not parse leaf certificate: {error}"))?;
    match normalized_subject_alt_names(&certificate) {
        Ok((subject_alt_names, subject_alt_names_truncated)) => {
            observation.subject_alt_names = subject_alt_names;
            observation.subject_alt_names_truncated = subject_alt_names_truncated;
        }
        Err(()) => observation
            .errors
            .push("subject alternative name extension could not be parsed".to_owned()),
    }
    observation.leaf_certificate_sha256 = Some(format!("{:x}", Sha256::digest(leaf.as_ref())));
    observation.subject = Some(certificate.subject().to_string());
    observation.issuer = Some(certificate.issuer().to_string());
    observation.serial_number = Some(certificate.raw_serial_as_string());
    observation.valid_from_unix = Some(certificate.validity().not_before.timestamp());
    observation.valid_until_unix = Some(certificate.validity().not_after.timestamp());
    let public_key = certificate.public_key();
    observation.public_key_algorithm = Some(public_key.algorithm.algorithm.to_id_string());
    observation.public_key_bits = public_key.parsed().ok().and_then(|key| {
        let named_curve_oid = public_key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok());
        parsed_public_key_bits(&key, named_curve_oid.as_ref())
    });
    observation.signature_algorithm =
        Some(certificate.signature_algorithm.algorithm.to_id_string());
    Ok(())
}

fn normalized_subject_alt_names(
    certificate: &X509Certificate<'_>,
) -> Result<(Vec<String>, bool), ()> {
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    let Some(extension) = certificate.subject_alternative_name().map_err(|_| ())? else {
        return Ok((names, false));
    };
    for name in &extension.value.general_names {
        let normalized = match name {
            GeneralName::DNSName(name) => Some(name.trim_end_matches('.').to_ascii_lowercase()),
            GeneralName::IPAddress(bytes) if bytes.len() == 4 => Some(format!(
                "{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            )),
            GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                let Ok(octets) = <[u8; 16]>::try_from(*bytes) else {
                    continue;
                };
                Some(std::net::Ipv6Addr::from(octets).to_string())
            }
            _ => None,
        };
        let Some(normalized) = normalized.filter(|name| !name.is_empty()) else {
            continue;
        };
        if !seen.insert(normalized.clone()) {
            continue;
        }
        if names.len() == MAX_SUBJECT_ALT_NAMES {
            return Ok((names, true));
        }
        names.push(normalized);
    }
    Ok((names, false))
}

fn parsed_public_key_bits(key: &PublicKey<'_>, named_curve_oid: Option<&Oid<'_>>) -> Option<usize> {
    match key {
        PublicKey::RSA(key) => rsa_modulus_bits(key.modulus),
        PublicKey::EC(_) => {
            let oid = named_curve_oid?;
            if oid == &OID_EC_P256 {
                Some(256)
            } else if oid == &OID_NIST_EC_P384 {
                Some(384)
            } else if oid == &OID_NIST_EC_P521 {
                Some(521)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn rsa_modulus_bits(modulus: &[u8]) -> Option<usize> {
    let unsigned = match modulus {
        [0, next, ..] if next & 0x80 != 0 => &modulus[1..],
        [] | [0, ..] => return None,
        [first, ..] if first & 0x80 != 0 => return None,
        _ => modulus,
    };
    let bits_per_byte = usize::try_from(u8::BITS).ok()?;
    let significant_bits = usize::try_from(u8::BITS - unsigned.first()?.leading_zeros()).ok()?;
    unsigned
        .len()
        .checked_sub(1)?
        .checked_mul(bits_per_byte)?
        .checked_add(significant_bits)
}

fn failed(address: SocketAddr, server_name: String, error: &str) -> TlsObservation {
    TlsObservation {
        address,
        server_name,
        handshake_succeeded: false,
        certificate_trusted: None,
        hostname_matches: None,
        protocol_version: None,
        cipher_suite: None,
        alpn: None,
        certificate_chain_length: None,
        leaf_certificate_sha256: None,
        subject: None,
        issuer: None,
        serial_number: None,
        valid_from_unix: None,
        valid_until_unix: None,
        subject_alt_names: Vec::new(),
        subject_alt_names_truncated: false,
        public_key_algorithm: None,
        public_key_bits: None,
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

    use rcgen::{
        CertificateParams, CertifiedKey, CustomExtension, KeyPair, generate_simple_self_signed,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_util::sync::CancellationToken;
    use x509_parser::public_key::PublicKey;

    use super::{
        MAX_CERTIFICATE_DER_BYTES, TlsObservation, analyze_tls, analyze_tls_with_connector, failed,
        inspect_certificates, parsed_public_key_bits, rsa_modulus_bits,
    };
    use crate::{DetectionConfidence, ServiceKind, ServiceObservation, TransportProtocol};

    fn service(address: std::net::SocketAddr, kind: ServiceKind) -> ServiceObservation {
        ServiceObservation {
            transport: TransportProtocol::Tcp,
            address,
            service: kind,
            confidence: DetectionConfidence::High,
            banner: None,
            protocol_details: BTreeMap::new(),
        }
    }

    fn fixture(names: Vec<String>) -> (TlsConnector, TlsAcceptor, CertificateDer<'static>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(names).unwrap_or_else(|error| panic!("{error}"));
        let certificate = cert.der().clone();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.clone())
            .unwrap_or_else(|error| panic!("{error}"));
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        (
            TlsConnector::from(Arc::new(client)),
            TlsAcceptor::from(Arc::new(server)),
            certificate,
        )
    }

    fn blank_observation() -> TlsObservation {
        let mut observation = failed(
            "127.0.0.1:443"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            "localhost".to_owned(),
            "fixture",
        );
        observation.errors.clear();
        observation
    }

    #[tokio::test]
    async fn reports_successful_fixture_fields_and_deduplicates_endpoint() {
        let (connector, acceptor, certificate) = fixture(vec!["localhost".to_owned()]);
        let expected_fingerprint = format!("{:x}", Sha256::digest(certificate.as_ref()));
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
            acceptor
                .accept(stream)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(
                timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let duplicate = service(address, ServiceKind::Https);
        let observations = analyze_tls_with_connector(
            &[duplicate.clone(), duplicate],
            "localhost",
            2,
            Duration::from_secs(2),
            &CancellationToken::new(),
            connector,
        )
        .await;
        server.await.unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert!(observation.handshake_succeeded);
        assert_eq!(observation.certificate_trusted, Some(true));
        assert_eq!(observation.hostname_matches, Some(true));
        assert!(observation.protocol_version.is_some());
        assert!(observation.cipher_suite.is_some());
        assert_eq!(observation.alpn.as_deref(), Some("h2"));
        assert_eq!(observation.certificate_chain_length, Some(1));
        assert_eq!(
            observation.leaf_certificate_sha256.as_deref(),
            Some(expected_fingerprint.as_str())
        );
        assert_eq!(observation.public_key_bits, Some(256));
        assert_eq!(observation.subject_alt_names, ["localhost"]);
        assert!(!observation.subject_alt_names_truncated);
        assert!(observation.errors.is_empty());
    }

    #[tokio::test]
    async fn non_applicable_service_makes_no_connection() {
        let (connector, _, _) = fixture(vec!["localhost".to_owned()]);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let observations = analyze_tls_with_connector(
            &[service(address, ServiceKind::Ssh)],
            "localhost",
            1,
            Duration::from_millis(100),
            &CancellationToken::new(),
            connector,
        )
        .await;

        assert!(observations.is_empty());
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn certificate_and_san_inspection_respects_bounds() {
        let names = (0..129)
            .map(|index| format!("N{index:03}.EXAMPLE.COM."))
            .collect();
        let (_, _, certificate) = fixture(names);
        let mut observation = blank_observation();
        inspect_certificates(std::slice::from_ref(&certificate), &mut observation)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(observation.subject_alt_names.len(), 128);
        assert_eq!(observation.subject_alt_names[0], "n000.example.com");
        assert_eq!(observation.subject_alt_names[127], "n127.example.com");
        assert!(observation.subject_alt_names_truncated);

        let mut chain_observation = blank_observation();
        inspect_certificates(&vec![certificate.clone(); 17], &mut chain_observation)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(chain_observation.certificate_chain_length, Some(17));
        assert!(
            chain_observation
                .errors
                .iter()
                .any(|error| error.contains("first 16"))
        );

        let oversized = CertificateDer::from(vec![0_u8; MAX_CERTIFICATE_DER_BYTES]);
        let mut bytes_observation = blank_observation();
        inspect_certificates(&[certificate, oversized], &mut bytes_observation)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(bytes_observation.leaf_certificate_sha256.is_some());
        assert!(
            bytes_observation
                .errors
                .iter()
                .any(|error| error.contains("1048576 cumulative bytes"))
        );
    }

    #[test]
    fn malformed_and_absent_san_are_distinct() {
        let signing_key = KeyPair::generate().unwrap_or_else(|error| panic!("{error}"));
        let absent_certificate = CertificateParams::default()
            .self_signed(&signing_key)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut absent_observation = blank_observation();
        inspect_certificates(
            std::slice::from_ref(absent_certificate.der()),
            &mut absent_observation,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(absent_observation.subject_alt_names.is_empty());
        assert!(!absent_observation.subject_alt_names_truncated);
        assert!(absent_observation.errors.is_empty());

        let mut malformed_params = CertificateParams::default();
        malformed_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                vec![0x05, 0x00],
            ));
        let malformed_certificate = malformed_params
            .self_signed(&signing_key)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut malformed_observation = blank_observation();
        inspect_certificates(
            std::slice::from_ref(malformed_certificate.der()),
            &mut malformed_observation,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(malformed_observation.subject_alt_names.is_empty());
        assert!(!malformed_observation.subject_alt_names_truncated);
        assert_eq!(
            malformed_observation.errors,
            ["subject alternative name extension could not be parsed"]
        );
    }

    #[test]
    fn exact_public_key_bits_rejects_inexact_or_malformed_keys() {
        let mut rsa_2048 = vec![0_u8; 257];
        rsa_2048[1] = 0x80;
        assert_eq!(rsa_modulus_bits(&rsa_2048), Some(2048));

        let mut rsa_2047 = vec![0_u8; 256];
        rsa_2047[0] = 0x40;
        assert_eq!(rsa_modulus_bits(&rsa_2047), Some(2047));
        assert_eq!(rsa_modulus_bits(&[0x00, 0x80]), Some(8));
        assert_eq!(rsa_modulus_bits(&[]), None);
        assert_eq!(rsa_modulus_bits(&[0x00]), None);
        assert_eq!(rsa_modulus_bits(&[0x80]), None);
        assert_eq!(rsa_modulus_bits(&[0x00, 0x7f]), None);
        assert_eq!(parsed_public_key_bits(&PublicKey::DSA(&[0x01]), None), None);
        assert_eq!(
            parsed_public_key_bits(&PublicKey::Unknown(&[0x01]), None),
            None
        );
    }

    #[test]
    fn older_json_defaults_new_tls_fields() {
        let old = json!({
            "address": "127.0.0.1:443",
            "server_name": "example.com",
            "handshake_succeeded": true,
            "certificate_trusted": true,
            "hostname_matches": true,
            "protocol_version": "TLSv1_3",
            "alpn": "h2",
            "subject": "CN=example.com",
            "issuer": "CN=issuer",
            "serial_number": "01",
            "valid_from_unix": 1,
            "valid_until_unix": 2,
            "subject_alt_names": ["example.com"],
            "public_key_algorithm": "1.2.840.10045.2.1",
            "signature_algorithm": "1.2.840.10045.4.3.2",
            "errors": []
        });
        let observation: TlsObservation =
            serde_json::from_value(old).unwrap_or_else(|error| panic!("{error}"));

        assert!(observation.cipher_suite.is_none());
        assert!(observation.certificate_chain_length.is_none());
        assert!(observation.leaf_certificate_sha256.is_none());
        assert!(observation.public_key_bits.is_none());
        assert!(!observation.subject_alt_names_truncated);
    }

    #[tokio::test]
    async fn reports_self_signed_certificate_validation_failure() {
        let (_, acceptor, _) = fixture(vec!["localhost".to_owned()]);
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
        let observations = analyze_tls(
            &[service(address, ServiceKind::Https)],
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
