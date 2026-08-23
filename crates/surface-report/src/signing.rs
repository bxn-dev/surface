use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    pub format: String,
    pub version: String,
    pub algorithm: String,
    pub key_id: String,
    pub sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    MalformedEnvelope,
    UnknownAlgorithm,
    MalformedKey,
    DigestMismatch,
    KeyIdMismatch,
    InvalidSignature,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MalformedEnvelope => "signature envelope is malformed",
            Self::UnknownAlgorithm => "signature algorithm is unsupported",
            Self::MalformedKey => "public key is malformed",
            Self::DigestMismatch => "report digest does not match signature envelope",
            Self::KeyIdMismatch => "signature key ID does not match public key",
            Self::InvalidSignature => "report signature is invalid",
        })
    }
}
impl std::error::Error for VerificationError {}

/// Signs exact report bytes with a raw 32-byte Ed25519 private key.
///
/// # Errors
///
/// Returns an error when envelope serialization fails.
pub fn sign_bytes(report: &[u8], private_key: &[u8; 32]) -> Result<String, serde_json::Error> {
    let key = SigningKey::from_bytes(private_key);
    let public_key = key.verifying_key().to_bytes();
    let envelope = SignatureEnvelope {
        format: "surface-detached-signature".to_owned(),
        version: "1.0".to_owned(),
        algorithm: "Ed25519".to_owned(),
        key_id: hex(&Sha256::digest(public_key))[..32].to_owned(),
        sha256: hex(&Sha256::digest(report)),
        signature: hex(&key.sign(report).to_bytes()),
    };
    serde_json::to_string_pretty(&envelope)
}

/// Verifies exact report bytes against a detached signature envelope.
///
/// # Errors
///
/// Distinguishes malformed envelopes/keys, unsupported algorithms, digest mismatch, and invalid signatures.
pub fn verify_bytes(
    report: &[u8],
    envelope_json: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VerificationError> {
    let envelope: SignatureEnvelope =
        serde_json::from_slice(envelope_json).map_err(|_| VerificationError::MalformedEnvelope)?;
    if envelope.format != "surface-detached-signature" || envelope.version != "1.0" {
        return Err(VerificationError::MalformedEnvelope);
    }
    if envelope.algorithm != "Ed25519" {
        return Err(VerificationError::UnknownAlgorithm);
    }
    if envelope.sha256 != hex(&Sha256::digest(report)) {
        return Err(VerificationError::DigestMismatch);
    }
    if envelope.key_id != hex(&Sha256::digest(public_key))[..32] {
        return Err(VerificationError::KeyIdMismatch);
    }
    let signature =
        decode_hex::<64>(&envelope.signature).ok_or(VerificationError::MalformedEnvelope)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| VerificationError::MalformedKey)?;
    key.verify(report, &Signature::from_bytes(&signature))
        .map_err(|_| VerificationError::InvalidSignature)
}

/// Decodes a fixed-size hexadecimal key file after trimming ASCII whitespace.
#[must_use]
pub fn decode_key<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    let value = std::str::from_utf8(value).ok()?.trim();
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(output)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
const fn digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{SignatureEnvelope, VerificationError, sign_bytes, verify_bytes};

    #[test]
    fn exact_bytes_are_signed_and_changes_fail() {
        let private = [7; 32];
        let public = SigningKey::from_bytes(&private).verifying_key().to_bytes();
        let envelope = sign_bytes(b"report", &private).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            verify_bytes(b"report", envelope.as_bytes(), &public),
            Ok(())
        );
        assert_eq!(
            verify_bytes(b"changed", envelope.as_bytes(), &public),
            Err(VerificationError::DigestMismatch)
        );
        let wrong = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_bytes(b"report", envelope.as_bytes(), &wrong),
            Err(VerificationError::KeyIdMismatch)
        );
        let mut tampered: SignatureEnvelope =
            serde_json::from_str(&envelope).unwrap_or_else(|error| panic!("{error}"));
        tampered.key_id = "00000000000000000000000000000000".to_owned();
        let tampered = serde_json::to_vec(&tampered).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            verify_bytes(b"report", &tampered, &public),
            Err(VerificationError::KeyIdMismatch)
        );
    }
}
