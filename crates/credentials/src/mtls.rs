//! mTLS with a Workload Identity Certificate (a SPIFFE X.509-SVID), per
//! draft-ietf-wimse-mutual-tls.
//!
//! The certificate comes from the proxy that terminated TLS (Envoy's
//! `source.certificate`), which has already checked that the client holds its
//! private key. This module checks the certificate itself: one CA per trust
//! domain, no chain building, no revocation.

use base64::{Engine, engine::general_purpose::STANDARD};
use wimsey_jose::{Algorithm, VerifyingKey};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519};
use x509_parser::prelude::FromDer;

use crate::MAX_CREDENTIAL_LEN;
use crate::error::AuthError;

/// The CA that issues X.509-SVIDs for one trust domain.
#[derive(Debug, Clone)]
pub struct X509Bundle {
    trust_domain: String,
    ca_der: Vec<u8>,
}

impl X509Bundle {
    /// The CA certificate `ca_pem` (one PEM `CERTIFICATE` block) for
    /// `trust_domain`. Leaf certificates must be signed directly by it, with an
    /// Ed25519 or P-256 key.
    ///
    /// # Errors
    ///
    /// A description of the problem if `ca_pem` is not exactly one certificate.
    pub fn from_pem(trust_domain: impl Into<String>, ca_pem: &str) -> Result<Self, String> {
        let der = pem_certificate(ca_pem.as_bytes())
            .ok_or("expected exactly one PEM CERTIFICATE block")?;
        Self::from_der(trust_domain, der)
    }

    /// The DER-encoded CA certificate for `trust_domain`.
    ///
    /// # Errors
    ///
    /// A description of the problem if `ca_der` is not one certificate.
    pub fn from_der(trust_domain: impl Into<String>, ca_der: Vec<u8>) -> Result<Self, String> {
        match X509Certificate::from_der(&ca_der) {
            Ok(([], _)) => Ok(Self {
                trust_domain: trust_domain.into(),
                ca_der,
            }),
            _ => Err("not a DER certificate".into()),
        }
    }
}

/// A verified peer certificate.
pub(crate) struct VerifiedPeer {
    /// The workload identifier from the URI SAN.
    pub(crate) id: String,
    /// The certificate's public key, when it is Ed25519 or P-256.
    pub(crate) key: Option<VerifyingKey>,
}

/// Verifies the peer certificate `encoded` (URL-encoded PEM, as Envoy sends it)
/// against the CA for the trust domain in its URI SAN. The unverified SAN only
/// selects the CA; the signature is then checked against it.
pub(crate) fn verify(
    bundles: &[X509Bundle],
    encoded: &str,
    now: u64,
) -> Result<VerifiedPeer, AuthError> {
    let invalid = |e: wimsey_mtls::MtlsError| AuthError::Certificate(e.to_string());
    if encoded.len() > MAX_CREDENTIAL_LEN {
        return Err(AuthError::TooLarge);
    }
    let pem =
        percent_decode(encoded).ok_or_else(|| AuthError::Certificate("not URL-encoded".into()))?;
    let der = pem_certificate(&pem)
        .ok_or_else(|| AuthError::Certificate("not one PEM certificate".into()))?;
    let claimed = wimsey_mtls::workload_identifier(&der).map_err(invalid)?;
    let bundle = bundles
        .iter()
        .find(|b| b.trust_domain == claimed.trust_domain())
        .ok_or(AuthError::CertificateUntrustedDomain)?;
    let id = wimsey_mtls::verify(&der, &bundle.ca_der, now).map_err(invalid)?;
    if id.trust_domain() != bundle.trust_domain {
        return Err(AuthError::CertificateUntrustedDomain);
    }
    let Ok(([], leaf)) = X509Certificate::from_der(&der) else {
        return Err(AuthError::Certificate("malformed".into()));
    };
    check_leaf(&leaf)?;
    Ok(VerifiedPeer {
        id: id.as_str().to_owned(),
        key: leaf_key(&leaf),
    })
}

/// X.509-SVID leaf rules: not a CA, and, if key usage is present, it allows
/// signatures and not certificate or CRL signing.
fn check_leaf(leaf: &X509Certificate<'_>) -> Result<(), AuthError> {
    let malformed = |_| AuthError::Certificate("malformed extensions".into());
    if leaf
        .basic_constraints()
        .map_err(malformed)?
        .is_some_and(|bc| bc.value.ca)
    {
        return Err(AuthError::Certificate("leaf is a CA".into()));
    }
    if let Some(usage) = leaf.key_usage().map_err(malformed)? {
        let usage = usage.value;
        if !usage.digital_signature() || usage.key_cert_sign() || usage.crl_sign() {
            return Err(AuthError::Certificate("key usage".into()));
        }
    }
    Ok(())
}

/// The leaf's public key, for the algorithms a proof of possession can use.
fn leaf_key(leaf: &X509Certificate<'_>) -> Option<VerifyingKey> {
    let spki = leaf.public_key();
    if spki.subject_public_key.unused_bits != 0 {
        return None;
    }
    let raw = spki.subject_public_key.data.as_ref();
    let algorithm = &spki.algorithm;
    if algorithm.algorithm == OID_SIG_ED25519 {
        return VerifyingKey::from_raw_bytes(Algorithm::Ed25519, raw).ok();
    }
    let curve = algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok());
    if algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY && curve == Some(OID_EC_P256) {
        return VerifyingKey::from_raw_bytes(Algorithm::Es256, raw).ok();
    }
    None
}

/// Percent-decodes `s`. `+` stays `+`. `None` for a malformed escape.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Some(out)
}

/// The DER of the single `CERTIFICATE` block in `pem`. A chain, another block
/// type or text around the block is refused.
fn pem_certificate(pem: &[u8]) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(pem).ok()?.trim();
    let body = text.strip_prefix(BEGIN)?.strip_suffix(END)?;
    if body.contains('-') {
        return None;
    }
    let base64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(base64).ok()
}

#[cfg(test)]
mod tests {
    use super::{check_leaf, pem_certificate, percent_decode};
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    #[test]
    fn a_ca_certificate_is_not_a_leaf() {
        let ca = wimsey_mtls::WorkloadCa::generate(0, 4_000_000_000).unwrap();
        let (_, cert) = X509Certificate::from_der(ca.certificate_der()).unwrap();
        assert!(check_leaf(&cert).is_err());
    }

    #[test]
    fn percent_decoding_is_strict() {
        assert_eq!(percent_decode("a%2Fb+c%0A").unwrap(), b"a/b+c\n");
        assert!(percent_decode("%").is_none());
        assert!(percent_decode("%2").is_none());
        assert!(percent_decode("%+1").is_none());
        assert!(percent_decode("%zz").is_none());
    }

    #[test]
    fn only_one_certificate_block() {
        let one = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_certificate(one.as_bytes()).unwrap(), [0, 1, 2]);
        let two = format!("{one}{one}");
        assert!(pem_certificate(two.as_bytes()).is_none());
        let key = one.replace("CERTIFICATE", "PRIVATE KEY");
        assert!(pem_certificate(key.as_bytes()).is_none());
        assert!(
            pem_certificate(b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----")
                .is_none()
        );
    }
}
