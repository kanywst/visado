//! Compact JWS parts, SHA-256 digests and public JWKs, as the chain formats
//! use them.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use wimsey_jose::{Algorithm, Jwk, SIGNATURE_LEN, VerifyingKey};

use crate::json::{Value, write_jcs_string};

/// The prefix of a JWK Thumbprint URI (RFC 9278) for SHA-256.
pub const THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/// JWK members that carry private or symmetric key material.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The three parts of a compact JWS, borrowed from the token.
#[derive(Debug, Clone, Copy)]
pub struct Compact<'a> {
    /// `header.payload`: the JWS Signing Input (RFC 7515 §5.1).
    pub signing_input: &'a str,
    /// The base64url protected header.
    pub header: &'a str,
    /// The base64url payload.
    pub payload: &'a str,
    /// The base64url signature.
    pub signature: &'a str,
}

/// Splits a compact JWS into its three parts. `None` unless there are
/// exactly three.
#[must_use]
pub fn split(token: &str) -> Option<Compact<'_>> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some(Compact {
        signing_input: &token[..header.len() + 1 + payload.len()],
        header,
        payload,
        signature,
    })
}

/// Decodes unpadded base64url.
#[must_use]
pub fn b64(part: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(part).ok()
}

/// Verifies an Ed25519 or ES256 signature over the signing input exactly as
/// presented.
#[must_use]
pub fn signature_ok(key: &VerifyingKey, jws: Compact<'_>) -> bool {
    match b64(jws.signature) {
        Some(sig) if sig.len() == SIGNATURE_LEN => {
            key.verify(jws.signing_input.as_bytes(), &sig).is_ok()
        }
        _ => false,
    }
}

/// `base64url-nopad(SHA-256(input))`, as for `par_hash`, `aat_hash` and
/// DPoP `ath`.
#[must_use]
pub fn hash(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// A public key read from a JWK, with its RFC 7638 thumbprint.
#[derive(Debug, Clone)]
pub struct HolderKey {
    /// The key.
    pub key: VerifyingKey,
    /// Its base64url SHA-256 thumbprint.
    pub thumbprint: String,
}

/// Reads `cnf.jwk` as a public Ed25519 or P-256 key.
#[must_use]
pub fn holder_key(cnf: Option<&Value>) -> Option<HolderKey> {
    public_jwk(cnf?.get("jwk")?)
}

/// Reads a JWK as a public Ed25519 (`OKP`) or P-256 (`EC`) key. Rejects a
/// JWK carrying private or symmetric key material.
#[must_use]
pub fn public_jwk(jwk: &Value) -> Option<HolderKey> {
    let members = jwk.as_object()?;
    if members
        .iter()
        .any(|(k, _)| PRIVATE_MEMBERS.contains(&k.as_str()))
    {
        return None;
    }
    let kty = jwk.get("kty")?.as_str()?;
    let crv = jwk.get("crv")?.as_str()?;
    let x = jwk.get("x")?.as_str()?;
    let (alg, y) = match (kty, crv) {
        ("OKP", "Ed25519") => {
            if jwk.get("y").is_some() {
                return None;
            }
            (Algorithm::Ed25519, None)
        }
        ("EC", "P-256") => (Algorithm::Es256, Some(jwk.get("y")?.as_str()?)),
        _ => return None,
    };
    let key = Jwk {
        alg: Some(alg.as_str().to_owned()),
        kty: kty.to_owned(),
        crv: crv.to_owned(),
        x: x.to_owned(),
        y: y.map(ToOwned::to_owned),
    }
    .to_verifying_key()
    .ok()?;
    Some(HolderKey {
        thumbprint: thumbprint(kty, crv, x, y),
        key,
    })
}

/// The RFC 7638 SHA-256 thumbprint of a public key.
#[must_use]
pub fn key_thumbprint(key: &VerifyingKey) -> String {
    let jwk = Jwk::from_verifying_key(key);
    thumbprint(&jwk.kty, &jwk.crv, &jwk.x, jwk.y.as_deref())
}

fn thumbprint(kty: &str, crv: &str, x: &str, y: Option<&str>) -> String {
    // The required members in lexicographic order, no whitespace (RFC 7638 §3).
    let mut s = String::from("{\"crv\":");
    write_jcs_string(crv, &mut s);
    s.push_str(",\"kty\":");
    write_jcs_string(kty, &mut s);
    s.push_str(",\"x\":");
    write_jcs_string(x, &mut s);
    if let Some(y) = y {
        s.push_str(",\"y\":");
        write_jcs_string(y, &mut s);
    }
    s.push('}');
    hash(&s)
}

#[cfg(test)]
mod tests {
    use super::{holder_key, key_thumbprint};
    use crate::json::parse;

    #[test]
    fn thumbprint_matches_rfc_8037_example() {
        // RFC 8037 Appendix A.3.
        let cnf = parse(
            br#"{"jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#,
        )
        .unwrap();
        let key = holder_key(Some(&cnf)).unwrap();
        assert_eq!(
            key.thumbprint,
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(key_thumbprint(&key.key), key.thumbprint);
    }

    #[test]
    fn private_members_are_rejected() {
        let cnf = parse(
            br#"{"jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"AA"}}"#,
        )
        .unwrap();
        assert!(holder_key(Some(&cnf)).is_none());
    }
}
