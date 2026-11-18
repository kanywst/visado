//! Compact JWS handling for AATs and PoP JWTs (§3.5), and holder keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use wimsey_jose::{Algorithm, Jwk, SIGNATURE_LEN, VerifyingKey};

use crate::json::{self, Value, write_jcs_string};

/// The prefix of a JWK Thumbprint URI (RFC 9278) for SHA-256.
pub(crate) const THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/// JWK members that carry private or symmetric key material.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The algorithms on the allowlist (§9.11). `EdDSA` is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    Ed25519,
    Es256,
}

impl Alg {
    fn parse(alg: &str) -> Option<Self> {
        match alg {
            "Ed25519" => Some(Self::Ed25519),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// Whether `key`'s type and curve fit this algorithm.
    pub(crate) fn fits(self, key: &VerifyingKey) -> bool {
        match self {
            Self::Ed25519 => matches!(key.algorithm(), Algorithm::Ed25519 | Algorithm::EdDsa),
            Self::Es256 => key.algorithm() == Algorithm::Es256,
        }
    }
}

/// The three parts of a compact JWS.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Compact<'a> {
    pub(crate) signing_input: &'a str,
    pub(crate) header: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) signature: &'a str,
}

pub(crate) fn split(token: &str) -> Option<Compact<'_>> {
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

pub(crate) fn b64(part: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(part).ok()
}

/// What the protected header contributed.
#[derive(Debug)]
pub(crate) struct Header {
    pub(crate) alg: Alg,
    pub(crate) kid: Option<String>,
}

/// Checks the protected header (§3.5; §8 steps 3a, 4a and 7a): `alg` on the
/// allowlist, `typ` exactly `typ`, and no `crit`, since this implementation
/// understands no extension header parameter. Key-bearing parameters such as
/// `jwk` are ignored.
pub(crate) fn header(part: &str, typ: &str) -> Option<Header> {
    let value = json::parse(&b64(part)?).ok()?;
    value.as_object()?;
    let alg = Alg::parse(value.get("alg")?.as_str()?)?;
    if value.get("typ")?.as_str()? != typ {
        return None;
    }
    if value.get("crit").is_some() {
        return None;
    }
    let kid = match value.get("kid") {
        None => None,
        Some(v) => Some(v.as_str()?.to_owned()),
    };
    Some(Header { alg, kid })
}

/// Verifies the signature over the signing input exactly as presented.
pub(crate) fn signature_ok(key: &VerifyingKey, jws: Compact<'_>) -> bool {
    match b64(jws.signature) {
        Some(sig) if sig.len() == SIGNATURE_LEN => {
            key.verify(jws.signing_input.as_bytes(), &sig).is_ok()
        }
        _ => false,
    }
}

/// `base64url-nopad(SHA-256(input))`, as for `par_hash` and `aat_hash`.
pub(crate) fn hash(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// A holder key from a `cnf.jwk`.
#[derive(Debug, Clone)]
pub(crate) struct HolderKey {
    pub(crate) key: VerifyingKey,
    pub(crate) thumbprint: String,
}

/// Reads `cnf.jwk` as a public Ed25519 or P-256 key (§8 steps 3l and 4b2).
pub(crate) fn holder_key(cnf: Option<&Value>) -> Option<HolderKey> {
    let jwk = cnf?.get("jwk")?;
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
pub(crate) fn key_thumbprint(key: &VerifyingKey) -> String {
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
