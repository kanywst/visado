//! DPoP proofs (RFC 9449), as an asor leaf holder and a DPoP-bound OAuth
//! client present them.
//!
//! [`verify`] runs the proof checks of RFC 9449 §4.3 that need no state:
//! the JWS and its header, the key thumbprint, `htm`, `htu`, `iat` and
//! `ath`. Recording `jti` is the caller's, so each caller keeps its own
//! replay cache and key.

use crate::jose::{self, HolderKey};
use crate::json::{self, Value};
use wimsey_jose::Algorithm;

/// The JOSE `typ` of a DPoP proof (RFC 9449 §4.2).
pub const TYP: &str = "dpop+jwt";

/// The longest proof `jti` accepted, in bytes.
pub const MAX_JTI_LEN: usize = 256;

/// The HTTP request a DPoP proof must be bound to.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    /// The method, such as `POST`.
    pub method: &'a str,
    /// The target URI, `scheme://authority/path`. A query or fragment is
    /// ignored, as RFC 9449 §4.3 ignores them in `htu`.
    pub uri: &'a str,
}

/// What a proof must match.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The access token's `cnf.jkt`.
    pub jkt: &'a str,
    /// The access token the proof is presented with; `ath` must be its hash.
    pub access_token: &'a str,
    /// The `alg` values accepted. Only `Ed25519`, `EdDSA` (with an Ed25519
    /// key) and `ES256` are understood; anything else never matches.
    pub algs: &'a [&'a str],
    /// The largest proof accepted, in bytes.
    pub max_size: usize,
    /// Seconds either side of now within which `iat` must fall.
    pub iat_window: i64,
}

/// What a valid proof established.
#[derive(Debug, Clone)]
pub struct Proof {
    /// `jti`, at most [`MAX_JTI_LEN`] bytes.
    pub jti: String,
    /// `iat`, within the window.
    pub iat: i64,
    /// The proof key, whose thumbprint is the expected `jkt`.
    pub key: HolderKey,
}

/// Why a proof was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The proof itself is invalid (RFC 9449 `invalid_dpop_proof`).
    Proof(&'static str),
    /// The proof is valid but made with a key other than the token's
    /// `cnf.jkt` (RFC 9449 §7.1 `invalid_token`).
    KeyMismatch,
}

impl Rejection {
    /// A short reason for logs and audit records.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Proof(reason) => reason,
            Self::KeyMismatch => "DPoP key is not the token's cnf.jkt",
        }
    }
}

/// Checks `proof` against `expected` and `request` at `now`. The signature
/// is checked before the key is compared with `cnf.jkt`, so an unsigned
/// proof is never reported as a key mismatch.
///
/// # Errors
///
/// The first check that failed.
pub fn verify(
    proof: &str,
    expected: &Expected<'_>,
    request: &HttpRequest<'_>,
    now: i64,
) -> Result<Proof, Rejection> {
    let bad = Rejection::Proof;
    if proof.len() > expected.max_size {
        return Err(bad("DPoP proof too large"));
    }
    let jws = jose::split(proof).ok_or(bad("DPoP proof is not a compact JWS"))?;
    let header = jose::b64(jws.header)
        .and_then(|h| json::parse(&h).ok())
        .ok_or(bad("DPoP header does not parse"))?;
    let key = header_key(&header, expected.algs).ok_or(bad("bad DPoP header"))?;
    if !jose::signature_ok(&key.key, jws) {
        return Err(bad("DPoP signature does not verify"));
    }
    if key.thumbprint != expected.jkt {
        return Err(Rejection::KeyMismatch);
    }
    let claims = jose::b64(jws.payload)
        .and_then(|p| json::parse(&p).ok())
        .filter(|c| c.as_object().is_some())
        .ok_or(bad("DPoP claims do not parse"))?;
    let text = |name| claims.get(name).and_then(Value::as_str);
    let jti = text("jti")
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI_LEN)
        .ok_or(bad("bad DPoP jti"))?;
    if text("htm") != Some(request.method) {
        return Err(bad("DPoP htm does not match the request method"));
    }
    let htu = text("htu").and_then(normalize_uri);
    if htu.is_none() || htu != normalize_uri(request.uri) {
        return Err(bad("DPoP htu does not match the request URI"));
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_integer)
        .ok_or(bad("bad DPoP iat"))?;
    if iat < now.saturating_sub(expected.iat_window)
        || iat > now.saturating_add(expected.iat_window)
    {
        return Err(bad("DPoP iat outside the accepted window"));
    }
    // Every proof checked here comes with an access token, so `ath` is
    // required (RFC 9449 §4.2) and binds the proof to the token presented.
    if text("ath") != Some(jose::hash(expected.access_token).as_str()) {
        return Err(bad("DPoP ath does not match the access token"));
    }
    Ok(Proof {
        jti: jti.to_owned(),
        iat,
        key,
    })
}

/// The protected header: `typ` `dpop+jwt`, an accepted `alg` fitting the
/// public `jwk`, and no `crit`. A JWK with private or symmetric members is
/// refused by [`jose::public_jwk`].
fn header_key(header: &Value, algs: &[&str]) -> Option<HolderKey> {
    header.as_object()?;
    if header.get("typ")?.as_str()? != TYP || header.get("crit").is_some() {
        return None;
    }
    let alg = header.get("alg")?.as_str()?;
    if !algs.contains(&alg) {
        return None;
    }
    let key = jose::public_jwk(header.get("jwk")?)?;
    let fits = match alg {
        "Ed25519" | "EdDSA" => {
            matches!(key.key.algorithm(), Algorithm::Ed25519 | Algorithm::EdDsa)
        }
        "ES256" => key.key.algorithm() == Algorithm::Es256,
        _ => false,
    };
    fits.then_some(key)
}

/// `htu` as compared (RFC 9449 §4.3 item 9): query and fragment removed,
/// then the syntax- and scheme-based normalization of RFC 3986 §6.2.2 and
/// §6.2.3 that cannot change which resource is named: scheme and host
/// lowercased, the default port dropped, an empty path made `/`. Percent
/// encodings are left as they are. `None` unless the scheme is `http` or
/// `https` and there is an authority.
#[must_use]
pub fn normalize_uri(uri: &str) -> Option<String> {
    let uri = uri.split(['?', '#']).next().unwrap_or(uri);
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => return None,
    };
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let mut authority = authority.to_ascii_lowercase();
    if authority.ends_with(default_port) {
        authority.truncate(authority.len() - default_port.len());
    }
    let path = if path.is_empty() { "/" } else { path };
    Some(format!("{scheme}://{authority}{path}"))
}

#[cfg(test)]
mod tests {
    use super::normalize_uri;

    #[test]
    fn htu_normalization() {
        let n = |u| normalize_uri(u);
        assert_eq!(
            n("HTTPS://API.Example:443/a/B?x=1#f").as_deref(),
            Some("https://api.example/a/B")
        );
        assert_eq!(n("http://h:80").as_deref(), Some("http://h/"));
        assert_eq!(n("https://h:8443/p").as_deref(), Some("https://h:8443/p"));
        assert_eq!(n("https://h:80/p").as_deref(), Some("https://h:80/p"));
        assert_ne!(n("https://h/a"), n("https://h/A"));
        assert_eq!(n("ftp://h/"), None);
        assert_eq!(n("/relative"), None);
        assert_eq!(n("https:///p"), None);
        assert_eq!(n("https://user@h/p"), None);
    }
}
