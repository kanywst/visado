//! Step 6: the DPoP proof (RFC 9449) that the presenter holds the leaf key.

use visado_chain::jose::{self, HolderKey};
use visado_chain::json::{self, Value};
use visado_chain::replay::ReplayCache;
use wimsey_jose::Algorithm;

/// The JOSE `typ` of a DPoP proof (RFC 9449 §4.2).
pub const DPOP_TYP: &str = "dpop+jwt";

/// The longest proof `jti` accepted, in bytes.
const MAX_JTI_LEN: usize = 256;

/// The HTTP request a DPoP proof must be bound to.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    /// The method, such as `POST`.
    pub method: &'a str,
    /// The target URI, `scheme://authority/path`. A query or fragment is
    /// ignored, as RFC 9449 §4.3 ignores them in `htu`.
    pub uri: &'a str,
}

/// What a valid proof established.
pub(crate) struct Proof {
    pub(crate) jti: String,
}

/// Settings for proof checks.
pub(crate) struct Window {
    pub(crate) max_size: usize,
    /// Seconds either side of now within which `iat` must fall.
    pub(crate) iat_window: i64,
}

/// Checks `proof` against the leaf's `cnf.jkt`, the leaf token itself
/// (`ath`) and the request, and records its `jti`. Every failure is
/// `holder_binding_failed`, so this returns only the reason.
pub(crate) fn verify(
    proof: &str,
    jkt: &str,
    leaf_token: &str,
    request: &HttpRequest<'_>,
    window: &Window,
    now: i64,
    replay: Option<&dyn ReplayCache>,
) -> Result<Proof, &'static str> {
    if proof.len() > window.max_size {
        return Err("DPoP proof too large");
    }
    let jws = jose::split(proof).ok_or("DPoP proof is not a compact JWS")?;
    let header = jose::b64(jws.header)
        .and_then(|h| json::parse(&h).ok())
        .ok_or("DPoP header does not parse")?;
    let key = header_key(&header).ok_or("bad DPoP header")?;
    if key.thumbprint != jkt {
        return Err("DPoP key is not the leaf cnf.jkt");
    }
    if !jose::signature_ok(&key.key, jws) {
        return Err("DPoP signature does not verify");
    }
    let claims = jose::b64(jws.payload)
        .and_then(|p| json::parse(&p).ok())
        .filter(|c| c.as_object().is_some())
        .ok_or("DPoP claims do not parse")?;
    let text = |name| claims.get(name).and_then(Value::as_str);
    let jti = text("jti")
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI_LEN)
        .ok_or("bad DPoP jti")?;
    if text("htm") != Some(request.method) {
        return Err("DPoP htm does not match the request method");
    }
    if text("htu").map(without_query) != Some(without_query(request.uri)) {
        return Err("DPoP htu does not match the request URI");
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_integer)
        .ok_or("bad DPoP iat")?;
    if iat < now.saturating_sub(window.iat_window) || iat > now.saturating_add(window.iat_window) {
        return Err("DPoP iat outside the accepted window");
    }
    // The Delegation Token is an access token, so `ath` is required
    // (RFC 9449 §4.2) and binds the proof to the leaf presented.
    if text("ath") != Some(jose::hash(leaf_token).as_str()) {
        return Err("DPoP ath does not match the leaf token");
    }
    if let Some(cache) = replay {
        let until = iat.saturating_add(window.iat_window);
        if !cache.check_and_record(&format!("{jkt}:{jti}"), until, now) {
            return Err("DPoP jti already accepted");
        }
    }
    Ok(Proof {
        jti: jti.to_owned(),
    })
}

/// The protected header: `typ` `dpop+jwt`, `alg` `Ed25519` or `ES256`
/// fitting the public `jwk`, and no `crit`.
fn header_key(header: &Value) -> Option<HolderKey> {
    header.as_object()?;
    if header.get("typ")?.as_str()? != DPOP_TYP || header.get("crit").is_some() {
        return None;
    }
    let key = jose::public_jwk(header.get("jwk")?)?;
    let fits = match header.get("alg")?.as_str()? {
        "Ed25519" => matches!(key.key.algorithm(), Algorithm::Ed25519 | Algorithm::EdDsa),
        "ES256" => key.key.algorithm() == Algorithm::Es256,
        _ => false,
    };
    fits.then_some(key)
}

fn without_query(uri: &str) -> &str {
    uri.split(['?', '#']).next().unwrap_or(uri)
}
