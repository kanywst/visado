//! Step 6: the DPoP proof (RFC 9449) that the presenter holds the leaf key.

use visado_chain::dpop::{self, Expected};
use visado_chain::replay::ReplayCache;

pub use visado_chain::dpop::{HttpRequest, TYP as DPOP_TYP};

/// The `alg` values a proof may use: fully specified, as for the tokens.
const ALGS: &[&str] = &["Ed25519", "ES256"];

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
    let expected = Expected {
        jkt,
        access_token: leaf_token,
        algs: ALGS,
        max_size: window.max_size,
        iat_window: window.iat_window,
        nonces: None,
    };
    let proof = dpop::verify(proof, &expected, request, now).map_err(dpop::Rejection::reason)?;
    if let Some(cache) = replay {
        let until = proof.iat.saturating_add(window.iat_window);
        if !cache.check_and_record(&format!("{jkt}:{}", proof.jti), until, now) {
            return Err("DPoP jti already accepted");
        }
    }
    Ok(Proof { jti: proof.jti })
}
