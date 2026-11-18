//! Fixed-key fixtures for visado tests. Not for production use.

#![allow(clippy::missing_panics_doc)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, Jwk, SigningKey, VerifyingKey};
use wimsey_wit::{Confirmation, WitClaims};
use wimsey_wpt::WptClaims;

/// A fixed time used across tests.
pub const NOW: u64 = 1_800_000_000;

/// The trust domain used across tests.
pub const TRUST_DOMAIN: &str = "td.example";

/// The OAuth issuer used across tests.
pub const OAUTH_ISSUER: &str = "https://idp.example";

/// The WIT issuer's signing key.
#[must_use]
pub fn wit_issuer_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x31; 32])
}

/// A workload's proof-of-possession key, derived from `seed`.
#[must_use]
pub fn pop_key(seed: u8) -> SigningKey {
    SigningKey::from_ed25519_seed(&[seed; 32])
}

/// The OAuth issuer's signing key (`EdDSA`).
///
/// # Panics
///
/// Never: the relabel from `Ed25519` to `EdDSA` is always valid.
#[must_use]
pub fn oauth_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x41; 32])
        .with_algorithm(Algorithm::EdDsa)
        .expect("EdDSA relabel")
}

/// The OAuth issuer's JWKS as JSON, with `kid` "idp-1".
#[must_use]
pub fn oauth_jwks() -> Value {
    let mut jwk = serde_json::to_value(Jwk::from_verifying_key(&oauth_key().verifying_key()))
        .expect("jwk serializes");
    jwk["kid"] = json!("idp-1");
    jwk["use"] = json!("sig");
    json!({ "keys": [jwk] })
}

/// The WIT issuer's verifying key.
#[must_use]
pub fn wit_issuer_verifying_key() -> VerifyingKey {
    wit_issuer_key().verifying_key()
}

/// A WIT for `workload` (a path in [`TRUST_DOMAIN`]) bound to `pop`, valid for
/// 10 minutes from [`NOW`], with `kid` "wit-1".
///
/// # Panics
///
/// If `workload` does not make a valid identifier.
#[must_use]
pub fn wit(workload: &str, pop: &SigningKey) -> String {
    wit_for(&format!("spiffe://{TRUST_DOMAIN}/{workload}"), pop)
}

/// A WIT for the full workload identifier `id`, signed by the test issuer.
///
/// # Panics
///
/// If `id` is not a valid identifier.
#[must_use]
pub fn wit_for(id: &str, pop: &SigningKey) -> String {
    wit_at(id, pop, NOW)
}

/// A WIT for `id` bound to `pop`, issued at `now` and valid for 10 minutes.
#[must_use]
pub fn wit_at(id: &str, pop: &SigningKey, now: u64) -> String {
    let claims = WitClaims {
        iss: Some("https://wit.td.example".into()),
        sub: WorkloadIdentifier::parse(id).expect("valid identifier"),
        iat: Some(now - 5),
        exp: now + 600,
        jti: None,
        cnf: Confirmation {
            jwk: Jwk::from_verifying_key(&pop.verifying_key()),
        },
    };
    wimsey_wit::issue(&claims, Some("wit-1"), &wimsey_issuer_key()).expect("wit issues")
}

fn wimsey_issuer_key() -> SigningKey {
    wit_issuer_key()
}

/// A WPT over `wit` for `audience`, with `jti`, optionally binding a Txn-Token
/// and a user token carried in `user_header`.
///
/// # Panics
///
/// Never for valid inputs.
#[must_use]
pub fn wpt(
    wit: &str,
    pop: &SigningKey,
    audience: &str,
    jti: &str,
    txn_token: Option<&str>,
    user: Option<(&str, &str)>,
) -> String {
    wpt_at(wit, pop, audience, jti, txn_token, user, NOW)
}

/// Like [`wpt`], expiring 60 seconds after `now`.
#[must_use]
pub fn wpt_at(
    wit: &str,
    pop: &SigningKey,
    audience: &str,
    jti: &str,
    txn_token: Option<&str>,
    user: Option<(&str, &str)>,
    now: u64,
) -> String {
    let claims = WptClaims {
        aud: audience.into(),
        exp: now + 60,
        jti: jti.into(),
        wth: wimsey_wpt::wit_thumbprint(wit),
        tth: txn_token.map(wimsey_wpt::txn_token_thumbprint),
        oth: user.map(|(header, value)| {
            std::iter::once(wimsey_wpt::other_token_entry(header, value)).collect()
        }),
    };
    wimsey_wpt::issue(&claims, pop).expect("wpt issues")
}

/// An access token from [`OAUTH_ISSUER`] for `sub`, with `client_id`, `scope`
/// and `aud`, expiring at `exp`.
#[must_use]
pub fn access_token(sub: &str, client_id: &str, scope: &str, aud: &str, exp: u64) -> String {
    signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": sub, "aud": aud, "client_id": client_id,
        "scope": scope, "iat": NOW - 5, "exp": exp, "jti": format!("at-{sub}-{exp}"),
    }))
}

/// An access token with exactly `claims`, signed by the test OAuth issuer.
#[must_use]
pub fn signed_access_token(claims: &Value) -> String {
    let header = json!({ "typ": "at+jwt", "alg": "EdDSA", "kid": "idp-1" });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json"));
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json"));
    let input = format!("{h}.{c}");
    let sig = URL_SAFE_NO_PAD.encode(oauth_key().sign(input.as_bytes()));
    format!("{input}.{sig}")
}
