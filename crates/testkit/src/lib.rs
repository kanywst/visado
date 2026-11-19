//! Fixed-key fixtures for visado tests. Not for production use.

#![allow(clippy::missing_panics_doc, clippy::too_many_arguments)]

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

/// The AAT trust anchor's signing key.
#[must_use]
pub fn aat_anchor_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x61; 32])
}

/// The AAT trust anchor's issuer.
pub const AAT_ISSUER: &str = "https://aat.td.example";

fn sign_aat(typ: &str, payload: &Value, key: &SigningKey) -> String {
    // serde_json maps keep keys sorted and print without whitespace, which is
    // the JCS form for the strings and integers used here.
    let header = json!({ "alg": "Ed25519", "typ": typ });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json"));
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("json"));
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    format!("{input}.{sig}")
}

fn signing_input_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let input = token.rsplit_once('.').map_or(token, |(i, _)| i);
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

fn aat_detail(tools: &Value) -> Value {
    json!([{ "type": "attenuating_agent_token", "tools": tools }])
}

/// A root AAT from [`AAT_ISSUER`] delegating `tools` to `holder`, for the
/// enforcement point `audience`.
#[must_use]
pub fn aat_root(
    jti: &str,
    holder: &SigningKey,
    tools: &Value,
    now: u64,
    max_depth: u32,
    audience: &str,
) -> String {
    let payload = json!({
        "jti": jti, "iss": AAT_ISSUER, "aud": audience, "iat": now, "exp": now + 600,
        "del_depth": 0, "del_max_depth": max_depth,
        "cnf": { "jwk": Jwk::from_verifying_key(&holder.verifying_key()) },
        "authorization_details": aat_detail(tools),
    });
    let mut payload = payload;
    if let Some(jwk) = payload["cnf"]["jwk"].as_object_mut() {
        jwk.remove("alg");
    }
    sign_aat("aat+jwt", &payload, &aat_anchor_key())
}

/// A child AAT of `parent` (held by `parent_holder`) delegating `tools` to
/// `holder`, at depth `depth`.
#[must_use]
pub fn aat_child(
    jti: &str,
    parent: &str,
    parent_holder: &SigningKey,
    holder: &SigningKey,
    tools: &Value,
    depth: u32,
    max_depth: u32,
    now: u64,
) -> String {
    let iss = format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        visado_chain_aat::jwk_thumbprint(&parent_holder.verifying_key())
    );
    let mut payload = json!({
        "jti": jti, "iss": iss, "iat": now, "exp": now + 300,
        "del_depth": depth, "del_max_depth": max_depth,
        "par_hash": signing_input_hash(parent),
        "cnf": { "jwk": Jwk::from_verifying_key(&holder.verifying_key()) },
        "authorization_details": aat_detail(tools),
    });
    if let Some(jwk) = payload["cnf"]["jwk"].as_object_mut() {
        jwk.remove("alg");
    }
    sign_aat("aat+jwt", &payload, parent_holder)
}

/// A proof of possession by `holder` of the leaf token `leaf` (whose `jti` is
/// `leaf_jti`), for calling `tool` with `args` at `audience`.
#[must_use]
pub fn aat_pop(
    jti: &str,
    leaf: &str,
    leaf_jti: &str,
    holder: &SigningKey,
    tool: &str,
    args: &Value,
    audience: &str,
    now: u64,
) -> String {
    let payload = json!({
        "jti": jti, "iat": now, "aat_id": leaf_jti, "aat_hash": signing_input_hash(leaf),
        "aat_tool": tool, "hta": args, "aat_aud": audience,
    });
    sign_aat("aat-pop+jwt", &payload, holder)
}

/// The asor trust anchor's signing key.
#[must_use]
pub fn asor_anchor_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x71; 32])
}

/// The asor trust anchor's issuer.
pub const ASOR_ISSUER: &str = "https://asor.td.example";

/// The Principal of the asor test chains.
pub const ASOR_PRINCIPAL: &str = "user:alice";

/// Signs `header` and `payload`, both given as the exact JSON text to encode,
/// with the asor anchor key.
#[must_use]
pub fn asor_sign_raw(header: &str, payload: &str) -> String {
    let h = URL_SAFE_NO_PAD.encode(header);
    let p = URL_SAFE_NO_PAD.encode(payload);
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(asor_anchor_key().sign(input.as_bytes()));
    format!("{input}.{sig}")
}

/// A Delegation Token with exactly `payload`, signed by the asor anchor.
/// `serde_json` maps keep keys sorted and print without whitespace, which is
/// the JCS form for the strings and integers used here.
#[must_use]
pub fn asor_sign(payload: &Value) -> String {
    asor_sign_raw(
        r#"{"alg":"Ed25519","typ":"at+jwt"}"#,
        &serde_json::to_string(payload).expect("json"),
    )
}

/// The claims of a root Delegation Token from [`ASOR_ISSUER`] for
/// [`ASOR_PRINCIPAL`], acted on by `client_id` holding `holder`, granting
/// `scopes` under `constraints`, for `audience`, valid 10 minutes from `now`.
#[must_use]
pub fn asor_root_claims(
    jti: &str,
    client_id: &str,
    holder: &SigningKey,
    scopes: &Value,
    constraints: &Value,
    audience: &str,
    now: u64,
    max_depth: u32,
) -> Value {
    json!({
        "iss": ASOR_ISSUER, "sub": ASOR_PRINCIPAL, "client_id": client_id, "aud": audience,
        "iat": now, "exp": now + 600, "jti": jti, "del_depth": 0, "del_max_depth": max_depth,
        "cnf": { "jkt": visado_chain_aat::jwk_thumbprint(&holder.verifying_key()) },
        "authorization_details": [
            { "type": "agent_delegation", "scopes": scopes, "constraints": constraints }
        ],
    })
}

/// The claims of a child of `parent` at `depth`, like [`asor_root_claims`]
/// but valid 5 minutes and committing to `parent` with `par_hash`.
#[must_use]
pub fn asor_child_claims(
    jti: &str,
    client_id: &str,
    parent: &str,
    holder: &SigningKey,
    depth: u32,
    scopes: &Value,
    constraints: &Value,
    audience: &str,
    now: u64,
) -> Value {
    json!({
        "iss": ASOR_ISSUER, "sub": ASOR_PRINCIPAL, "client_id": client_id, "aud": audience,
        "iat": now, "exp": now + 300, "jti": jti, "del_depth": depth,
        "par_hash": signing_input_hash(parent),
        "cnf": { "jkt": visado_chain_aat::jwk_thumbprint(&holder.verifying_key()) },
        "authorization_details": [
            { "type": "agent_delegation", "scopes": scopes, "constraints": constraints }
        ],
    })
}

/// A DPoP proof (RFC 9449) by `holder` for `method` on `uri`, presenting the
/// access token `token`.
#[must_use]
pub fn dpop_proof(
    holder: &SigningKey,
    method: &str,
    uri: &str,
    token: &str,
    jti: &str,
    now: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut jwk = serde_json::to_value(Jwk::from_verifying_key(&holder.verifying_key()))
        .expect("jwk serializes");
    if let Some(jwk) = jwk.as_object_mut() {
        jwk.remove("alg");
    }
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": jwk });
    let payload = json!({
        "jti": jti, "htm": method, "htu": uri, "iat": now,
        "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
    });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json"));
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("json"));
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(holder.sign(input.as_bytes()));
    format!("{input}.{sig}")
}
