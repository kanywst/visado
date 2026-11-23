//! SPIFFE JWT-SVIDs presented as `Authorization: Bearer`.
//!
//! Per the SPIFFE JWT-SVID specification: `alg` RS256 or ES256 here, `typ`
//! absent or `JWT` / `JOSE`, `sub` a SPIFFE ID, `aud` required and naming this
//! service, `exp` required. Keys come from the trust domain's JWT bundle.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use wimsey_identifier::WorkloadIdentifier;

use crate::error::AuthError;

/// The JWT-SVID signing keys of one trust domain.
#[derive(Debug, Clone)]
pub struct JwtBundle {
    trust_domain: String,
    jwks: JwkSet,
}

impl JwtBundle {
    /// Trusts JWT-SVIDs for `trust_domain` signed by a key in `jwks`.
    #[must_use]
    pub fn new(trust_domain: impl Into<String>, jwks: JwkSet) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            jwks,
        }
    }

    /// The JWT keys of a SPIFFE trust bundle (a JWK set whose keys carry
    /// `use`): every key with `use` `jwt-svid`. X.509 entries are skipped.
    ///
    /// # Errors
    ///
    /// A description of the problem if the bundle is not a JWK set, a
    /// `jwt-svid` key does not parse or has no `kid`, or there is none.
    pub fn from_spiffe_bundle(
        trust_domain: impl Into<String>,
        bundle: &Value,
    ) -> Result<Self, String> {
        let keys = bundle
            .get("keys")
            .and_then(Value::as_array)
            .ok_or("not a JWK set")?;
        let mut jwks = JwkSet { keys: Vec::new() };
        for key in keys {
            if key.get("use").and_then(Value::as_str) != Some("jwt-svid") {
                continue;
            }
            let jwk: Jwk = serde_json::from_value(key.clone()).map_err(|e| e.to_string())?;
            if jwk.common.key_id.is_none() {
                return Err("a jwt-svid key has no kid".into());
            }
            jwks.keys.push(jwk);
        }
        if jwks.keys.is_empty() {
            return Err("no key with use jwt-svid".into());
        }
        Ok(Self::new(trust_domain, jwks))
    }
}

#[derive(Deserialize)]
struct Unverified {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
    #[serde(default)]
    nbf: Option<u64>,
}

const ALGORITHMS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// Whether `token` should be checked as a JWT-SVID rather than an OAuth access
/// token: its `sub` is a SPIFFE ID and its `iss`, if any, is not a configured
/// OAuth issuer. Only routes the token; nothing here is trusted.
pub(crate) fn is_svid(token: &str, oauth_issuers: &[&str]) -> bool {
    let Some(claims) = unverified(token) else {
        return false;
    };
    claims.sub.is_some_and(|sub| sub.starts_with("spiffe://"))
        && !claims
            .iss
            .is_some_and(|iss| oauth_issuers.contains(&iss.as_str()))
}

fn unverified(token: &str) -> Option<Unverified> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Verifies `token` against the bundle for the trust domain in its `sub`, for
/// one of `audiences`. Returns the SPIFFE ID.
pub(crate) fn verify(
    bundles: &[JwtBundle],
    audiences: &[String],
    token: &str,
    now: u64,
    leeway: u64,
) -> Result<String, AuthError> {
    let invalid = |e: jsonwebtoken::errors::Error| AuthError::JwtSvid(crate::error::jwt_reason(&e));
    let header = decode_header(token).map_err(invalid)?;
    if !ALGORITHMS.contains(&header.alg) {
        return Err(AuthError::JwtSvid("algorithm not allowed".into()));
    }
    if header
        .typ
        .as_deref()
        .is_some_and(|typ| typ != "JWT" && typ != "JOSE")
    {
        return Err(AuthError::JwtSvid("typ not allowed".into()));
    }
    let sub = unverified(token)
        .and_then(|c| c.sub)
        .ok_or_else(|| AuthError::JwtSvid("malformed".into()))?;
    let sub = WorkloadIdentifier::parse(&sub).map_err(|e| AuthError::JwtSvid(e.to_string()))?;
    let bundle = bundles
        .iter()
        .find(|b| b.trust_domain == sub.trust_domain())
        .ok_or(AuthError::JwtSvidUntrustedDomain)?;
    let jwk = match &header.kid {
        Some(kid) => bundle.jwks.find(kid),
        None if bundle.jwks.keys.len() == 1 => bundle.jwks.keys.first(),
        None => None,
    }
    .ok_or_else(|| AuthError::JwtSvid("no trusted key".into()))?;
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|u| *u != PublicKeyUse::Other("jwt-svid".into()))
    {
        return Err(AuthError::JwtSvid("key not for JWT-SVIDs".into()));
    }
    if jwk
        .common
        .key_algorithm
        .is_some_and(|alg| alg.to_string().parse::<Algorithm>().ok() != Some(header.alg))
    {
        return Err(AuthError::JwtSvid(
            "algorithm does not match the key".into(),
        ));
    }
    let key = DecodingKey::from_jwk(jwk).map_err(invalid)?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(audiences);
    // Time is checked below against the injected clock.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = ["sub", "aud", "exp"]
        .into_iter()
        .map(String::from)
        .collect();
    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(invalid)?
        .claims;
    if now >= claims.exp.saturating_add(leeway) {
        return Err(AuthError::JwtSvid("expired".into()));
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(leeway))
    {
        return Err(AuthError::JwtSvid("not yet valid".into()));
    }
    let verified =
        WorkloadIdentifier::parse(&claims.sub).map_err(|e| AuthError::JwtSvid(e.to_string()))?;
    if verified.trust_domain() != bundle.trust_domain {
        return Err(AuthError::JwtSvidUntrustedDomain);
    }
    Ok(verified.as_str().to_owned())
}
