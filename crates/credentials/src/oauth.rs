use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::error::AuthError;

/// A trusted OAuth authorization server.
#[derive(Debug, Clone)]
pub struct OAuthIssuer {
    issuer: String,
    audience: String,
    jwks: JwkSet,
}

impl OAuthIssuer {
    /// Trusts tokens with `iss` = `issuer` and `aud` containing `audience`,
    /// signed by a key in `jwks`.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: JwkSet) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks,
        }
    }
}

/// A verified access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// `iss`.
    pub issuer: String,
    /// `sub`: the user or client the token was issued for.
    pub subject: String,
    /// `client_id`, falling back to `azp`.
    pub client_id: Option<String>,
    /// `scope`, space-delimited.
    pub scope: Option<String>,
    /// `exp`.
    pub expires_at: u64,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: u64,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct UnverifiedIss {
    iss: String,
}

const ALGORITHMS: [Algorithm; 4] = [
    Algorithm::RS256,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::EdDSA,
];

pub(crate) fn verify(
    issuers: &[OAuthIssuer],
    token: &str,
    now: u64,
    leeway: u64,
) -> Result<AccessToken, AuthError> {
    let invalid = |e: jsonwebtoken::errors::Error| AuthError::AccessToken(e.to_string());
    let header = decode_header(token).map_err(invalid)?;
    if !ALGORITHMS.contains(&header.alg) {
        return Err(AuthError::AccessToken("algorithm not allowed".into()));
    }
    let iss = unverified_iss(token)?;
    let issuer = issuers
        .iter()
        .find(|i| i.issuer == iss)
        .ok_or(AuthError::UntrustedIssuer)?;
    let jwk = match &header.kid {
        Some(kid) => issuer.jwks.find(kid),
        None if issuer.jwks.keys.len() == 1 => issuer.jwks.keys.first(),
        None => None,
    }
    .ok_or_else(|| AuthError::AccessToken("no trusted key".into()))?;
    let key = DecodingKey::from_jwk(jwk).map_err(invalid)?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&issuer.issuer]);
    validation.set_audience(&[&issuer.audience]);
    // Time is checked below against the injected clock.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = ["iss", "sub", "aud", "exp"]
        .into_iter()
        .map(String::from)
        .collect();
    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(invalid)?
        .claims;
    if now >= claims.exp.saturating_add(leeway) {
        return Err(AuthError::Expired);
    }
    Ok(AccessToken {
        issuer: claims.iss,
        subject: claims.sub,
        client_id: claims.client_id.or(claims.azp),
        scope: claims.scope,
        expires_at: claims.exp,
    })
}

fn unverified_iss(token: &str) -> Result<String, AuthError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::AccessToken("malformed".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthError::AccessToken("malformed".into()))?;
    let parsed: UnverifiedIss =
        serde_json::from_slice(&bytes).map_err(|_| AuthError::AccessToken("malformed".into()))?;
    Ok(parsed.iss)
}
