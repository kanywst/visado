use jsonwebtoken::jwk::{JwkSet, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::error::AuthError;

/// A trusted OAuth authorization server.
#[derive(Debug, Clone)]
pub struct OAuthIssuer {
    issuer: String,
    audience: String,
    jwks: JwkSet,
    prefix: Option<String>,
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
            prefix: None,
        }
    }

    /// Prefixes `sub` and `client_id` from this issuer, so they cannot collide
    /// with identifiers from another issuer or with workload identifiers.
    #[must_use]
    pub fn with_subject_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) const fn has_prefix(&self) -> bool {
        self.prefix.is_some()
    }
}

/// A verified access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// `iss`.
    pub issuer: String,
    /// `sub`, with the issuer's subject prefix if one is configured.
    pub subject: String,
    /// `client_id`, falling back to `azp`, with the issuer's subject prefix.
    pub client_id: Option<String>,
    /// `scope`, space-delimited.
    pub scope: Option<String>,
    /// `exp`.
    pub expires_at: u64,
    /// `iat`, when present.
    pub issued_at: Option<u64>,
    /// `jti`, when present.
    pub id: Option<String>,
    /// The RFC 8693 `act` (actor) claim as the issuer signed it, unchecked:
    /// its shape is checked by whoever uses it.
    pub act: Option<serde_json::Value>,
    /// The RFC 7638 SHA-256 thumbprint of the issuer key that verified the
    /// token.
    pub key_thumbprint: String,
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
    #[serde(default)]
    scp: Option<serde_json::Value>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    cnf: Option<serde_json::Value>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    jti: Option<String>,
    /// `null` is kept as a present claim, so a chain adapter rejects it
    /// rather than reading the token as having no actor.
    #[serde(default, deserialize_with = "present")]
    act: Option<serde_json::Value>,
}

/// Any value, `null` included, as `Some`. Absence is `None` through
/// `#[serde(default)]`.
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
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
    let key_thumbprint = jwk.thumbprint(ThumbprintHash::SHA256).map_err(invalid)?;

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
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(leeway))
    {
        return Err(AuthError::AccessToken("not yet valid".into()));
    }
    // Proof of possession for DPoP or mTLS-bound tokens is not implemented, so
    // accepting one as a plain bearer token would drop its binding.
    if claims.cnf.is_some() {
        return Err(AuthError::SenderConstrained);
    }
    let prefix = issuer.prefix.as_deref().unwrap_or("");
    Ok(AccessToken {
        issuer: claims.iss,
        subject: format!("{prefix}{}", claims.sub),
        client_id: claims
            .client_id
            .or(claims.azp)
            .map(|c| format!("{prefix}{c}")),
        scope: claims
            .scope
            .or_else(|| claims.scp.as_ref().and_then(scp_to_scope)),
        expires_at: claims.exp,
        issued_at: claims.iat,
        id: claims.jti,
        act: claims.act,
        key_thumbprint,
    })
}

/// `scp` as used by some issuers instead of `scope`: a string or an array of
/// strings.
fn scp_to_scope(scp: &serde_json::Value) -> Option<String> {
    match scp {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|v| v.as_str().map(ToOwned::to_owned))
            .collect::<Option<Vec<_>>>()
            .map(|v| v.join(" ")),
        _ => None,
    }
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
