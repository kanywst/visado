use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse, ThumbprintHash};
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

/// Whether `jwk` may verify a signature made with `alg` (RFC 7517 §4.2-4.4):
/// `use`, when present, is `sig`; `key_ops`, when present, includes `verify`;
/// and `alg`, when present, is `alg`.
fn verifies(jwk: &Jwk, alg: Algorithm) -> bool {
    let common = &jwk.common;
    common
        .public_key_use
        .as_ref()
        .is_none_or(|u| *u == PublicKeyUse::Signature)
        && common
            .key_operations
            .as_ref()
            .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
        && common
            .key_algorithm
            .is_none_or(|key_alg| Algorithm::try_from(key_alg).is_ok_and(|a| a == alg))
}

/// How a verified access token is bound to its presenter.
#[derive(Debug)]
pub(crate) enum Binding {
    /// No `cnf`: a bearer token.
    Bearer,
    /// `cnf` with only `jkt`: a DPoP-bound token (RFC 9449 §6).
    Dpop(String),
}

/// Verifies a token presented without proof of possession: as
/// `Authorization: Bearer`, or as a user token next to a caller's own proof.
/// A DPoP-bound token is refused (RFC 9449 §7.1: a bound token must not be
/// accepted as a bearer token).
pub(crate) fn verify(
    issuers: &[OAuthIssuer],
    token: &str,
    now: u64,
    leeway: u64,
) -> Result<AccessToken, AuthError> {
    match verify_bound(issuers, token, now, leeway)? {
        (token, Binding::Bearer) => Ok(token),
        (_, Binding::Dpop(_)) => Err(AuthError::DpopBound),
    }
}

/// Verifies a token and reports its binding. A `cnf` other than a lone
/// string `jkt` is refused: no other confirmation method is implemented, so
/// accepting it would drop the binding.
pub(crate) fn verify_bound(
    issuers: &[OAuthIssuer],
    token: &str,
    now: u64,
    leeway: u64,
) -> Result<(AccessToken, Binding), AuthError> {
    let invalid = |e: jsonwebtoken::errors::Error| AuthError::AccessToken(e.to_string());
    let header = decode_header(token).map_err(invalid)?;
    if !ALGORITHMS.contains(&header.alg) {
        return Err(AuthError::AccessToken("algorithm not allowed".into()));
    }
    if header
        .typ
        .as_deref()
        .is_some_and(|typ| DELEGATION_TYPS.contains(&typ.to_ascii_lowercase().as_str()))
    {
        return Err(AuthError::DelegationToken(
            "typ names a delegation token".into(),
        ));
    }
    let iss = unverified_iss(token)?;
    let issuer = issuers
        .iter()
        .find(|i| i.issuer == iss)
        .ok_or(AuthError::UntrustedIssuer)?;
    // A key published for encryption or for another algorithm never
    // verifies. Without a `kid`, the set must hold exactly one key in total,
    // so adding a key (a rotation) never changes which key a kid-less token
    // is checked against.
    let keys = &issuer.jwks.keys;
    let jwk = match &header.kid {
        Some(kid) => keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid.as_str())),
        None if keys.len() == 1 => keys.first(),
        None => None,
    }
    .filter(|jwk| verifies(jwk, header.alg))
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
    delegation_claims(token)?;
    if now >= claims.exp.saturating_add(leeway) {
        return Err(AuthError::Expired);
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(leeway))
    {
        return Err(AuthError::AccessToken("not yet valid".into()));
    }
    let binding = match &claims.cnf {
        None => Binding::Bearer,
        Some(cnf) => dpop_jkt(cnf)
            .map(Binding::Dpop)
            .ok_or(AuthError::SenderConstrained)?,
    };
    let prefix = issuer.prefix.as_deref().unwrap_or("");
    let token = AccessToken {
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
    };
    Ok((token, binding))
}

/// The JOSE `typ` values of AAT tokens and proofs
/// (draft-niyikiza-oauth-attenuating-agent-tokens-02 §3.5), with and without
/// the `application/` prefix. An asor Delegation Token uses `at+jwt`, like
/// any access token, so it is told apart by its claims instead.
const DELEGATION_TYPS: [&str; 4] = [
    "aat+jwt",
    "application/aat+jwt",
    "aat-pop+jwt",
    "application/aat-pop+jwt",
];

/// Claims that only a delegation-chain token carries: the asor and AAT chain
/// claims (`del_depth`, `del_max_depth`, `par_hash`), the AAT proof claims,
/// and `status` (a Token Status List reference, which this path does not
/// check).
const DELEGATION_CLAIMS: [&str; 9] = [
    "del_depth",
    "del_max_depth",
    "par_hash",
    "status",
    "aat_id",
    "aat_hash",
    "aat_tool",
    "aat_aud",
    "hta",
];

/// The `authorization_details` types of the delegation-chain formats: asor's
/// `agent_delegation` and AAT's `attenuating_agent_token`.
const DELEGATION_DETAIL_TYPES: [&str; 2] = ["agent_delegation", "attenuating_agent_token"];

/// Refuses a verified token that is a link of a delegation chain. Such a
/// token is checked only on its chain path (status, depth, parent hash,
/// constraints); accepted here it would skip all of that, and the PDP would
/// not learn it is a delegation.
fn delegation_claims(token: &str) -> Result<(), AuthError> {
    let payload = payload(token)?;
    if let Some(claim) = DELEGATION_CLAIMS
        .iter()
        .find(|claim| payload.contains_key(**claim))
    {
        return Err(AuthError::DelegationToken(format!("carries `{claim}`")));
    }
    let Some(details) = payload.get("authorization_details") else {
        return Ok(());
    };
    // RFC 9396 §2: an array. Any other shape is refused rather than skipped,
    // so a chain entry cannot hide in an object.
    let details = details
        .as_array()
        .ok_or_else(|| AuthError::AccessToken("authorization_details is not an array".into()))?;
    let detail = details
        .iter()
        .filter_map(|entry| entry.get("type")?.as_str())
        .find_map(|kind| {
            let kind = kind.trim();
            DELEGATION_DETAIL_TYPES
                .iter()
                .find(|chain| chain.eq_ignore_ascii_case(kind))
        });
    if let Some(kind) = detail {
        return Err(AuthError::DelegationToken(format!(
            "authorization_details type `{kind}`"
        )));
    }
    Ok(())
}

/// `cnf.jkt` when it is a non-empty string and the only confirmation member.
///
/// Keycloak adds `kc-jkt-type` next to `jkt` to say which binding the
/// thumbprint is for: `DPoP`, or `ABCA` for a key from client attestation.
/// `kc-jkt-type` `DPoP` is accepted; any other value is not a DPoP binding.
fn dpop_jkt(cnf: &serde_json::Value) -> Option<String> {
    let members = cnf.as_object()?;
    let others = match members.get(KEYCLOAK_JKT_TYPE) {
        None => 1,
        Some(kind) if kind.as_str() == Some("DPoP") => 2,
        Some(_) => return None,
    };
    if members.len() != others {
        return None;
    }
    members
        .get("jkt")?
        .as_str()
        .filter(|jkt| !jkt.is_empty())
        .map(ToOwned::to_owned)
}

/// The member Keycloak puts in `cnf` to name what `jkt` binds.
const KEYCLOAK_JKT_TYPE: &str = "kc-jkt-type";

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
    let parsed: UnverifiedIss = serde_json::from_slice(&payload_bytes(token)?)
        .map_err(|_| AuthError::AccessToken("malformed".into()))?;
    Ok(parsed.iss)
}

/// The payload as a JSON object.
fn payload(token: &str) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
    serde_json::from_slice(&payload_bytes(token)?)
        .map_err(|_| AuthError::AccessToken("malformed".into()))
}

fn payload_bytes(token: &str) -> Result<Vec<u8>, AuthError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::AccessToken("malformed".into()))?;
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthError::AccessToken("malformed".into()))
}
