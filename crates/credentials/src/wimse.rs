use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::VerifyingKey;
use wimsey_wit::{Validation, VerifiedWit};

use crate::error::AuthError;

/// A trusted WIT issuer for one trust domain.
#[derive(Debug, Clone)]
pub struct WitIssuer {
    trust_domain: String,
    issuer: Option<String>,
    keys: BTreeMap<String, VerifyingKey>,
}

impl WitIssuer {
    /// An issuer for `trust_domain` with no keys yet.
    #[must_use]
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            issuer: None,
            keys: BTreeMap::new(),
        }
    }

    /// Requires `iss` to equal `issuer`.
    #[must_use]
    pub fn expect_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Adds a signing key selected by `kid`.
    #[must_use]
    pub fn with_key(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.keys.insert(kid.into(), key);
        self
    }
}

#[derive(Deserialize)]
struct Header {
    kid: Option<String>,
}

#[derive(Deserialize)]
struct Subject {
    sub: String,
}

/// Verifies `wit` against the issuer configured for the trust domain in its
/// `sub`. The unverified `sub` and `kid` only select the key; the signature is
/// then checked against it.
pub(crate) fn verify_wit(
    issuers: &[WitIssuer],
    wit: &str,
    now: u64,
    leeway: u64,
) -> Result<VerifiedWit, AuthError> {
    let mut parts = wit.split('.');
    let (Some(header), Some(claims)) = (parts.next(), parts.next()) else {
        return Err(AuthError::Wit("malformed".into()));
    };
    let header: Header = decode(header)?;
    let subject: Subject = decode(claims)?;
    let sub = WorkloadIdentifier::parse(&subject.sub).map_err(|e| AuthError::Wit(e.to_string()))?;
    let issuer = issuers
        .iter()
        .find(|i| i.trust_domain == sub.trust_domain())
        .ok_or(AuthError::UntrustedDomain)?;
    let key = match header.kid {
        Some(kid) => issuer.keys.get(&kid),
        None if issuer.keys.len() == 1 => issuer.keys.values().next(),
        None => None,
    }
    .ok_or_else(|| AuthError::Wit("no trusted key".into()))?;

    let mut validation = Validation::at(now).with_leeway(leeway);
    if let Some(iss) = &issuer.issuer {
        validation = validation.expect_issuer(iss.clone());
    }
    let verified =
        wimsey_wit::verify(wit, key, &validation).map_err(|e| AuthError::Wit(e.to_string()))?;
    if verified.claims.sub.trust_domain() != issuer.trust_domain {
        return Err(AuthError::UntrustedDomain);
    }
    Ok(verified)
}

fn decode<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, AuthError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| AuthError::Wit("malformed".into()))?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::Wit("malformed".into()))
}
