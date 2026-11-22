//! Compact-JWS minting and verification.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wimsey_jose::{Algorithm, JoseError, SIGNATURE_LEN, SigningKey};

use crate::claims::TxnTokenClaims;
use crate::error::TxnTokenError;
use crate::keys::{Key, KeySet};

/// The JOSE `typ` of a Transaction Token (§9.1).
pub const TYP: &str = "txntoken+jwt";

/// The HTTP header that carries a Transaction Token (§12.1).
pub const HEADER: &str = "Txn-Token";

/// The largest compact serialization accepted, in bytes. Checked before any
/// decoding.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

/// `RS256` (RFC 7518 §3.3), verified with keys added by
/// [`KeySet::with_rsa_key`]. Minting is `Ed25519`, `EdDSA` or `ES256` only.
const RS256: &str = "RS256";

#[derive(Serialize, Deserialize)]
struct Header {
    #[serde(default)]
    typ: String,
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
}

/// What a recipient checks besides the signature.
///
/// `now` is passed in so verification is deterministic in tests.
#[derive(Debug, Clone)]
pub struct Validation {
    /// The current time, seconds since the Unix epoch.
    pub now: u64,
    /// Clock-skew tolerance for `exp` and `iat`, in seconds.
    pub leeway: u64,
    /// The recipient's trust domain. `aud` must equal it exactly.
    pub trust_domain: String,
    /// The longest accepted `exp - iat`, in seconds. `None` disables the check.
    pub max_lifetime: Option<u64>,
}

impl Validation {
    /// Validation for `trust_domain` at `now`, with no leeway and no lifetime cap.
    #[must_use]
    pub fn new(trust_domain: impl Into<String>, now: u64) -> Self {
        Self {
            now,
            leeway: 0,
            trust_domain: trust_domain.into(),
            max_lifetime: None,
        }
    }

    /// Sets the clock-skew tolerance.
    #[must_use]
    pub fn with_leeway(mut self, leeway: u64) -> Self {
        self.leeway = leeway;
        self
    }

    /// Rejects tokens whose lifetime is longer than `seconds`.
    #[must_use]
    pub fn with_max_lifetime(mut self, seconds: u64) -> Self {
        self.max_lifetime = Some(seconds);
        self
    }
}

/// A Transaction Token whose signature, audience and time have been checked.
#[derive(Debug, Clone)]
pub struct VerifiedTxnToken {
    /// The claims.
    pub claims: TxnTokenClaims,
    /// The header `kid`, if any.
    pub kid: Option<String>,
}

/// Signs `claims` as a Transaction Token.
///
/// The output is reproducible for a fixed key, `kid` and claim set.
///
/// # Errors
///
/// Whatever [`TxnTokenClaims::check`] returns, or [`TxnTokenError::Json`] if
/// serialization fails.
pub fn mint(
    claims: &TxnTokenClaims,
    kid: Option<&str>,
    key: &SigningKey,
) -> Result<String, TxnTokenError> {
    claims.check()?;
    let header = Header {
        typ: TYP.to_owned(),
        alg: key.algorithm().as_str().to_owned(),
        kid: kid.map(ToOwned::to_owned),
        crit: None,
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()));
    Ok(format!("{signing_input}.{signature}"))
}

/// Verifies a Transaction Token.
///
/// Checks, in order: size, structure, `typ`, `alg`, `crit`, key selection,
/// signature, claims, `aud`, `exp`, `iat` and lifetime. Stops at the first
/// failure.
///
/// # Errors
///
/// The [`TxnTokenError`] for the first check that failed.
pub fn verify(
    token: &str,
    keys: &KeySet,
    validation: &Validation,
) -> Result<VerifiedTxnToken, TxnTokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(TxnTokenError::TooLong);
    }
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TxnTokenError::Malformed);
    };

    let header: Header = serde_json::from_slice(&decode(header_b64)?)?;
    if !wimsey_jose::typ_conveys(&header.typ, TYP) {
        return Err(TxnTokenError::WrongType { found: header.typ });
    }
    let signing_input = &token[..header_b64.len() + 1 + claims_b64.len()];
    if header.alg == RS256 {
        if header.crit.is_some() {
            return Err(TxnTokenError::UnsupportedCritical);
        }
        let Key::Rsa(key) = keys
            .find(header.kid.as_deref())
            .ok_or(TxnTokenError::UnknownKey)?
        else {
            return Err(TxnTokenError::AlgorithmMismatch);
        };
        if decode(signature_b64)?.len() != key.len {
            return Err(TxnTokenError::Malformed);
        }
        let ok = jsonwebtoken::crypto::verify(
            signature_b64,
            signing_input.as_bytes(),
            &key.key,
            jsonwebtoken::Algorithm::RS256,
        )
        .unwrap_or(false);
        if !ok {
            return Err(TxnTokenError::InvalidSignature);
        }
    } else {
        let alg = Algorithm::parse(&header.alg).map_err(|e| match e {
            JoseError::UnsupportedAlg { found } | JoseError::ForbiddenAlg { found } => {
                TxnTokenError::UnsupportedAlg { found }
            }
            _ => TxnTokenError::UnsupportedAlg {
                found: header.alg.clone(),
            },
        })?;
        if header.crit.is_some() {
            return Err(TxnTokenError::UnsupportedCritical);
        }
        let Key::Jose(key) = keys
            .find(header.kid.as_deref())
            .ok_or(TxnTokenError::UnknownKey)?
        else {
            return Err(TxnTokenError::AlgorithmMismatch);
        };
        if !alg.same_signature_as(key.algorithm()) {
            return Err(TxnTokenError::AlgorithmMismatch);
        }
        let signature = decode(signature_b64)?;
        if signature.len() != SIGNATURE_LEN {
            return Err(TxnTokenError::Malformed);
        }
        key.verify(signing_input.as_bytes(), &signature)
            .map_err(|_| TxnTokenError::InvalidSignature)?;
    }

    let claims: TxnTokenClaims = serde_json::from_slice(&decode(claims_b64)?)?;
    claims.check()?;
    if claims.aud != validation.trust_domain {
        return Err(TxnTokenError::AudienceMismatch);
    }
    if validation.now >= claims.exp.saturating_add(validation.leeway) {
        return Err(TxnTokenError::Expired);
    }
    if claims.iat > validation.now.saturating_add(validation.leeway) {
        return Err(TxnTokenError::IssuedInFuture);
    }
    if let Some(max) = validation.max_lifetime
        && claims.exp - claims.iat > max
    {
        return Err(TxnTokenError::InvalidLifetime);
    }
    Ok(VerifiedTxnToken {
        claims,
        kid: header.kid,
    })
}

/// A log-safe identifier for a token: the Base64url SHA-256 of its compact
/// form. §15.2 forbids logging the token itself.
#[must_use]
pub fn fingerprint(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn decode(part: &str) -> Result<Vec<u8>, TxnTokenError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| TxnTokenError::Malformed)
}
