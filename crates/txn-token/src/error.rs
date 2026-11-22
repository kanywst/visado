//! Errors for minting, verifying and replacing Transaction Tokens.

/// An error from minting, verifying or replacing a Transaction Token.
///
/// Every variant maps to a stable, language-neutral [`code`](TxnTokenError::code)
/// that the conformance vectors and audit records use.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TxnTokenError {
    /// The token is larger than [`MAX_TOKEN_LEN`](crate::MAX_TOKEN_LEN).
    #[error("token exceeds the maximum accepted size")]
    TooLong,
    /// The compact serialization is not three Base64url parts, or a part does
    /// not decode.
    #[error("malformed token")]
    Malformed,
    /// The header or the claim set is not the JSON the draft requires.
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    /// The header `typ` does not convey `txntoken+jwt` (§9.1).
    #[error("unexpected token type `{found}`, expected `txntoken+jwt`")]
    WrongType {
        /// The `typ` value found, or an empty string if absent.
        found: String,
    },
    /// The header `alg` is not an algorithm this crate verifies.
    #[error("unsupported algorithm `{found}`")]
    UnsupportedAlg {
        /// The `alg` value found.
        found: String,
    },
    /// The header names a critical extension this crate does not implement.
    #[error("unsupported critical header parameter")]
    UnsupportedCritical,
    /// No configured key matches the header's `kid`.
    #[error("no trusted key for this token")]
    UnknownKey,
    /// The key found for `kid` uses a different algorithm than the header names.
    #[error("the token's `alg` does not match the key's algorithm")]
    AlgorithmMismatch,
    /// An RSA key is shorter than [`MIN_RSA_BITS`](crate::MIN_RSA_BITS) or
    /// has no exponent.
    #[error("RSA key too weak")]
    WeakKey,
    /// The signature does not verify.
    #[error("signature verification failed")]
    InvalidSignature,
    /// `aud` is not this trust domain (§9.2, §12.2).
    #[error("audience is not this trust domain")]
    AudienceMismatch,
    /// The token has expired.
    #[error("token has expired")]
    Expired,
    /// `iat` is in the future.
    #[error("token issued in the future")]
    IssuedInFuture,
    /// `exp` is not after `iat`, or the lifetime exceeds the configured maximum (§13.1).
    #[error("token lifetime is invalid or too long")]
    InvalidLifetime,
    /// A required claim is empty or otherwise unusable.
    #[error("invalid claim `{claim}`")]
    InvalidClaim {
        /// The claim name.
        claim: &'static str,
    },
    /// A replacement would widen `scope` (§13.6, §13.15).
    #[error("scope would widen")]
    ScopeEscalation,
    /// A replacement would change `txn`, `sub` or `aud` (§13.15).
    #[error("immutable claim `{claim}` would change")]
    ImmutableClaimChanged {
        /// The claim name.
        claim: &'static str,
    },
    /// A replacement would change an existing `tctx` member. Members can only be added.
    #[error("existing `tctx` member `{member}` would change")]
    TctxModified {
        /// The member name.
        member: String,
    },
    /// A token request is not a valid Transaction Token request (§11).
    #[error("invalid token request: {0}")]
    InvalidRequest(&'static str),
}

impl TxnTokenError {
    /// The stable error code, as used in conformance vectors and audit records.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLong => "txn.too_long",
            Self::Malformed | Self::Json(_) => "txn.malformed",
            Self::WrongType { .. } => "txn.wrong_type",
            Self::UnsupportedAlg { .. } => "txn.unsupported_alg",
            Self::UnsupportedCritical => "txn.unsupported_crit",
            Self::UnknownKey => "txn.unknown_key",
            Self::AlgorithmMismatch => "txn.alg_mismatch",
            Self::WeakKey => "txn.weak_key",
            Self::InvalidSignature => "txn.bad_signature",
            Self::AudienceMismatch => "txn.audience_mismatch",
            Self::Expired => "txn.expired",
            Self::IssuedInFuture => "txn.issued_in_future",
            Self::InvalidLifetime => "txn.invalid_lifetime",
            Self::InvalidClaim { .. } => "txn.invalid_claim",
            Self::ScopeEscalation => "txn.scope_escalation",
            Self::ImmutableClaimChanged { .. } => "txn.immutable_claim_changed",
            Self::TctxModified { .. } => "txn.tctx_modified",
            Self::InvalidRequest(_) => "txn.invalid_request",
        }
    }
}
