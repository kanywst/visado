//! Verification outcomes, named as the draft's Table 2 names them.

use std::fmt;

use visado_chain::ChainError;
use visado_chain::dpop::NonceError;

/// Why a chain or an action was denied: the outcome names of Table 2
/// (§6.2). The algorithm denies on the first failure, so one denial carries
/// one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// A token is not three base64url parts, a required claim is absent or
    /// of the wrong shape, an integer exceeds 2^53-1, a scope is invalid, a
    /// constraint is malformed or repeated, or the detail is not exactly one
    /// closed `agent_delegation` object.
    Malformed,
    /// A decoded header or payload is not its own JCS serialization.
    NonCanonical,
    /// A JSON object repeats a member name.
    DuplicateMember,
    /// A number is not finite.
    NonFinite,
    /// Step 1: a signature does not verify, the algorithm is not accepted or
    /// differs from the key's, or the token is not under a trusted key.
    SignatureInvalid,
    /// Step 2: a child's `par_hash` does not match the parent presented.
    ParHashMismatch,
    /// Step 3: a `del_depth` is out of sequence or the chain is too deep.
    DepthInvalid,
    /// Step 3: a token's `sub` differs from the root's.
    PrincipalAltered,
    /// Step 4: a child's authority is not subsumed by its parent's.
    NotNarrower,
    /// Step 5: a token is outside its validity window, or its `exp`
    /// exceeds its parent's.
    Expired,
    /// Step 6: the DPoP proof is absent or invalid for this request.
    HolderBindingFailed,
    /// Step 7: a token is revoked: its status list entry is `INVALID` or
    /// `SUSPENDED`.
    Revoked,
    /// Step 7: a token's status cannot be established: no list for its
    /// reference, a list that is invalid, expired or stale, an index out of
    /// range, or a status value this verifier does not know.
    StatusUnknown,
    /// Step 8: the leaf's `aud` does not name this enforcement point.
    AudienceMismatch,
    /// Step 8: the action's scope is not covered by the leaf's scopes.
    ScopeNotGranted,
    /// Step 8: the action violates a constraint of the leaf.
    CeilingExceeded,
    /// Step 8: the leaf carries a constraint type this verifier does not
    /// implement.
    UnknownConstraint,
}

impl Outcome {
    /// The name as Table 2 writes it, such as `"not_narrower"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NonCanonical => "non_canonical",
            Self::DuplicateMember => "duplicate_member",
            Self::NonFinite => "non_finite",
            Self::SignatureInvalid => "signature_invalid",
            Self::ParHashMismatch => "par_hash_mismatch",
            Self::DepthInvalid => "depth_invalid",
            Self::PrincipalAltered => "principal_altered",
            Self::NotNarrower => "not_narrower",
            Self::Expired => "expired",
            Self::HolderBindingFailed => "holder_binding_failed",
            Self::Revoked => "revoked",
            Self::StatusUnknown => "status_unknown",
            Self::AudienceMismatch => "audience_mismatch",
            Self::ScopeNotGranted => "scope_not_granted",
            Self::CeilingExceeded => "ceiling_exceeded",
            Self::UnknownConstraint => "unknown_constraint",
        }
    }

    /// The step of §6 the outcome belongs to: `"parse"` or `"1"` to `"8"`.
    #[must_use]
    pub const fn step(self) -> &'static str {
        match self {
            Self::Malformed | Self::NonCanonical | Self::DuplicateMember | Self::NonFinite => {
                "parse"
            }
            Self::SignatureInvalid => "1",
            Self::ParHashMismatch => "2",
            Self::DepthInvalid | Self::PrincipalAltered => "3",
            Self::NotNarrower => "4",
            Self::Expired => "5",
            Self::HolderBindingFailed => "6",
            Self::Revoked | Self::StatusUnknown => "7",
            Self::AudienceMismatch
            | Self::ScopeNotGranted
            | Self::CeilingExceeded
            | Self::UnknownConstraint => "8",
        }
    }

    /// The stable error code, `asor.` and the name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "asor.malformed",
            Self::NonCanonical => "asor.non_canonical",
            Self::DuplicateMember => "asor.duplicate_member",
            Self::NonFinite => "asor.non_finite",
            Self::SignatureInvalid => "asor.signature_invalid",
            Self::ParHashMismatch => "asor.par_hash_mismatch",
            Self::DepthInvalid => "asor.depth_invalid",
            Self::PrincipalAltered => "asor.principal_altered",
            Self::NotNarrower => "asor.not_narrower",
            Self::Expired => "asor.expired",
            Self::HolderBindingFailed => "asor.holder_binding_failed",
            Self::Revoked => "asor.revoked",
            Self::StatusUnknown => "asor.status_unknown",
            Self::AudienceMismatch => "asor.audience_mismatch",
            Self::ScopeNotGranted => "asor.scope_not_granted",
            Self::CeilingExceeded => "asor.ceiling_exceeded",
            Self::UnknownConstraint => "asor.unknown_constraint",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A denial: the outcome, the token it is about, and a short reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsorError {
    outcome: Outcome,
    token: Option<usize>,
    reason: &'static str,
    nonce: Option<NonceError>,
}

impl AsorError {
    pub(crate) const fn new(outcome: Outcome, reason: &'static str) -> Self {
        Self {
            outcome,
            token: None,
            reason,
            nonce: None,
        }
    }

    pub(crate) const fn with_dpop_nonce(mut self, nonce: NonceError) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub(crate) const fn at(outcome: Outcome, token: usize, reason: &'static str) -> Self {
        Self {
            outcome,
            token: Some(token),
            reason,
            nonce: None,
        }
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The position of the token that failed, root first, if the failure is
    /// about one token.
    #[must_use]
    pub const fn token(&self) -> Option<usize> {
        self.token
    }

    /// The stable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.outcome.code()
    }

    /// A short reason, finer than the outcome.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// For a `holder_binding_failed` whose proof was valid except for its
    /// server nonce (RFC 9449 §9), why the nonce was refused. The holder
    /// can retry with a fresh nonce.
    #[must_use]
    pub const fn dpop_nonce(&self) -> Option<NonceError> {
        self.nonce
    }
}

impl fmt::Display for AsorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (step {}): {}",
            self.outcome,
            self.outcome.step(),
            self.reason
        )?;
        if let Some(i) = self.token {
            write!(f, " (token {i})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AsorError {}

impl ChainError for AsorError {
    fn code(&self) -> &'static str {
        self.outcome.code()
    }
}
