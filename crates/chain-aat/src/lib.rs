//! Attenuating Agent Token chains, per
//! draft-niyikiza-oauth-attenuating-agent-tokens-02.
//!
//! [`Verifier::verify`] runs the §8 algorithm for one tool invocation: chain
//! size and cycle checks, the root against a trust anchor, each link (holder
//! key, depth, time, attenuation, `par_hash`), the PoP JWT signature, the
//! invocation against the leaf's constraints, chain audience, and the rest of
//! the PoP JWT. A failure reports the §8 [`Step`] and a stable
//! [`code`](AatError::code).
//!
//! The [`ChainDecoder`](visado_chain::ChainDecoder) implementation runs steps
//! 1 to 5 only and yields a [`NormalizedChain`](visado_chain::NormalizedChain).
//!
//! Only `Ed25519` and `ES256` are accepted. Numbers in claims and arguments
//! are read as written, so admissibility (§3.4) is checked exactly.

mod constraint;
mod error;
mod json;
mod jws;
mod replay;
mod verify;

pub use error::{AatError, Step};
pub use replay::{MemoryReplayCache, ReplayCache};
pub use verify::{
    Authorized, DETAIL_TYPE, Invocation, Limits, POP_TYP, Policy, Presentation, TYP, TrustAnchor,
    Verifier,
};

/// The RFC 7638 SHA-256 thumbprint of `key`, as AAT uses it to name holders.
#[must_use]
pub fn jwk_thumbprint(key: &wimsey_jose::VerifyingKey) -> String {
    jws::key_thumbprint(key)
}
