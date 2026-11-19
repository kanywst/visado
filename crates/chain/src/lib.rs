//! The format-neutral model of a verified delegation chain.
//!
//! Each chain format has a [`ChainDecoder`] that parses the format, checks
//! signatures and links, and produces a [`NormalizedChain`]. Code after the
//! decoder works on this model only, so a new format is a new decoder.
//!
//! Only [`Assurance::Verified`] hops may be used for authorization, and only
//! from a chain whose [`holder_proof`](NormalizedChain::holder_proof) is
//! `true`. [`Assurance::Declared`] hops are for the audit record and the
//! Transaction Token context.
//!
//! The [`json`], [`jose`] and [`replay`] modules hold what the JWS-based
//! decoders share: a strict JSON parser with JCS (RFC 8785), compact JWS
//! parts and JWK thumbprints, and a proof `jti` cache.

pub mod jose;
pub mod json;
pub mod replay;

use std::fmt;

/// The chain format and revision a [`NormalizedChain`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// draft-niyikiza-oauth-attenuating-agent-tokens-02.
    Aat02,
    /// draft-asor-wimse-agent-delegation-chain-03.
    Asor03,
    /// The RFC 8693 `act` (actor) claim of an OAuth access token.
    Rfc8693Act,
}

impl Profile {
    /// A stable name for logs and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aat02 => "aat-02",
            Self::Asor03 => "asor-03",
            Self::Rfc8693Act => "rfc8693-act",
        }
    }
}

/// A base64url SHA-256 JWK thumbprint (RFC 7638).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyThumbprint(pub String);

impl fmt::Display for KeyThumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who a hop's authority is held by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActorId {
    /// A holder identified only by its key.
    Key(KeyThumbprint),
    /// A named actor, such as a SPIFFE ID or a client ID.
    Name(String),
    /// An actor named by an issuer, such as an RFC 8693 `act` claim's `sub`
    /// in the namespace of its `iss` (or of the token's issuer).
    Subject {
        /// The issuer that named the actor.
        issuer: String,
        /// The actor's subject identifier.
        subject: String,
    },
}

/// On whose behalf the chain acts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Principal {
    /// The format does not name one. AAT omits `sub` by design.
    Unspecified,
    /// A subject named by an issuer.
    Subject {
        /// The issuer that named the subject.
        issuer: String,
        /// The subject identifier.
        subject: String,
    },
}

/// The trust anchor the first hop was verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRef {
    /// The anchor's issuer identifier.
    pub issuer: String,
    /// The anchor key that verified the first hop.
    pub key: KeyThumbprint,
}

/// How a hop's signing key was tied to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignerBinding {
    /// Signed by a configured trust anchor.
    RootAnchor,
    /// Signed by the key in the previous hop's `cnf`.
    ParentCnf,
}

/// How a hop is bound to the previous one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Link {
    /// The first hop; nothing to link to.
    Root,
    /// A digest of the parent's signed bytes, such as AAT `par_hash`.
    ParHash(String),
    /// The previous hop is nested inside this hop's claim in the same signed
    /// token, as a prior actor is inside the current actor's RFC 8693 `act`
    /// claim. Nothing beyond that token's signature binds the two.
    Nested,
}

/// What a hop authorizes, as the format carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// The kind of authority, such as a RAR `type` value.
    pub detail_type: String,
    /// The authority as canonical JSON (RFC 8785).
    pub json: String,
}

/// A hop's validity window, in seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// When the hop was issued.
    pub issued_at: i64,
    /// When the hop expires.
    pub expires_at: i64,
}

/// The key a hop's holder proves possession of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cnf {
    /// The holder key's thumbprint.
    pub thumbprint: KeyThumbprint,
}

/// Whether a hop was cryptographically checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Assurance {
    /// Signature, signer binding and link were checked. This says nothing
    /// about whether the presenter holds the leaf key; see
    /// [`NormalizedChain::holder_proof`].
    Verified,
    /// Carried as data only, such as a prior actor in a nested RFC 8693
    /// `act` claim.
    Declared,
}

/// One delegation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    /// The token identifier.
    pub id: String,
    /// Position in the chain; the first hop is 0.
    pub depth: u32,
    /// The deepest position this hop allows, if the format has one.
    pub max_depth: Option<u32>,
    /// Who holds this hop's authority.
    pub actor: ActorId,
    /// Who delegated to the actor. `None` for the first hop.
    pub delegator: Option<ActorId>,
    /// The key that signed this hop.
    pub signer: KeyThumbprint,
    /// How that key was tied to the chain.
    pub signer_binding: SignerBinding,
    /// How this hop is bound to the previous one.
    pub link: Link,
    /// What this hop authorizes.
    pub authority: Authority,
    /// The validity window.
    pub validity: Validity,
    /// The audiences this hop is restricted to, if any.
    pub audience: Option<Vec<String>>,
    /// The holder key, if the hop is sender-constrained.
    pub cnf: Option<Cnf>,
    /// Whether this hop was verified.
    pub assurance: Assurance,
}

/// A delegation chain in format-neutral form, first hop first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedChain {
    /// The source format.
    pub profile: Profile,
    /// On whose behalf the chain acts.
    pub principal: Principal,
    /// The trust anchor of the first hop.
    pub root: TrustRef,
    /// The hops, first hop first. Never empty.
    pub hops: Vec<Hop>,
    /// Whether the presenter proved possession of the leaf holder key for
    /// this request. [`ChainDecoder::decode`] checks the chain only and sets
    /// `false`; a format's request verification sets `true` after checking
    /// the proof. For an RFC 8693 `act` chain, whose actors have no key, it
    /// is `true` when the current actor is the authenticated caller and that
    /// caller proved possession of a key for the request (a WIT or mTLS).
    pub holder_proof: bool,
}

impl NormalizedChain {
    /// The last hop: the one whose holder presents the chain.
    #[must_use]
    pub fn leaf(&self) -> Option<&Hop> {
        self.hops.last()
    }
}

/// An error with a stable, language-neutral code.
pub trait ChainError: std::error::Error {
    /// The stable error code, as used in conformance vectors and audit records.
    fn code(&self) -> &'static str;
}

/// Parses one chain format, checks its signatures and links, and produces a
/// [`NormalizedChain`] with [`holder_proof`](NormalizedChain::holder_proof)
/// set to `false`. A decoded chain alone must not authorize a request.
pub trait ChainDecoder {
    /// What the decoder reads, such as a list of compact JWS.
    type Input: ?Sized;
    /// The decoder's error.
    type Error: ChainError;

    /// Decodes and verifies `input` at time `now` (seconds since the Unix
    /// epoch).
    ///
    /// # Errors
    ///
    /// The first check that failed.
    fn decode(&self, input: &Self::Input, now: i64) -> Result<NormalizedChain, Self::Error>;
}
