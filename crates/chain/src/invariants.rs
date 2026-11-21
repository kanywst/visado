//! The format-neutral invariant engine.
//!
//! [`Engine::check`] runs on every [`NormalizedChain`] after its format's
//! decoder and request checks, whatever the format. The decoders keep their
//! own checks; the engine is a second, independent pass over the normalized
//! model that must agree with them. It checks, in this order:
//!
//! 1. shape: at least one hop, at most [`MAX_HOPS`], depths `0..n` in order
//! 2. links: the first hop is the root, signed by the chain's trust anchor;
//!    every later hop names its parent's actor as delegator and is signed by
//!    the key its binding says (the parent's `cnf` or the trust anchor)
//! 3. the principal never changes
//! 4. `exp` is monotone: no hop outlives its parent
//! 5. depth limits hold, per the profile's [`DepthSemantics`]
//! 6. audiences only narrow
//! 7. no delegation token repeats
//! 8. verified hops end the chain, and the leaf is verified
//! 9. every verified hop's authority has an algebra, and each subsumes the
//!    next ([`AuthorityAlgebra::subsumes`](crate::algebra::AuthorityAlgebra::subsumes))
//! 10. every status reference was checked
//! 11. the presenter proved possession of the leaf key
//! 12. the leaf's authority permits the action
//!     ([`AuthorityAlgebra::permits`](crate::algebra::AuthorityAlgebra::permits))
//!
//! [`Engine::check_chain`] runs 1 to 9, for a verifier without a request.

use std::collections::HashSet;
use std::fmt;

use crate::algebra::{Action, Algebras};
use crate::{
    Assurance, ChainError, Hop, Link, NormalizedChain, Profile, SignerBinding, StatusCheck,
};

/// The most hops the engine accepts in one chain.
pub const MAX_HOPS: usize = 32;

/// What a hop's `max_depth` bounds. The drafts differ (`del_max_depth`), so
/// the semantics is fixed per profile by [`DepthSemantics::for_profile`] and
/// reported in the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DepthSemantics {
    /// asor-03 §6 step 3: only the first hop's bound limits the chain. Every
    /// hop's depth is at most the first hop's `max_depth`, and no hop states
    /// a larger one.
    AsorStrict,
    /// AAT-02 §4.3: every hop carries its own cap. Each hop's depth is at
    /// most its own `max_depth`, and no hop raises its parent's.
    AatHolderCap,
    /// The format has no per-hop bound (RFC 8693 `act`); only [`MAX_HOPS`]
    /// and any `max_depth` a hop does state apply.
    Uncapped,
}

impl DepthSemantics {
    /// The semantics of `profile`'s depth bound.
    #[must_use]
    pub const fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Asor03 => Self::AsorStrict,
            Profile::Aat02 => Self::AatHolderCap,
            Profile::Rfc8693Act => Self::Uncapped,
        }
    }

    /// A stable name for logs and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsorStrict => "asor-strict",
            Self::AatHolderCap => "aat-holder-cap",
            Self::Uncapped => "uncapped",
        }
    }
}

/// The invariant a chain broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Invariant {
    /// No hops, too many, or depths out of order.
    Shape,
    /// A hop is not linked to its parent or not signed by the key its
    /// binding names.
    Link,
    /// A hop names a different principal.
    Principal,
    /// A hop expires after its parent.
    Expiry,
    /// A hop is deeper than its depth bound allows, or raises the bound.
    Depth,
    /// A hop's audience restriction is empty or not within its parent's.
    Audience,
    /// A delegation token appears twice.
    Repeat,
    /// A declared hop follows a verified one, or the leaf is not verified.
    Assurance,
    /// A verified hop's authority type has no algebra.
    UnknownAuthority,
    /// A hop's authority is not subsumed by its parent's.
    Attenuation,
    /// A status reference was not checked.
    Status,
    /// The presenter did not prove possession of the leaf key.
    HolderProof,
    /// The leaf's authority does not permit the action.
    Action,
}

impl Invariant {
    /// The stable deny code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Shape => "chain.malformed",
            Self::Link => "chain.link_mismatch",
            Self::Principal => "chain.principal_altered",
            Self::Expiry => "chain.exp_extended",
            Self::Depth => "chain.depth_exceeded",
            Self::Audience => "chain.audience_widened",
            Self::Repeat => "chain.token_repeated",
            Self::Assurance => "chain.unverified",
            Self::UnknownAuthority => "chain.unknown_authority",
            Self::Attenuation => "chain.scope_escalation",
            Self::Status => "chain.status_unchecked",
            Self::HolderProof => "chain.no_holder_proof",
            Self::Action => "chain.action_denied",
        }
    }
}

/// A chain that broke an invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantError {
    /// Which invariant.
    pub invariant: Invariant,
    /// The position of the hop that broke it, when one did.
    pub hop: Option<usize>,
}

impl InvariantError {
    const fn at(invariant: Invariant, hop: usize) -> Self {
        Self {
            invariant,
            hop: Some(hop),
        }
    }

    const fn chain(invariant: Invariant) -> Self {
        Self {
            invariant,
            hop: None,
        }
    }
}

impl fmt::Display for InvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.hop {
            Some(hop) => write!(f, "{} at hop {hop}", self.invariant.code()),
            None => f.write_str(self.invariant.code()),
        }
    }
}

impl std::error::Error for InvariantError {}

impl ChainError for InvariantError {
    fn code(&self) -> &'static str {
        self.invariant.code()
    }
}

/// What the engine found about a chain that holds every invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    /// How the depth bound was read.
    pub depth_semantics: DepthSemantics,
}

/// The invariant engine, with the authority algebras it accepts.
#[derive(Debug, Clone, Default)]
pub struct Engine {
    algebras: Algebras,
}

impl Engine {
    /// An engine that judges authorities with `algebras`. An authority whose
    /// type is not among them is denied.
    #[must_use]
    pub const fn new(algebras: Algebras) -> Self {
        Self { algebras }
    }

    /// The algebras.
    #[must_use]
    pub const fn algebras(&self) -> &Algebras {
        &self.algebras
    }

    /// Every invariant, for a chain that is to authorize `action`. Pass
    /// `None` only when the chain is not asked to authorize an action (an
    /// RFC 8693 `act` chain, whose actors hold no authority of their own).
    ///
    /// # Errors
    ///
    /// The first invariant broken, in the order of the module docs.
    pub fn check(
        &self,
        chain: &NormalizedChain,
        action: Option<&Action<'_>>,
    ) -> Result<Checked, InvariantError> {
        let checked = self.check_chain(chain)?;
        if let Some(i) = chain
            .hops
            .iter()
            .position(|h| h.status == Some(StatusCheck::Unchecked))
        {
            return Err(InvariantError::at(Invariant::Status, i));
        }
        if !chain.holder_proof {
            return Err(InvariantError::chain(Invariant::HolderProof));
        }
        let leaf = chain
            .leaf()
            .ok_or(InvariantError::chain(Invariant::Shape))?;
        if !self.algebras.permits(&leaf.authority, action) {
            return Err(InvariantError::at(Invariant::Action, chain.hops.len() - 1));
        }
        Ok(checked)
    }

    /// The invariants that need no request (1 to 9 of the module docs).
    ///
    /// # Errors
    ///
    /// The first invariant broken.
    pub fn check_chain(&self, chain: &NormalizedChain) -> Result<Checked, InvariantError> {
        shape(&chain.hops)?;
        links(chain)?;
        if let Some(i) = chain
            .hops
            .iter()
            .position(|h| h.principal != chain.principal)
        {
            return Err(InvariantError::at(Invariant::Principal, i));
        }
        expiry(&chain.hops)?;
        let depth_semantics = DepthSemantics::for_profile(chain.profile);
        depth(&chain.hops, depth_semantics)?;
        audience(&chain.hops)?;
        repeats(&chain.hops)?;
        assurance(&chain.hops)?;
        self.authority(&chain.hops)?;
        Ok(Checked { depth_semantics })
    }

    /// Every verified hop's authority has an algebra, and each verified hop's
    /// authority is subsumed by its verified parent's. Declared hops are
    /// never used for authorization, so their authority is not judged.
    fn authority(&self, hops: &[Hop]) -> Result<(), InvariantError> {
        let mut parent: Option<&Hop> = None;
        for (i, hop) in hops.iter().enumerate() {
            if hop.assurance != Assurance::Verified {
                continue;
            }
            if self.algebras.get(&hop.authority.detail_type).is_none() {
                return Err(InvariantError::at(Invariant::UnknownAuthority, i));
            }
            if let Some(p) = parent
                && !self.algebras.subsumes(&p.authority, &hop.authority)
            {
                return Err(InvariantError::at(Invariant::Attenuation, i));
            }
            parent = Some(hop);
        }
        Ok(())
    }
}

/// At least one hop, at most [`MAX_HOPS`], and hop `i` at depth `i`.
fn shape(hops: &[Hop]) -> Result<(), InvariantError> {
    if hops.is_empty() || hops.len() > MAX_HOPS {
        return Err(InvariantError::chain(Invariant::Shape));
    }
    match hops
        .iter()
        .enumerate()
        .find(|(i, h)| usize::try_from(h.depth).ok() != Some(*i))
    {
        Some((i, _)) => Err(InvariantError::at(Invariant::Shape, i)),
        None => Ok(()),
    }
}

fn links(chain: &NormalizedChain) -> Result<(), InvariantError> {
    let mut parent: Option<&Hop> = None;
    for (i, hop) in chain.hops.iter().enumerate() {
        let signed = match hop.signer_binding {
            SignerBinding::RootAnchor => hop.signer == chain.root.key,
            SignerBinding::ParentCnf => parent
                .and_then(|p| p.cnf.as_ref())
                .is_some_and(|cnf| cnf.thumbprint == hop.signer),
        };
        let linked = match parent {
            None => {
                hop.link == Link::Root
                    && hop.delegator.is_none()
                    && hop.signer_binding == SignerBinding::RootAnchor
            }
            Some(p) => {
                hop.delegator.as_ref() == Some(&p.actor)
                    && match &hop.link {
                        Link::Root => false,
                        Link::ParHash(digest) => !digest.is_empty(),
                        // Nested in the parent's token: the same token and
                        // signer.
                        Link::Nested => hop.id == p.id && hop.signer == p.signer,
                    }
            }
        };
        if !(signed && linked) {
            return Err(InvariantError::at(Invariant::Link, i));
        }
        parent = Some(hop);
    }
    Ok(())
}

fn expiry(hops: &[Hop]) -> Result<(), InvariantError> {
    match hops
        .windows(2)
        .position(|w| w[1].validity.expires_at > w[0].validity.expires_at)
    {
        Some(i) => Err(InvariantError::at(Invariant::Expiry, i + 1)),
        None => Ok(()),
    }
}

fn depth(hops: &[Hop], semantics: DepthSemantics) -> Result<(), InvariantError> {
    let err = |i| Err(InvariantError::at(Invariant::Depth, i));
    let root_max = hops.first().and_then(|h| h.max_depth);
    let mut parent_max: Option<u32> = None;
    for (i, hop) in hops.iter().enumerate() {
        let ok = match semantics {
            DepthSemantics::AsorStrict => root_max.is_some_and(|root| {
                hop.depth <= root && hop.max_depth.is_none_or(|own| own <= root)
            }),
            DepthSemantics::AatHolderCap => hop.max_depth.is_some_and(|own| {
                hop.depth <= own && parent_max.is_none_or(|p| own <= p && hop.depth <= p)
            }),
            DepthSemantics::Uncapped => hop.max_depth.is_none_or(|own| hop.depth <= own),
        };
        if !ok {
            return err(i);
        }
        parent_max = hop.max_depth;
    }
    Ok(())
}

/// A hop without an audience inherits its parent's restriction; one with an
/// audience must name a non-empty subset of the restriction in force.
fn audience(hops: &[Hop]) -> Result<(), InvariantError> {
    let mut in_force: Option<&[String]> = None;
    for (i, hop) in hops.iter().enumerate() {
        let Some(own) = hop.audience.as_deref() else {
            continue;
        };
        let narrower = !own.is_empty()
            && in_force.is_none_or(|allowed| own.iter().all(|a| allowed.contains(a)));
        if !narrower {
            return Err(InvariantError::at(Invariant::Audience, i));
        }
        in_force = Some(own);
    }
    Ok(())
}

/// Every hop that is its own token has a distinct identifier. A holder may
/// appear more than once (AAT-02 §6.2 allows a holder to derive a token for
/// itself, and keys may cycle), and a hop nested in its parent's token
/// shares that token's identifier.
fn repeats(hops: &[Hop]) -> Result<(), InvariantError> {
    let mut seen = HashSet::new();
    for (i, hop) in hops.iter().enumerate() {
        if hop.link != Link::Nested && !seen.insert(hop.id.as_str()) {
            return Err(InvariantError::at(Invariant::Repeat, i));
        }
    }
    Ok(())
}

/// Declared hops may only precede verified ones, and the leaf is verified.
fn assurance(hops: &[Hop]) -> Result<(), InvariantError> {
    let mut verified = false;
    for (i, hop) in hops.iter().enumerate() {
        match hop.assurance {
            Assurance::Verified => verified = true,
            Assurance::Declared if verified => {
                return Err(InvariantError::at(Invariant::Assurance, i));
            }
            Assurance::Declared => {}
        }
    }
    if verified {
        Ok(())
    } else {
        Err(InvariantError::at(Invariant::Assurance, hops.len() - 1))
    }
}
