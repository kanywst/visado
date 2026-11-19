//! RFC 8693 `act` (actor) claims as delegation chains.
//!
//! An OAuth access token issued by token exchange may carry an `act` claim
//! (RFC 8693 §4.1): a JSON object whose `sub` (with `iss`, when present)
//! names the actor. A nested `act` inside it names a prior actor, and so on;
//! the outermost is the current actor and the most deeply nested the least
//! recent. RFC 8693 says that for access control a token consumer "MUST only
//! consider the token's top-level claims and the party identified as the
//! current actor", and that prior actors are informational only.
//!
//! This crate reads that claim from a token whose signature, issuer, audience
//! and lifetime were already verified (`visado-credentials` does that), and
//! produces a [`NormalizedChain`]: the principal is the token's `sub`, the
//! hops are the actors from the least recent to the current one, all signed
//! by the token's issuer key.
//!
//! - [`Verifier::decode`] checks the claim's shape: every `act` is an object
//!   with a non-empty string `sub` and, when present, a non-empty string
//!   `iss`, and there are at most [`Verifier::max_actors`] actors. Every hop
//!   is [`Assurance::Declared`] and `holder_proof` is false.
//! - [`Verifier::verify`] also binds the current actor to the authenticated
//!   caller: its `sub`, mapped through [`Verifier::with_actor`] when the
//!   operator configured a mapping for it, must equal the caller's
//!   identifier. Only then is the current actor's hop
//!   [`Assurance::Verified`]. Prior actors stay `Declared` and are never
//!   compared with anything.
//!
//! RFC 8693 defines no authority per actor, so this crate invents none: each
//! hop's [`Authority`] is an empty object, and what the token grants is its
//! top-level `scope`. Claims inside `act` other than `sub`, `iss` and `act`
//! are ignored, as §4.1 says non-identity claims there are not used.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;
use visado_chain::{
    ActorId, Assurance, Authority, ChainError, Hop, KeyThumbprint, Link, NormalizedChain,
    Principal, Profile, SignerBinding, TrustRef, Validity,
};

/// The default limit on the number of actors in one `act` claim.
pub const DEFAULT_MAX_ACTORS: usize = 8;

/// The largest limit [`Verifier::with_max_actors`] accepts.
pub const MAX_ACTORS_LIMIT: usize = 32;

/// The [`Authority::detail_type`] of every hop.
pub const DETAIL_TYPE: &str = "rfc8693-act";

/// What the adapter reads from an access token that was already verified.
#[derive(Debug, Clone, Copy)]
pub struct ActToken<'a> {
    /// `iss`.
    pub issuer: &'a str,
    /// `sub`, as the caller names it (with any subject prefix): the
    /// principal.
    pub subject: &'a str,
    /// `jti`, when present.
    pub id: Option<&'a str>,
    /// The RFC 7638 thumbprint of the issuer key that verified the token.
    pub key_thumbprint: &'a str,
    /// `iat`, when present.
    pub issued_at: Option<u64>,
    /// `exp`.
    pub expires_at: u64,
    /// The `act` claim.
    pub act: &'a Value,
}

/// The authenticated party presenting the token.
#[derive(Debug, Clone, Copy)]
pub struct Caller<'a> {
    /// The caller's identifier: a workload identifier, or the OAuth client.
    pub id: &'a str,
    /// Whether the caller proved possession of a key for this request (a
    /// WIT or mTLS), rather than presenting only bearer tokens.
    pub proved_key: bool,
}

/// Why an `act` claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActError {
    /// An `act` value, outermost or nested, is not a JSON object.
    NotObject,
    /// An actor has no `sub`, or its `sub` is not a non-empty string.
    MissingSub,
    /// An actor's `iss` is present but not a non-empty string.
    BadIssuer,
    /// The claim names more actors than the verifier allows.
    TooDeep,
    /// The current actor is not the authenticated caller.
    ActorMismatch,
}

impl ActError {
    /// The stable code, as used in vectors and audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotObject => "act.not_object",
            Self::MissingSub => "act.missing_sub",
            Self::BadIssuer => "act.bad_issuer",
            Self::TooDeep => "act.too_deep",
            Self::ActorMismatch => "act.actor_mismatch",
        }
    }
}

impl fmt::Display for ActError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotObject => "an act claim is not a JSON object",
            Self::MissingSub => "an actor has no non-empty string sub",
            Self::BadIssuer => "an actor's iss is not a non-empty string",
            Self::TooDeep => "the act claim names too many actors",
            Self::ActorMismatch => "the current actor is not the authenticated caller",
        })
    }
}

impl std::error::Error for ActError {}

impl ChainError for ActError {
    fn code(&self) -> &'static str {
        self.as_str()
    }
}

/// Reads `act` claims and binds the current actor to the caller.
#[derive(Debug, Clone)]
pub struct Verifier {
    max_actors: usize,
    actors: BTreeMap<String, String>,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    /// A verifier allowing [`DEFAULT_MAX_ACTORS`] actors, with no mapping:
    /// the current actor's `sub` must equal the caller's identifier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_actors: DEFAULT_MAX_ACTORS,
            actors: BTreeMap::new(),
        }
    }

    /// Allows at most `max` actors (the current one and its prior actors),
    /// clamped to `1..=`[`MAX_ACTORS_LIMIT`].
    #[must_use]
    pub fn with_max_actors(mut self, max: usize) -> Self {
        self.max_actors = max.clamp(1, MAX_ACTORS_LIMIT);
        self
    }

    /// The most actors one claim may name.
    #[must_use]
    pub const fn max_actors(&self) -> usize {
        self.max_actors
    }

    /// Binds the actor whose `act.sub` is `actor` to the caller identified
    /// as `caller`, for issuers that name an actor differently from how the
    /// caller authenticates (a client ID for a workload's SPIFFE ID, say).
    /// A mapped `sub` is bound only to its mapped caller.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>, caller: impl Into<String>) -> Self {
        self.actors.insert(actor.into(), caller.into());
        self
    }

    /// The caller identifier the current actor `sub` must authenticate as.
    #[must_use]
    pub fn bound_caller<'a>(&'a self, actor: &'a str) -> &'a str {
        self.actors.get(actor).map_or(actor, String::as_str)
    }

    /// Checks the shape of `token`'s `act` claim and returns the chain, with
    /// every hop [`Assurance::Declared`] and `holder_proof` false. The
    /// current actor is the last hop.
    ///
    /// # Errors
    ///
    /// The first shape check that failed, outermost actor first.
    pub fn decode(&self, token: &ActToken<'_>) -> Result<NormalizedChain, ActError> {
        let mut actors = self.actors_of(token.act)?;
        actors.reverse();
        let signer = KeyThumbprint(token.key_thumbprint.to_owned());
        let validity = Validity {
            issued_at: token.issued_at.map_or(0, saturate),
            expires_at: saturate(token.expires_at),
        };
        let mut hops: Vec<Hop> = Vec::with_capacity(actors.len());
        for (depth, actor) in actors.into_iter().enumerate() {
            let actor = ActorId::Subject {
                issuer: actor.iss.unwrap_or_else(|| token.issuer.to_owned()),
                subject: actor.sub,
            };
            let delegator = hops.last().map(|previous| previous.actor.clone());
            hops.push(Hop {
                id: token.id.unwrap_or_default().to_owned(),
                depth: u32::try_from(depth).unwrap_or(u32::MAX),
                max_depth: None,
                actor,
                link: if delegator.is_some() {
                    Link::Nested
                } else {
                    Link::Root
                },
                delegator,
                signer: signer.clone(),
                signer_binding: SignerBinding::RootAnchor,
                authority: Authority {
                    detail_type: DETAIL_TYPE.to_owned(),
                    json: "{}".to_owned(),
                },
                validity,
                audience: None,
                cnf: None,
                assurance: Assurance::Declared,
            });
        }
        Ok(NormalizedChain {
            profile: Profile::Rfc8693Act,
            principal: Principal::Subject {
                issuer: token.issuer.to_owned(),
                subject: token.subject.to_owned(),
            },
            root: TrustRef {
                issuer: token.issuer.to_owned(),
                key: signer,
            },
            hops,
            holder_proof: false,
        })
    }

    /// Like [`decode`](Self::decode), then requires the current actor to be
    /// `caller`: its `sub`, mapped by [`with_actor`](Self::with_actor) when a
    /// mapping exists, must equal `caller.id`. Prior actors are not
    /// compared. On success the current actor's hop is
    /// [`Assurance::Verified`] and `holder_proof` is `caller.proved_key`.
    ///
    /// # Errors
    ///
    /// A shape error from `decode`, or [`ActError::ActorMismatch`].
    pub fn verify(
        &self,
        token: &ActToken<'_>,
        caller: &Caller<'_>,
    ) -> Result<NormalizedChain, ActError> {
        let mut chain = self.decode(token)?;
        let current = chain.hops.last_mut().ok_or(ActError::NotObject)?;
        let ActorId::Subject { subject, .. } = &current.actor else {
            return Err(ActError::MissingSub);
        };
        if self.bound_caller(subject) != caller.id {
            return Err(ActError::ActorMismatch);
        }
        current.assurance = Assurance::Verified;
        chain.holder_proof = caller.proved_key;
        Ok(chain)
    }

    /// The actors, outermost (current) first.
    fn actors_of(&self, act: &Value) -> Result<Vec<Actor>, ActError> {
        let mut actors = Vec::new();
        let mut next = Some(act);
        while let Some(value) = next {
            let Value::Object(object) = value else {
                return Err(ActError::NotObject);
            };
            if actors.len() == self.max_actors {
                return Err(ActError::TooDeep);
            }
            let sub = match object.get("sub") {
                Some(Value::String(sub)) if !sub.is_empty() => sub.clone(),
                _ => return Err(ActError::MissingSub),
            };
            let iss = match object.get("iss") {
                None => None,
                Some(Value::String(iss)) if !iss.is_empty() => Some(iss.clone()),
                Some(_) => return Err(ActError::BadIssuer),
            };
            actors.push(Actor { sub, iss });
            next = object.get("act");
        }
        Ok(actors)
    }
}

struct Actor {
    sub: String,
    iss: Option<String>,
}

fn saturate(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use visado_chain::{ActorId, Assurance, Link, Principal};

    use super::{ActError, ActToken, Caller, MAX_ACTORS_LIMIT, Verifier};

    fn token(act: &Value) -> ActToken<'_> {
        ActToken {
            issuer: "https://as.example",
            subject: "alice",
            id: Some("at-1"),
            key_thumbprint: "kt",
            issued_at: Some(100),
            expires_at: 200,
            act,
        }
    }

    fn nested(depth: usize) -> Value {
        let mut act = json!({ "sub": "a0" });
        for i in 1..depth {
            act = json!({ "sub": format!("a{i}"), "act": act });
        }
        act
    }

    fn subject(actor: &ActorId) -> &str {
        match actor {
            ActorId::Subject { subject, .. } => subject,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn hops_run_from_the_least_recent_actor_to_the_current_one() {
        let act = json!({ "sub": "current", "act": { "sub": "prior", "iss": "https://other" } });
        let chain = Verifier::new().decode(&token(&act)).unwrap();
        assert_eq!(chain.hops.len(), 2);
        assert_eq!(
            chain.hops[0].actor,
            ActorId::Subject {
                issuer: "https://other".into(),
                subject: "prior".into()
            }
        );
        assert_eq!(
            chain.hops[1].actor,
            ActorId::Subject {
                issuer: "https://as.example".into(),
                subject: "current".into()
            }
        );
        assert_eq!(chain.hops[0].link, Link::Root);
        assert_eq!(chain.hops[1].link, Link::Nested);
        assert_eq!(chain.hops[1].delegator, Some(chain.hops[0].actor.clone()));
        assert_eq!(chain.hops[1].depth, 1);
        assert_eq!(chain.hops[1].validity.issued_at, 100);
        assert_eq!(chain.root.key.0, "kt");
        assert_eq!(
            chain.principal,
            Principal::Subject {
                issuer: "https://as.example".into(),
                subject: "alice".into()
            }
        );
        assert!(
            chain
                .hops
                .iter()
                .all(|h| h.assurance == Assurance::Declared)
        );
        assert!(!chain.holder_proof);
    }

    #[test]
    fn only_the_current_actor_is_bound_and_verified() {
        let act = json!({ "sub": "agent-b", "act": { "sub": "agent-a" } });
        let verifier = Verifier::new();
        let chain = verifier
            .verify(
                &token(&act),
                &Caller {
                    id: "agent-b",
                    proved_key: true,
                },
            )
            .unwrap();
        assert_eq!(chain.hops[0].assurance, Assurance::Declared);
        assert_eq!(chain.hops[1].assurance, Assurance::Verified);
        assert!(chain.holder_proof);
        let prior = Caller {
            id: "agent-a",
            proved_key: true,
        };
        assert_eq!(
            verifier.verify(&token(&act), &prior),
            Err(ActError::ActorMismatch)
        );
        let bearer = Caller {
            id: "agent-b",
            proved_key: false,
        };
        assert!(!verifier.verify(&token(&act), &bearer).unwrap().holder_proof);
    }

    #[test]
    fn a_mapping_replaces_the_exact_match() {
        let act = json!({ "sub": "client-7" });
        let verifier = Verifier::new().with_actor("client-7", "spiffe://td.example/agent");
        let mapped = Caller {
            id: "spiffe://td.example/agent",
            proved_key: true,
        };
        assert!(verifier.verify(&token(&act), &mapped).is_ok());
        let literal = Caller {
            id: "client-7",
            proved_key: false,
        };
        assert_eq!(
            verifier.verify(&token(&act), &literal),
            Err(ActError::ActorMismatch)
        );
    }

    #[test]
    fn depth_is_limited() {
        let verifier = Verifier::new().with_max_actors(3);
        assert_eq!(verifier.decode(&token(&nested(3))).unwrap().hops.len(), 3);
        assert_eq!(verifier.decode(&token(&nested(4))), Err(ActError::TooDeep));
        assert_eq!(
            Verifier::new().with_max_actors(0).max_actors(),
            1,
            "clamped up"
        );
        assert_eq!(
            Verifier::new().with_max_actors(1000).max_actors(),
            MAX_ACTORS_LIMIT
        );
        let deep = nested(MAX_ACTORS_LIMIT + 1);
        assert_eq!(
            Verifier::new()
                .with_max_actors(MAX_ACTORS_LIMIT)
                .decode(&token(&deep)),
            Err(ActError::TooDeep)
        );
    }

    #[test]
    fn shape_errors() {
        let cases = [
            (json!("agent"), ActError::NotObject),
            (json!(["agent"]), ActError::NotObject),
            (json!(null), ActError::NotObject),
            (json!({ "sub": "a", "act": 1 }), ActError::NotObject),
            (json!({ "sub": "a", "act": null }), ActError::NotObject),
            (json!({}), ActError::MissingSub),
            (json!({ "sub": 7 }), ActError::MissingSub),
            (json!({ "sub": "" }), ActError::MissingSub),
            (
                json!({ "sub": "a", "act": { "iss": "x" } }),
                ActError::MissingSub,
            ),
            (json!({ "sub": "a", "iss": 1 }), ActError::BadIssuer),
            (json!({ "sub": "a", "iss": "" }), ActError::BadIssuer),
        ];
        for (act, expected) in cases {
            assert_eq!(Verifier::new().decode(&token(&act)), Err(expected), "{act}");
        }
    }

    #[test]
    fn non_identity_claims_in_act_are_ignored() {
        let act = json!({ "sub": "a", "exp": 1, "aud": "x", "scope": "admin" });
        let chain = Verifier::new().decode(&token(&act)).unwrap();
        assert_eq!(subject(&chain.hops[0].actor), "a");
        assert_eq!(chain.hops[0].authority.json, "{}");
    }

    #[test]
    fn codes_are_stable() {
        use visado_chain::ChainError;
        assert_eq!(ActError::NotObject.code(), "act.not_object");
        assert_eq!(ActError::MissingSub.code(), "act.missing_sub");
        assert_eq!(ActError::BadIssuer.code(), "act.bad_issuer");
        assert_eq!(ActError::TooDeep.code(), "act.too_deep");
        assert_eq!(ActError::ActorMismatch.code(), "act.actor_mismatch");
    }
}
