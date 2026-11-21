//! A bounded, in-memory record of recent decisions, for the chain view.
//!
//! Each [`RequestSummary`] holds identifiers and outcomes only: never a
//! token, a proof, a signature, a header value or a body. Strings are cut to
//! [`MAX_TEXT`] characters and chains to [`MAX_HOPS`] hops, so one entry stays
//! small whatever the request carried.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use visado_chain::{ActorId, Assurance, Link, NormalizedChain, Principal};

/// The longest string kept in a summary, in characters. Longer ones are cut
/// and end with `…`.
pub const MAX_TEXT: usize = 256;

/// The most hops kept per chain. The rest are counted in
/// [`ChainSummary::hops_omitted`].
pub const MAX_HOPS: usize = 32;

/// The last decisions, oldest dropped first.
#[derive(Debug)]
pub struct RequestLog {
    capacity: usize,
    entries: Mutex<VecDeque<RequestSummary>>,
}

impl RequestLog {
    /// A log that keeps the last `capacity` decisions. With 0 it keeps none.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
        }
    }

    /// How many decisions the log keeps.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Adds `summary`, dropping the oldest entry when full.
    pub fn record(&self, summary: RequestSummary) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self.lock();
        while entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(summary);
    }

    /// Up to `limit` entries, newest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<RequestSummary> {
        self.lock().iter().rev().take(limit).cloned().collect()
    }

    /// The entry with `id`, if it is still kept.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<RequestSummary> {
        self.lock().iter().rev().find(|s| s.id == id).cloned()
    }

    /// How many entries are kept now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no entry is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<RequestSummary>> {
        // The deque is valid after any panic in these methods.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The gate's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Forwarded with a Transaction Token.
    Allow,
    /// Rejected.
    Deny,
}

/// What the PDP said, if it was asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase", tag = "result", content = "code")]
pub enum PdpResult {
    /// The PDP allowed the request.
    Allow,
    /// The PDP denied the request.
    Deny,
    /// The call failed, with this code; the gate denied.
    Error(String),
}

/// One decision, as the chain view shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestSummary {
    /// This check's own identifier: the `txn` the gate would mint with.
    /// Unique per check, unlike [`txn`](Self::txn).
    pub id: String,
    /// The transaction the request belongs to: the new one, or the one of a
    /// forwarded Transaction Token. `None` when the gate stopped before it
    /// was known.
    pub txn: Option<String>,
    /// When the gate decided, in seconds since the Unix epoch.
    pub time: u64,
    /// HTTP method.
    pub method: String,
    /// `scheme://authority/path`, without the query.
    pub resource: String,
    /// The authenticated caller, if authentication succeeded.
    pub caller: Option<String>,
    /// How the caller authenticated, such as `wit-wpt`.
    pub auth_method: Option<&'static str>,
    /// On whose behalf, once known.
    pub principal: Option<String>,
    /// The gate's decision.
    pub decision: Decision,
    /// The HTTP status: 200 for an allow.
    pub status: u16,
    /// The stable reason code: `ok` for an allow.
    pub code: String,
    /// What the PDP said, if it was asked.
    pub pdp: Option<PdpResult>,
    /// The verified delegation chain, if the request carried one that
    /// verified.
    pub chain: Option<ChainSummary>,
}

/// A delegation chain without any of its tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainSummary {
    /// The format, such as `aat-02`.
    pub profile: &'static str,
    /// The trust anchor (issuer) of the first hop.
    pub issuer: String,
    /// The principal subject, if the format names one.
    pub principal: Option<String>,
    /// Whether the presenter proved possession of the leaf holder key.
    pub holder_proof: bool,
    /// The hops, first hop first.
    pub hops: Vec<HopSummary>,
    /// Hops left out after [`MAX_HOPS`].
    pub hops_omitted: usize,
}

/// One hop: who held it and how it was checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopSummary {
    /// Position in the chain; the first hop is 0.
    pub depth: u32,
    /// `key`, `name` or `subject`.
    pub actor_kind: &'static str,
    /// The key thumbprint, name or subject of the actor.
    pub actor: String,
    /// The issuer that named a `subject` actor.
    pub actor_issuer: Option<String>,
    /// `verified` or `declared`.
    pub assurance: &'static str,
    /// How the hop is bound to the previous one: `root`, `par_hash` or
    /// `nested`.
    pub link: &'static str,
    /// The thumbprint of the hop's holder key, if it is sender-constrained.
    pub holder: Option<String>,
}

impl ChainSummary {
    /// The parts of `chain` the chain view shows. Signatures, digests, the
    /// authority and the tokens themselves are left out.
    #[must_use]
    pub fn from_chain(chain: &NormalizedChain) -> Self {
        let principal = match &chain.principal {
            Principal::Subject { subject, .. } => Some(bounded(subject)),
            _ => None,
        };
        Self {
            profile: chain.profile.as_str(),
            issuer: bounded(&chain.root.issuer),
            principal,
            holder_proof: chain.holder_proof,
            hops: chain
                .hops
                .iter()
                .take(MAX_HOPS)
                .map(|hop| {
                    let (actor_kind, actor, actor_issuer) = match &hop.actor {
                        ActorId::Key(key) => ("key", bounded(&key.0), None),
                        ActorId::Name(name) => ("name", bounded(name), None),
                        ActorId::Subject { issuer, subject } => {
                            ("subject", bounded(subject), Some(bounded(issuer)))
                        }
                        _ => ("unknown", String::new(), None),
                    };
                    HopSummary {
                        depth: hop.depth,
                        actor_kind,
                        actor,
                        actor_issuer,
                        assurance: match hop.assurance {
                            Assurance::Verified => "verified",
                            Assurance::Declared => "declared",
                        },
                        link: match hop.link {
                            Link::Root => "root",
                            Link::ParHash(_) => "par_hash",
                            Link::Nested => "nested",
                            _ => "unknown",
                        },
                        holder: hop.cnf.as_ref().map(|c| bounded(&c.thumbprint.0)),
                    }
                })
                .collect(),
            hops_omitted: chain.hops.len().saturating_sub(MAX_HOPS),
        }
    }
}

/// `text` cut to [`MAX_TEXT`] characters.
#[must_use]
pub fn bounded(text: &str) -> String {
    match text.char_indices().nth(MAX_TEXT) {
        None => text.to_owned(),
        Some((end, _)) => {
            let mut cut = text[..end].to_owned();
            cut.pop();
            cut.push('…');
            cut
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, MAX_HOPS, MAX_TEXT, RequestLog, RequestSummary, bounded};
    use visado_chain::{
        ActorId, Assurance, Authority, Cnf, Hop, KeyThumbprint, Link, NormalizedChain, Principal,
        Profile, SignerBinding, TrustRef, Validity,
    };

    fn summary(id: &str) -> RequestSummary {
        RequestSummary {
            id: id.into(),
            txn: None,
            time: 1,
            method: "GET".into(),
            resource: "https://tools.example/".into(),
            caller: None,
            auth_method: None,
            principal: None,
            decision: Decision::Deny,
            status: 401,
            code: "credential.missing".into(),
            pdp: None,
            chain: None,
        }
    }

    #[test]
    fn keeps_the_last_entries_newest_first() {
        let log = RequestLog::new(3);
        for i in 0..5 {
            log.record(summary(&format!("r{i}")));
        }
        assert_eq!(log.len(), 3);
        let ids: Vec<String> = log.recent(10).into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["r4", "r3", "r2"]);
        assert_eq!(log.recent(1)[0].id, "r4");
        assert!(log.get("r1").is_none(), "evicted");
        assert_eq!(log.get("r2").unwrap().id, "r2");
    }

    #[test]
    fn capacity_zero_keeps_nothing() {
        let log = RequestLog::new(0);
        log.record(summary("r0"));
        assert!(log.is_empty());
        assert_eq!(log.recent(10).len(), 0);
        assert!(log.get("r0").is_none());
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        assert_eq!(bounded("short"), "short");
        let exact = "a".repeat(MAX_TEXT);
        assert_eq!(bounded(&exact), exact);
        let long = "é".repeat(MAX_TEXT + 10);
        let cut = bounded(&long);
        assert_eq!(cut.chars().count(), MAX_TEXT);
        assert!(cut.ends_with('…'));
    }

    fn hop(depth: u32, assurance: Assurance) -> Hop {
        Hop {
            id: format!("jti-{depth}"),
            depth,
            max_depth: None,
            actor: ActorId::Name(format!("agent-{depth}")),
            principal: Principal::Unspecified,
            delegator: None,
            signer: KeyThumbprint("signer".into()),
            signer_binding: SignerBinding::ParentCnf,
            link: if depth == 0 {
                Link::Root
            } else {
                Link::ParHash("digest".into())
            },
            authority: Authority {
                detail_type: "tool".into(),
                json: r#"{"secret":"do-not-copy"}"#.into(),
            },
            validity: Validity {
                issued_at: 0,
                expires_at: 1,
            },
            audience: None,
            cnf: Some(Cnf {
                thumbprint: KeyThumbprint(format!("jkt-{depth}")),
            }),
            status: None,
            assurance,
        }
    }

    #[test]
    fn a_chain_keeps_actors_and_links_and_drops_the_rest() {
        let mut hops: Vec<Hop> = (0..u32::try_from(MAX_HOPS).unwrap() + 3)
            .map(|d| hop(d, Assurance::Verified))
            .collect();
        hops[1].assurance = Assurance::Declared;
        let chain = NormalizedChain {
            profile: Profile::Aat02,
            principal: Principal::Subject {
                issuer: "https://idp".into(),
                subject: "alice".into(),
            },
            root: TrustRef {
                issuer: "https://anchor".into(),
                key: KeyThumbprint("anchor-key".into()),
            },
            hops,
            holder_proof: true,
        };
        let summary = super::ChainSummary::from_chain(&chain);
        assert_eq!(summary.hops.len(), MAX_HOPS);
        assert_eq!(summary.hops_omitted, 3);
        assert_eq!(summary.principal.as_deref(), Some("alice"));
        assert_eq!(summary.hops[0].link, "root");
        assert_eq!(summary.hops[1].assurance, "declared");
        assert_eq!(summary.hops[1].link, "par_hash");
        assert_eq!(summary.hops[2].holder.as_deref(), Some("jkt-2"));
        let json = serde_json::to_string(&summary).unwrap();
        for absent in ["do-not-copy", "digest", "signer", "jti-0", "anchor-key"] {
            assert!(!json.contains(absent), "{absent} in {json}");
        }
    }
}
