//! Each invariant of the engine, broken one at a time on a chain that holds
//! them all.

use std::sync::Arc;

use visado_chain::algebra::{Action, Algebras, AuthorityAlgebra};
use visado_chain::invariants::{DepthSemantics, Engine, Invariant, InvariantError, MAX_HOPS};
use visado_chain::{
    ActorId, Assurance, Authority, Cnf, Hop, KeyThumbprint, Link, NormalizedChain, Principal,
    Profile, SignerBinding, StatusCheck, TrustRef, Validity,
};

/// Authorities are comma-separated names; a child may only drop names, and
/// an action is allowed when its name is listed.
#[derive(Debug)]
struct Names;

fn names(a: &Authority) -> Vec<&str> {
    a.json.split(',').filter(|s| !s.is_empty()).collect()
}

impl AuthorityAlgebra for Names {
    fn detail_type(&self) -> &'static str {
        "names"
    }
    fn subsumes(&self, parent: &Authority, child: &Authority) -> bool {
        names(child).iter().all(|c| names(parent).contains(c))
    }
    fn permits(&self, leaf: &Authority, action: Option<&Action<'_>>) -> bool {
        action.is_some_and(|a| names(leaf).contains(&a.name))
    }
}

fn engine() -> Engine {
    Engine::new(Algebras::new().with(Arc::new(Names)))
}

fn key(i: usize) -> KeyThumbprint {
    KeyThumbprint(format!("key-{i}"))
}

fn principal() -> Principal {
    Principal::Subject {
        issuer: "https://as.example".into(),
        subject: "alice".into(),
    }
}

/// An AAT-shaped chain of `n` hops: each signed by its parent's `cnf`, the
/// authority narrowing from `a,b,c`, exp and depth caps non-increasing.
fn chain(n: usize) -> NormalizedChain {
    let mut hops: Vec<Hop> = Vec::new();
    for i in 0..n {
        let depth = u32::try_from(i).unwrap();
        let parent = hops.last();
        hops.push(Hop {
            id: format!("jti-{i}"),
            depth,
            max_depth: Some(4),
            actor: ActorId::Key(key(i + 1)),
            principal: principal(),
            delegator: parent.map(|p| p.actor.clone()),
            signer: if i == 0 { key(0) } else { key(i) },
            signer_binding: if i == 0 {
                SignerBinding::RootAnchor
            } else {
                SignerBinding::ParentCnf
            },
            link: if i == 0 {
                Link::Root
            } else {
                Link::ParHash(format!("hash-{i}"))
            },
            authority: Authority {
                detail_type: "names".into(),
                json: ["a", "b", "c"][..3 - i.min(2)].join(","),
            },
            validity: Validity {
                issued_at: 100,
                expires_at: 1000 - i64::from(depth),
            },
            audience: Some(vec!["https://rs.example".into()]),
            cnf: Some(Cnf {
                thumbprint: key(i + 1),
            }),
            status: Some(StatusCheck::Valid),
            assurance: Assurance::Verified,
        });
    }
    NormalizedChain {
        profile: Profile::Aat02,
        principal: principal(),
        root: TrustRef {
            issuer: "https://as.example".into(),
            key: key(0),
        },
        hops,
        holder_proof: true,
    }
}

const ACTION: Action<'static> = Action {
    name: "a",
    params_json: "{}",
};

fn deny(chain: &NormalizedChain) -> InvariantError {
    engine()
        .check(chain, Some(&ACTION))
        .expect_err("the engine must deny")
}

fn assert_denied(chain: &NormalizedChain, invariant: Invariant, hop: Option<usize>) {
    assert_eq!(deny(chain), InvariantError { invariant, hop }, "{chain:#?}");
}

#[test]
fn a_well_formed_chain_holds_every_invariant() {
    for n in 1..=4 {
        let checked = engine().check(&chain(n), Some(&ACTION)).unwrap();
        assert_eq!(checked.depth_semantics, DepthSemantics::AatHolderCap);
    }
}

#[test]
fn shape() {
    assert_denied(&chain(0), Invariant::Shape, None);
    let mut c = chain(3);
    c.hops[2].depth = 3;
    assert_denied(&c, Invariant::Shape, Some(2));
    let mut c = chain(1);
    c.profile = Profile::Rfc8693Act;
    let hop = c.hops[0].clone();
    c.hops = (0..=MAX_HOPS)
        .map(|i| Hop {
            depth: u32::try_from(i).unwrap(),
            ..hop.clone()
        })
        .collect();
    assert_denied(&c, Invariant::Shape, None);
}

#[test]
fn links() {
    let mut c = chain(3);
    c.hops[0].link = Link::ParHash("x".into());
    assert_denied(&c, Invariant::Link, Some(0));
    let mut c = chain(3);
    c.hops[0].signer = key(9);
    assert_denied(&c, Invariant::Link, Some(0));
    let mut c = chain(3);
    c.hops[0].signer_binding = SignerBinding::ParentCnf;
    assert_denied(&c, Invariant::Link, Some(0));
    let mut c = chain(3);
    c.hops[0].delegator = Some(ActorId::Name("x".into()));
    assert_denied(&c, Invariant::Link, Some(0));
    let mut c = chain(3);
    c.hops[2].signer = key(1);
    assert_denied(&c, Invariant::Link, Some(2));
    let mut c = chain(3);
    c.hops[1].cnf = None;
    assert_denied(&c, Invariant::Link, Some(2));
    let mut c = chain(3);
    c.hops[2].delegator = Some(c.hops[0].actor.clone());
    assert_denied(&c, Invariant::Link, Some(2));
    let mut c = chain(3);
    c.hops[2].link = Link::Root;
    assert_denied(&c, Invariant::Link, Some(2));
    let mut c = chain(3);
    c.hops[2].link = Link::ParHash(String::new());
    assert_denied(&c, Invariant::Link, Some(2));
    let mut c = chain(3);
    c.hops[2].link = Link::Nested;
    assert_denied(&c, Invariant::Link, Some(2));
    let mut c = chain(3);
    c.hops[2].signer_binding = SignerBinding::RootAnchor;
    assert_denied(&c, Invariant::Link, Some(2));
}

#[test]
fn principal_never_changes() {
    let mut c = chain(3);
    c.hops[2].principal = Principal::Subject {
        issuer: "https://as.example".into(),
        subject: "mallory".into(),
    };
    assert_denied(&c, Invariant::Principal, Some(2));
    let mut c = chain(2);
    c.hops[1].principal = Principal::Unspecified;
    assert_denied(&c, Invariant::Principal, Some(1));
}

#[test]
fn exp_is_monotone() {
    let mut c = chain(3);
    c.hops[2].validity.expires_at = c.hops[1].validity.expires_at + 1;
    assert_denied(&c, Invariant::Expiry, Some(2));
    let mut c = chain(3);
    c.hops[2].validity.expires_at = c.hops[1].validity.expires_at;
    assert!(
        engine().check(&c, Some(&ACTION)).is_ok(),
        "equal is allowed"
    );
}

#[test]
fn aat_holder_caps() {
    let mut c = chain(3);
    c.hops[2].max_depth = Some(1);
    assert_denied(&c, Invariant::Depth, Some(2));
    let mut c = chain(3);
    c.hops[2].max_depth = Some(5);
    assert_denied(&c, Invariant::Depth, Some(2));
    let mut c = chain(3);
    c.hops[1].max_depth = Some(1);
    c.hops[2].max_depth = Some(2);
    assert_denied(&c, Invariant::Depth, Some(2));
    let mut c = chain(2);
    c.hops[1].max_depth = None;
    assert_denied(&c, Invariant::Depth, Some(1));
}

#[test]
fn asor_strict_depth() {
    let asor = |c: &mut NormalizedChain, root: Option<u32>| {
        c.profile = Profile::Asor03;
        for hop in &mut c.hops {
            hop.max_depth = root;
        }
    };
    let mut c = chain(3);
    asor(&mut c, Some(2));
    let checked = engine().check(&c, Some(&ACTION)).unwrap();
    assert_eq!(checked.depth_semantics, DepthSemantics::AsorStrict);
    asor(&mut c, Some(1));
    assert_denied(&c, Invariant::Depth, Some(2));
    asor(&mut c, None);
    assert_denied(&c, Invariant::Depth, Some(0));
    asor(&mut c, Some(2));
    c.hops[1].max_depth = Some(3);
    assert_denied(&c, Invariant::Depth, Some(1));
    // Under asor only the first hop's bound counts: a later hop's own
    // smaller bound does not cap its descendants here.
    asor(&mut c, Some(2));
    c.hops[1].max_depth = Some(1);
    assert!(engine().check(&c, Some(&ACTION)).is_ok());
}

#[test]
fn uncapped_depth() {
    let mut c = chain(3);
    c.profile = Profile::Rfc8693Act;
    for hop in &mut c.hops {
        hop.max_depth = None;
    }
    assert_eq!(
        engine().check(&c, Some(&ACTION)).unwrap().depth_semantics,
        DepthSemantics::Uncapped
    );
    c.hops[2].max_depth = Some(1);
    assert_denied(&c, Invariant::Depth, Some(2));
}

#[test]
fn audiences_only_narrow() {
    let mut c = chain(3);
    c.hops[2].audience = Some(vec!["https://rs.example".into(), "https://other".into()]);
    assert_denied(&c, Invariant::Audience, Some(2));
    let mut c = chain(3);
    c.hops[1].audience = None;
    c.hops[2].audience = Some(vec!["https://other".into()]);
    assert_denied(&c, Invariant::Audience, Some(2));
    let mut c = chain(3);
    c.hops[2].audience = Some(vec![]);
    assert_denied(&c, Invariant::Audience, Some(2));
    // An unrestricted hop inherits; an unrestricted root lets a child set one.
    let mut c = chain(3);
    c.hops[0].audience = None;
    c.hops[1].audience = None;
    assert!(engine().check(&c, Some(&ACTION)).is_ok());
}

#[test]
fn no_token_repeats() {
    let mut c = chain(3);
    c.hops[2].id = c.hops[0].id.clone();
    assert_denied(&c, Invariant::Repeat, Some(2));
    // A holder may repeat (AAT-02 §6.2).
    let mut c = chain(3);
    c.hops[2].actor = c.hops[0].actor.clone();
    assert!(engine().check(&c, Some(&ACTION)).is_ok());
}

#[test]
fn nested_hops_share_their_token() {
    let mut c = chain(2);
    c.profile = Profile::Rfc8693Act;
    for hop in &mut c.hops {
        hop.max_depth = None;
        hop.signer = key(0);
        hop.signer_binding = SignerBinding::RootAnchor;
        hop.id = "at-1".into();
    }
    c.hops[1].link = Link::Nested;
    c.hops[0].assurance = Assurance::Declared;
    assert!(engine().check(&c, Some(&ACTION)).is_ok());
    c.hops[1].id = "at-2".into();
    assert_denied(&c, Invariant::Link, Some(1));
}

#[test]
fn verified_hops_end_the_chain() {
    let mut c = chain(3);
    c.hops[2].assurance = Assurance::Declared;
    assert_denied(&c, Invariant::Assurance, Some(2));
    let mut c = chain(3);
    c.hops[1].assurance = Assurance::Declared;
    assert_denied(&c, Invariant::Assurance, Some(1));
    let mut c = chain(3);
    c.hops[0].assurance = Assurance::Declared;
    assert!(engine().check(&c, Some(&ACTION)).is_ok());
}

#[test]
fn authority_attenuates_and_unknown_types_are_denied() {
    let mut c = chain(3);
    c.hops[2].authority.json = "a,b,c,d".into();
    assert_denied(&c, Invariant::Attenuation, Some(2));
    let mut c = chain(3);
    c.hops[1].authority.detail_type = "other".into();
    assert_denied(&c, Invariant::UnknownAuthority, Some(1));
    // A declared hop's authority is not used, so it is not judged.
    let mut c = chain(3);
    c.hops[0].assurance = Assurance::Declared;
    c.hops[0].authority.detail_type = "other".into();
    assert!(engine().check(&c, Some(&ACTION)).is_ok());
    // With no algebras at all, every chain is denied.
    let empty = Engine::default().check(&chain(1), Some(&ACTION));
    assert_eq!(empty.unwrap_err().invariant, Invariant::UnknownAuthority);
}

#[test]
fn status_must_be_checked() {
    let mut c = chain(3);
    c.hops[1].status = Some(StatusCheck::Unchecked);
    assert_denied(&c, Invariant::Status, Some(1));
    assert!(engine().check_chain(&c).is_ok(), "check_chain skips status");
}

#[test]
fn holder_proof_is_required() {
    let mut c = chain(2);
    c.holder_proof = false;
    assert_denied(&c, Invariant::HolderProof, None);
    assert!(engine().check_chain(&c).is_ok());
}

#[test]
fn the_action_must_be_permitted() {
    let c = chain(3);
    let other = Action {
        name: "c",
        params_json: "{}",
    };
    assert_eq!(
        engine().check(&c, Some(&other)),
        Err(InvariantError {
            invariant: Invariant::Action,
            hop: Some(2)
        })
    );
    assert_eq!(
        engine().check(&c, None).unwrap_err().invariant,
        Invariant::Action
    );
}

#[test]
fn codes_are_stable() {
    use visado_chain::ChainError;
    let codes = [
        (Invariant::Shape, "chain.malformed"),
        (Invariant::Link, "chain.link_mismatch"),
        (Invariant::Principal, "chain.principal_altered"),
        (Invariant::Expiry, "chain.exp_extended"),
        (Invariant::Depth, "chain.depth_exceeded"),
        (Invariant::Audience, "chain.audience_widened"),
        (Invariant::Repeat, "chain.token_repeated"),
        (Invariant::Assurance, "chain.unverified"),
        (Invariant::UnknownAuthority, "chain.unknown_authority"),
        (Invariant::Attenuation, "chain.scope_escalation"),
        (Invariant::Status, "chain.status_unchecked"),
        (Invariant::HolderProof, "chain.no_holder_proof"),
        (Invariant::Action, "chain.action_denied"),
    ];
    for (invariant, code) in codes {
        let e = InvariantError {
            invariant,
            hop: None,
        };
        assert_eq!(e.code(), code);
        assert_eq!(e.to_string(), code);
    }
    assert_eq!(
        DepthSemantics::for_profile(Profile::Asor03).as_str(),
        "asor-strict"
    );
    assert_eq!(
        DepthSemantics::for_profile(Profile::Aat02).as_str(),
        "aat-holder-cap"
    );
    assert_eq!(
        DepthSemantics::for_profile(Profile::Rfc8693Act).as_str(),
        "uncapped"
    );
}
