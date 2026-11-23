//! The steps the published vectors do not reach: JCS and number rules,
//! the DPoP proof (step 6), status (step 7) and the action (step 8), on
//! Ed25519 chains.

use std::sync::Arc;

use visado_chain::ChainDecoder;
use visado_chain::algebra::{Action as EngineAction, Algebras};
use visado_chain::invariants::{Engine, Invariant};

use serde_json::{Value, json};
use visado_chain_asor::{
    Action, AsorError, Cumulative, HttpRequest, MemoryReplayCache, MemoryStatusLists, Outcome,
    Presentation, RunningTotals, StatusListVerifier, TrustAnchor, Verifier,
};
use visado_testkit::{
    ASOR_ISSUER, STATUS_LIST_ISSUER, STATUS_LIST_URI, asor_anchor_key, asor_child_claims,
    asor_root_claims, asor_sign, asor_sign_raw, dpop_proof, pop_key, status_list_key,
    status_list_lst, status_list_token,
};

const NOW: u64 = 1_800_000_000;
const AUD: &str = "https://tools.example.com";
const URI: &str = "https://tools.example.com/mcp";

fn verifier() -> Verifier {
    Verifier::new(
        vec![TrustAnchor::new(
            ASOR_ISSUER,
            asor_anchor_key().verifying_key(),
        )],
        vec![AUD.to_owned()],
    )
}

/// Root held by key 1 granting `crm.*` with a row cap; child held by key 2
/// narrowed to `crm.read`.
fn chain_with(child_constraints: &Value) -> Vec<String> {
    let root = asor_sign(&asor_root_claims(
        "r",
        "orchestrator",
        &pop_key(1),
        &json!(["crm.*"]),
        &json!([{ "key": "rows", "max": 1000 }]),
        AUD,
        NOW,
        5,
    ));
    let child = asor_sign(&asor_child_claims(
        "c",
        "reader",
        &root,
        &pop_key(2),
        1,
        &json!(["crm.read"]),
        child_constraints,
        AUD,
        NOW,
    ));
    vec![root, child]
}

fn chain() -> Vec<String> {
    chain_with(&json!([{ "key": "rows", "max": 100 }]))
}

fn run(
    chain: &[String],
    proof: &str,
    scope: &str,
    params: &str,
    totals: Option<&dyn RunningTotals>,
    replay: Option<&MemoryReplayCache>,
) -> Result<(), AsorError> {
    let replay = replay.map(|r| r as &dyn visado_chain_asor::ReplayCache);
    let result = verifier()
        .verify(
            &Presentation { chain, dpop: proof },
            &HttpRequest {
                method: "POST",
                uri: URI,
            },
            &Action {
                scope,
                params_json: params,
                totals,
            },
            i64::try_from(NOW).unwrap(),
            replay,
        )
        .map(|authorized| {
            assert!(authorized.chain.holder_proof);
            authorized.chain
        });
    if totals.is_none() {
        engine_agrees(chain, scope, params, &result);
    }
    result.map(|_| ())
}

/// The invariant engine with the asor algebra agrees with step 8: it holds
/// on every permitted chain and denies the action wherever step 8 does. The
/// algebra holds no running totals, so runs with totals are not compared.
fn engine_agrees(
    chain: &[String],
    scope: &str,
    params: &str,
    result: &Result<visado_chain::NormalizedChain, AsorError>,
) {
    let engine = Engine::new(Algebras::new().with(Arc::new(verifier().algebra())));
    let action = EngineAction {
        name: scope,
        params_json: params,
    };
    match result {
        Ok(chain) => {
            engine
                .check(chain, Some(&action))
                .expect("the engine agrees");
        }
        Err(e)
            if matches!(
                e.outcome(),
                Outcome::ScopeNotGranted | Outcome::CeilingExceeded | Outcome::UnknownConstraint
            ) =>
        {
            let mut decoded = verifier()
                .decode(chain, i64::try_from(NOW).unwrap())
                .unwrap();
            decoded.holder_proof = true;
            assert_eq!(
                engine.check(&decoded, Some(&action)).unwrap_err().invariant,
                Invariant::Action,
                "{e}"
            );
        }
        Err(_) => {}
    }
}

fn proof(chain: &[String], seed: u8, jti: &str) -> String {
    dpop_proof(&pop_key(seed), "POST", URI, chain.last().unwrap(), jti, NOW)
}

fn outcome(result: Result<(), AsorError>) -> Option<Outcome> {
    result.err().map(|e| e.outcome())
}

#[test]
fn a_delegated_action_within_bounds_is_permitted() {
    let chain = chain();
    let cache = MemoryReplayCache::new(16);
    let p = proof(&chain, 2, "p1");
    assert_eq!(
        run(&chain, &p, "crm.read", r#"{"rows":50}"#, None, Some(&cache)),
        Ok(())
    );
    assert_eq!(
        outcome(run(
            &chain,
            &p,
            "crm.read",
            r#"{"rows":1}"#,
            None,
            Some(&cache)
        )),
        Some(Outcome::HolderBindingFailed),
        "replayed proof"
    );
}

#[test]
fn step_8_checks_scope_and_constraints() {
    let chain = chain();
    let p = proof(&chain, 2, "p1");
    assert_eq!(
        outcome(run(&chain, &p, "crm.write", "{}", None, None)),
        Some(Outcome::ScopeNotGranted)
    );
    assert_eq!(
        outcome(run(&chain, &p, "crm.read", r#"{"rows":101}"#, None, None)),
        Some(Outcome::CeilingExceeded)
    );
    assert_eq!(
        outcome(run(&chain, &p, "crm.read", "[]", None, None)),
        Some(Outcome::CeilingExceeded)
    );
}

#[test]
fn cumulative_constraints_need_a_held_total() {
    struct Held(f64);
    impl RunningTotals for Held {
        fn total(&self, jti: &str, key: &str, kind: Cumulative) -> Option<f64> {
            (jti == "c" && key == "calls" && kind == Cumulative::Lifetime).then_some(self.0)
        }
    }
    let chain = chain_with(&json!([
        { "key": "rows", "max": 100 },
        { "key": "calls", "max_lifetime": 3 },
    ]));
    // The root carries no lifetime bound, so the child may add one.
    let p = proof(&chain, 2, "p1");
    assert_eq!(
        outcome(run(&chain, &p, "crm.read", r#"{"rows":1}"#, None, None)),
        Some(Outcome::CeilingExceeded)
    );
    assert_eq!(
        run(
            &chain,
            &p,
            "crm.read",
            r#"{"rows":1}"#,
            Some(&Held(3.0)),
            None
        ),
        Ok(())
    );
    assert_eq!(
        outcome(run(
            &chain,
            &p,
            "crm.read",
            r#"{"rows":1}"#,
            Some(&Held(4.0)),
            None
        )),
        Some(Outcome::CeilingExceeded)
    );
}

#[test]
fn an_unknown_constraint_type_denies_every_action() {
    let chain = chain_with(&json!([
        { "key": "rows", "max": 100 },
        { "key": "units", "furlongs": 2 },
    ]));
    let p = proof(&chain, 2, "p1");
    assert_eq!(
        outcome(run(&chain, &p, "crm.read", r#"{"rows":1}"#, None, None)),
        Some(Outcome::UnknownConstraint)
    );
}

#[test]
fn step_6_binds_the_proof_to_the_leaf_key_and_the_request() {
    let chain = chain();
    let leaf = chain.last().unwrap();
    let key = pop_key(2);
    let denied = |p: &str| outcome(run(&chain, p, "crm.read", r#"{"rows":1}"#, None, None));
    let failed = Some(Outcome::HolderBindingFailed);
    assert_eq!(denied(""), failed, "missing proof");
    assert_eq!(denied(&proof(&chain, 1, "p")), failed, "parent's key");
    assert_eq!(
        denied(&dpop_proof(&key, "GET", URI, leaf, "p", NOW)),
        failed,
        "htm"
    );
    assert_eq!(
        denied(&dpop_proof(
            &key,
            "POST",
            "https://other.example/mcp",
            leaf,
            "p",
            NOW
        )),
        failed,
        "htu"
    );
    assert_eq!(
        denied(&dpop_proof(&key, "POST", URI, &chain[0], "p", NOW)),
        failed,
        "ath of another token"
    );
    assert_eq!(
        denied(&dpop_proof(&key, "POST", URI, leaf, "p", NOW - 61)),
        failed,
        "stale"
    );
    let query = dpop_proof(&key, "POST", &format!("{URI}?x=1"), leaf, "p", NOW);
    assert_eq!(denied(&query), None, "htu ignores the query");
}

#[test]
fn a_status_reference_cannot_be_checked() {
    let mut claims = asor_root_claims(
        "r",
        "orchestrator",
        &pop_key(1),
        &json!(["crm.read"]),
        &json!([]),
        AUD,
        NOW,
        5,
    );
    claims["status"] = json!({ "status_list": { "idx": 1, "uri": "https://s.example/1" } });
    let chain = vec![asor_sign(&claims)];
    let p = proof(&chain, 1, "p1");
    assert_eq!(
        outcome(run(&chain, &p, "crm.read", r#"{"rows":1}"#, None, None)),
        Some(Outcome::StatusUnknown)
    );
    assert_eq!(
        check(&chain),
        Some(Outcome::StatusUnknown),
        "check() fails closed too"
    );
}

/// Step 7 runs after the proof and before the action: a revoked token is
/// denied even for an action within bounds, and a valid one is permitted.
#[test]
fn step_7_checks_each_status_reference() {
    let list = status_list_token(
        &json!({ "alg": "Ed25519", "typ": "statuslist+jwt" }),
        &json!({
            "sub": STATUS_LIST_URI, "iat": NOW, "ttl": 60,
            "status_list": { "bits": 1, "lst": status_list_lst(1, &[0, 1]) },
        }),
    );
    let now = i64::try_from(NOW).unwrap();
    let lists = Arc::new(MemoryStatusLists::new());
    let held = StatusListVerifier::new(vec![TrustAnchor::new(
        STATUS_LIST_ISSUER,
        status_list_key().verifying_key(),
    )])
    .verify(&list, STATUS_LIST_URI, now);
    lists.update(STATUS_LIST_URI, held).unwrap();
    let verifier = verifier().with_status_lists(lists);
    let decide = |idx: u32, jti: &str| {
        let mut claims = asor_root_claims(
            "r",
            "orchestrator",
            &pop_key(1),
            &json!(["crm.read"]),
            &json!([]),
            AUD,
            NOW,
            5,
        );
        claims["status"] = json!({ "status_list": { "idx": idx, "uri": STATUS_LIST_URI } });
        let chain = vec![asor_sign(&claims)];
        let p = proof(&chain, 1, jti);
        verifier
            .verify(
                &Presentation {
                    chain: &chain,
                    dpop: &p,
                },
                &HttpRequest {
                    method: "POST",
                    uri: URI,
                },
                &Action {
                    scope: "crm.read",
                    params_json: "{}",
                    totals: None,
                },
                now,
                None,
            )
            .map(|_| ())
            .map_err(|e| (e.outcome(), e.reason()))
    };
    assert_eq!(decide(0, "p1"), Ok(()));
    assert_eq!(decide(1, "p2"), Err((Outcome::Revoked, "token is revoked")));
    assert_eq!(
        decide(8, "p3"),
        Err((Outcome::StatusUnknown, "status index out of range"))
    );
    // A bad proof is reported before status: step 6 comes first.
    let mut claims = asor_root_claims(
        "r",
        "orchestrator",
        &pop_key(1),
        &json!(["crm.read"]),
        &json!([]),
        AUD,
        NOW,
        5,
    );
    claims["status"] = json!({ "status_list": { "idx": 1, "uri": STATUS_LIST_URI } });
    let chain = vec![asor_sign(&claims)];
    let wrong_holder = proof(&chain, 9, "p4");
    assert_eq!(
        outcome(run(&chain, &wrong_holder, "crm.read", "{}", None, None)),
        Some(Outcome::HolderBindingFailed)
    );
}

fn check(tokens: &[String]) -> Option<Outcome> {
    verifier()
        .check(tokens, i64::try_from(NOW).unwrap())
        .err()
        .map(|e| e.outcome())
}

fn root_json(extra: &str) -> String {
    let claims = asor_root_claims(
        "r",
        "orchestrator",
        &pop_key(1),
        &json!(["crm.read"]),
        &json!([]),
        AUD,
        NOW,
        5,
    );
    let text = serde_json::to_string(&claims).unwrap();
    format!("{{{extra}{}", &text[1..])
}

#[test]
fn parse_rules() {
    let header = r#"{"alg":"Ed25519","typ":"at+jwt"}"#;
    assert_eq!(check(&[asor_sign_raw(header, &root_json(""))]), None);
    assert_eq!(
        check(&[asor_sign_raw(
            r#"{"typ":"at+jwt","alg":"Ed25519"}"#,
            &root_json("")
        )]),
        Some(Outcome::NonCanonical),
        "header member order"
    );
    assert_eq!(
        check(&[asor_sign_raw(header, &root_json(r#""zz":1.0,"#))]),
        Some(Outcome::NonCanonical),
        "1.0 is not JCS"
    );
    assert_eq!(
        check(&[asor_sign_raw(header, &root_json(r#""aud":"x","#))]),
        Some(Outcome::DuplicateMember)
    );
    assert_eq!(
        check(&[asor_sign_raw(header, &root_json(r#""a":1e400,"#))]),
        Some(Outcome::NonFinite)
    );
    assert_eq!(
        check(&[asor_sign_raw(
            header,
            &root_json(r#""a":9007199254740992,"#)
        )]),
        Some(Outcome::Malformed)
    );
    assert_eq!(
        check(&[asor_sign_raw(
            r#"{"alg":"Ed25519","typ":"JWT"}"#,
            &root_json("")
        )]),
        Some(Outcome::Malformed),
        "typ"
    );
    assert_eq!(check(&[]), Some(Outcome::Malformed));
    assert_eq!(check(&["a.b".to_owned()]), Some(Outcome::Malformed));
    assert_eq!(
        check(&["x".repeat(70 * 1024)]),
        Some(Outcome::Malformed),
        "oversized token"
    );
}

#[test]
fn depth_is_bounded_by_the_root_only() {
    let root = asor_sign(&asor_root_claims(
        "r",
        "a",
        &pop_key(1),
        &json!(["crm.read"]),
        &json!([]),
        AUD,
        NOW,
        2,
    ));
    let child = |parent: &str, jti: &str, depth: u32| {
        asor_sign(&asor_child_claims(
            jti,
            "b",
            parent,
            &pop_key(2),
            depth,
            &json!(["crm.read"]),
            &json!([]),
            AUD,
            NOW,
        ))
    };
    let one = child(&root, "c1", 1);
    assert_eq!(check(&[root.clone(), one.clone()]), None);
    let two = child(&one, "c2", 2);
    assert_eq!(
        check(&[root.clone(), one.clone(), two]),
        Some(Outcome::DepthInvalid),
        "a leaf at depth == del_max_depth"
    );
    let skipped = child(&root, "c3", 2);
    assert_eq!(check(&[root, skipped]), Some(Outcome::DepthInvalid));
}

#[test]
fn an_untrusted_or_wrong_issuer_signature_is_invalid() {
    let claims = asor_root_claims(
        "r",
        "a",
        &pop_key(1),
        &json!(["crm.read"]),
        &json!([]),
        AUD,
        NOW,
        2,
    );
    let mut other_issuer = claims.clone();
    other_issuer["iss"] = json!("https://other.example");
    assert_eq!(
        check(&[asor_sign(&other_issuer)]),
        Some(Outcome::SignatureInvalid)
    );
    let token = asor_sign(&claims);
    let (input, _) = token.rsplit_once('.').unwrap();
    let forged = format!("{input}.{}", "A".repeat(86));
    assert_eq!(check(&[forged]), Some(Outcome::SignatureInvalid));
}

/// A leaf proof's `iat` may be ahead of the clock by the proof skew (5 s by
/// default), not by the whole window, and is configurable.
#[test]
fn a_leaf_proof_from_the_future_is_refused() {
    let chain = chain();
    let ahead = |secs: u64, jti: &str| {
        dpop_proof(
            &pop_key(2),
            "POST",
            URI,
            chain.last().unwrap(),
            jti,
            NOW + secs,
        )
    };
    assert_eq!(
        run(
            &chain,
            &ahead(5, "p1"),
            "crm.read",
            r#"{"rows":1}"#,
            None,
            None
        ),
        Ok(())
    );
    let err = run(
        &chain,
        &ahead(6, "p2"),
        "crm.read",
        r#"{"rows":1}"#,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err.outcome(), Outcome::HolderBindingFailed);
    assert_eq!(err.reason(), "DPoP iat in the future");
}
