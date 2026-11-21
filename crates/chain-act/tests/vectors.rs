//! Runs `conformance/act/vectors.json`: two claim sets from RFC 8693 §4.1
//! and visado's own cases.

use std::sync::Arc;

use serde_json::{Value, json};
use visado_chain::ActorId;
use visado_chain::algebra::Algebras;
use visado_chain::invariants::{Engine, Invariant};
use visado_chain_act::{ActToken, Algebra, Caller, Verifier};

fn actor(id: &ActorId) -> Value {
    match id {
        ActorId::Subject { issuer, subject } => json!({ "iss": issuer, "sub": subject }),
        other => panic!("{other:?}"),
    }
}

#[test]
fn vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/act/vectors.json"
    );
    let suite: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(suite["format"], "visado-act-vectors/v1");
    let cases = suite["cases"].as_array().unwrap();
    let mut passed = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let claims = &case["claims"];
        let mut verifier = Verifier::new();
        if let Some(max) = case["max_actors"].as_u64() {
            verifier = verifier.with_max_actors(usize::try_from(max).unwrap());
        }
        if let Some(map) = case["actors"].as_object() {
            for (sub, caller) in map {
                verifier = verifier.with_actor(sub, caller.as_str().unwrap());
            }
        }
        let token = ActToken {
            issuer: claims["iss"].as_str().unwrap(),
            subject: claims["sub"].as_str().unwrap(),
            id: claims["jti"].as_str(),
            key_thumbprint: "test-key",
            issued_at: claims["iat"].as_u64(),
            expires_at: claims["exp"].as_u64().unwrap(),
            act: &claims["act"],
        };
        let caller = Caller {
            id: case["caller"].as_str().unwrap(),
            proved_key: false,
        };
        let result = verifier.verify(&token, &caller);
        match case["expect"].as_str().unwrap() {
            "accept" => {
                let chain = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                let (current, prior) = chain.hops.split_last().unwrap();
                assert_eq!(actor(&current.actor), case["actor"], "{name}");
                let prior: Vec<Value> = prior.iter().map(|h| actor(&h.actor)).collect();
                assert_eq!(Value::from(prior), case["prior_actors"], "{name}");
                // The engine needs a caller that proved a key; then it holds.
                let engine = Engine::new(Algebras::new().with(Arc::new(Algebra)));
                assert_eq!(
                    engine.check(&chain, None).unwrap_err().invariant,
                    Invariant::HolderProof,
                    "{name}"
                );
                let proved = Caller {
                    proved_key: true,
                    ..caller
                };
                let chain = verifier.verify(&token, &proved).unwrap();
                engine
                    .check(&chain, None)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            }
            code => assert_eq!(
                result
                    .map(|_| ())
                    .map_err(visado_chain_act::ActError::as_str),
                Err(code),
                "{name}"
            ),
        }
        passed += 1;
    }
    assert_eq!(passed, 20);
}
