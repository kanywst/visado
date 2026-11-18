//! Runs the published AAT JWS vectors in `conformance/aat/aat-jws-vectors.json`.
//!
//! Every vector must produce its expected verdict, and every denial must
//! fail at the expected §8 step.

use std::collections::BTreeSet;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use visado_chain::{Assurance, ChainDecoder, Link, SignerBinding};
use visado_chain_aat::{
    Invocation, Limits, MemoryReplayCache, Policy, Presentation, ReplayCache, TrustAnchor, Verifier,
};
use wimsey_jose::{Algorithm, VerifyingKey};

const VECTOR_COUNT: usize = 229;

fn suite() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/aat/aat-jws-vectors.json");
    let text = std::fs::read_to_string(path).expect("vector file");
    serde_json::from_str(&text).expect("vector JSON")
}

fn anchors(suite: &Value) -> Vec<TrustAnchor> {
    suite["trust_anchors"]
        .as_array()
        .expect("trust_anchors")
        .iter()
        .map(|a| {
            let x = URL_SAFE_NO_PAD
                .decode(a["jwk"]["x"].as_str().expect("x"))
                .expect("base64url x");
            let key = VerifyingKey::from_raw_bytes(Algorithm::Ed25519, &x).expect("Ed25519 key");
            TrustAnchor::new(a["iss"].as_str().expect("iss"), key)
        })
        .collect()
}

fn param(vector: &Value, suite: &Value, name: &str) -> i64 {
    vector["params"]
        .get(name)
        .or_else(|| suite["params"].get(name))
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("param {name}"))
}

fn limits(vector: &Value, suite: &Value) -> Limits {
    let p = |name| param(vector, suite, name);
    let size = |name| usize::try_from(p(name)).expect("size");
    Limits {
        max_iat_skew: p("max_iat_skew"),
        max_token_lifetime: p("max_token_lifetime"),
        max_delegation_depth: u32::try_from(p("max_delegation_depth")).expect("depth"),
        max_constraint_depth: size("max_constraint_depth"),
        max_token_size: size("max_token_size"),
        max_chain_size: size("max_chain_size"),
        pop_window: p("pop_window"),
    }
}

fn policy(vector: &Value) -> Policy {
    let p = &vector["policy"];
    Policy {
        require_chain_aud: p["require_chain_aud"].as_bool().unwrap_or(false),
        require_pop_aud: p["require_pop_aud"].as_bool().unwrap_or(false),
        nonces: p["nonce"].as_str().map(|n| BTreeSet::from([n.to_owned()])),
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Runs one vector and returns a description of any disagreement.
fn run(vector: &Value, suite: &Value) -> Option<String> {
    let id = vector["id"].as_str().expect("id");
    let audience = suite["params"]["audience"]
        .as_str()
        .expect("audience")
        .to_owned();
    let verifier = Verifier::new(anchors(suite), vec![audience])
        .with_limits(limits(vector, suite))
        .with_policy(policy(vector));
    let presentation = &vector["presentation"];
    let chain = strings(&presentation["aat_chain"]);
    let pop = presentation["aat_pop"].as_str().unwrap_or_default();
    let now = vector["now"].as_i64().expect("now");
    let invocation = Invocation {
        tool: vector["tool"].as_str().expect("tool"),
        args_json: vector["args_json"].as_str().expect("args_json"),
    };

    let tracked = vector["policy"]["track_pop_jti"].as_bool().unwrap_or(false);
    let cache = MemoryReplayCache::new(1024);
    for jti in strings(&vector["replay_state"]["before"]) {
        assert!(cache.check_and_record(&jti, now + 60, now));
    }
    let replay: Option<&dyn ReplayCache> = if tracked { Some(&cache) } else { None };

    let result = verifier.verify(
        &Presentation { chain: &chain, pop },
        &invocation,
        now,
        replay,
    );

    let expected = &vector["expected"];
    let got = match &result {
        Ok(_) => ("PERMIT".to_owned(), None),
        Err(e) => ("DENY".to_owned(), Some(e.step().as_str().to_owned())),
    };
    let want = (
        expected["verdict"].as_str().expect("verdict").to_owned(),
        expected["step"].as_str().map(ToOwned::to_owned),
    );
    if got != want {
        let detail = result.err().map(|e| e.to_string()).unwrap_or_default();
        return Some(format!("{id}: expected {want:?}, got {got:?} {detail}"));
    }

    if tracked {
        let pop_jti = vector["pop"]["payload"]["jti"].as_str().unwrap_or_default();
        let after = strings(&vector["replay_state"]["after"]);
        if cache.contains(pop_jti, now) != after.iter().any(|j| j == pop_jti) {
            return Some(format!("{id}: replay state after verification differs"));
        }
    }

    if let Ok(authorized) = result {
        let hops = &authorized.chain.hops;
        let ok = hops.len() == chain.len()
            && hops.iter().all(|h| h.assurance == Assurance::Verified)
            && hops.first().is_some_and(|h| {
                h.signer_binding == SignerBinding::RootAnchor && h.link == Link::Root
            })
            && hops.iter().skip(1).all(|h| {
                h.signer_binding == SignerBinding::ParentCnf && matches!(h.link, Link::ParHash(_))
            });
        if !ok {
            return Some(format!("{id}: normalized chain is inconsistent"));
        }
        let decoded = verifier.decode(&chain, now).ok();
        if decoded.as_ref() != Some(&authorized.chain) {
            return Some(format!("{id}: decode() disagrees with verify()"));
        }
    }
    None
}

#[test]
fn published_aat_vectors() {
    let suite = suite();
    assert_eq!(
        suite["spec"],
        "draft-niyikiza-oauth-attenuating-agent-tokens-02"
    );
    let vectors = suite["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), VECTOR_COUNT);

    let failures: Vec<String> = vectors.iter().filter_map(|v| run(v, &suite)).collect();
    let passed = vectors.len() - failures.len();
    println!("AAT vectors: {passed}/{} pass", vectors.len());
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
