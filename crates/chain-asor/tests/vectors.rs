//! Runs the published asor-03 vectors in `conformance/asor/vectors/`.
//!
//! Every vector must give its expected verdict, and every rejection must be
//! named with its expected Table 2 outcome. The vectors carry no request, so
//! each runs what a verifier with an audience but no request can check.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use visado_chain::algebra::Algebras;
use visado_chain::invariants::Engine;
use visado_chain::{Assurance, ChainDecoder, Link, Principal, Profile, SignerBinding};
use visado_chain_asor::{Alg, TrustAnchor, Verifier};

const VECTOR_COUNT: usize = 36;

fn vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/asor/vectors");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("vector directory")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).expect("vector file");
            (name, serde_json::from_str(&text).expect("vector JSON"))
        })
        .collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The verifier a vector describes: its test signer as the only trust
/// anchor, its accepted algorithms (names this crate does not implement are
/// on no list it can match), and its audience.
fn verifier(vector: &Value) -> Verifier {
    let signer = &vector["signer"];
    assert_eq!(signer["alg"], "HS256", "test signer");
    let anchor = TrustAnchor::hs256("attenu-guard", hex(signer["secret_hex"].as_str().unwrap()))
        .with_kid(signer["kid"].as_str().unwrap());
    let algorithms = vector["verifier"]["accepted_algs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| Alg::from_name(a.as_str().unwrap()))
        .collect();
    let audience = vector["verifier"]["audience"].as_str().unwrap().to_owned();
    Verifier::new(vec![anchor], vec![audience]).with_algorithms(algorithms)
}

#[test]
fn every_vector_matches() {
    let vectors = vectors();
    assert_eq!(vectors.len(), VECTOR_COUNT);
    let mut failures = Vec::new();
    let mut accepted = 0;
    for (name, vector) in &vectors {
        let tokens: Vec<String> = vector["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect();
        let now = vector["now"].as_i64().unwrap();
        let verifier = verifier(vector);
        let result = verifier.check(&tokens, now);
        // The invariant engine holds on every chain the decoder accepts,
        // accepted vectors included.
        let engine = Engine::new(Algebras::new().with(Arc::new(verifier.algebra())));
        if let Ok(decoded) = verifier.decode(&tokens, now)
            && let Err(e) = engine.check_chain(&decoded)
        {
            failures.push(format!("{name}: the engine denies a decoded chain: {e}"));
        }
        let expected = vector["expect_reject_reason"].as_str();
        match (expected, &result) {
            (None, Ok(chain)) => {
                assert_eq!(vector["expect"], "accept", "{name}");
                assert_eq!(chain.hops.len(), tokens.len(), "{name}");
                accepted += 1;
            }
            (Some(reason), Err(e)) if e.outcome().as_str() == reason => {}
            _ => failures.push(format!(
                "{name}: expected {}, got {result:?}",
                expected.unwrap_or("accept")
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(accepted, 5);
}

#[test]
fn decoded_chain_is_normalized() {
    let (_, vector) = vectors()
        .into_iter()
        .find(|(name, _)| name == "valid_chain")
        .unwrap();
    let tokens: Vec<String> = vector["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_owned())
        .collect();
    let chain = verifier(&vector).decode(&tokens, 0).unwrap();
    assert_eq!(chain.profile, Profile::Asor03);
    assert!(!chain.holder_proof);
    assert_eq!(
        chain.principal,
        Principal::Subject {
            issuer: "attenu-guard".into(),
            subject: "acct:finance-ops@example.com".into(),
        }
    );
    assert!(
        chain
            .hops
            .iter()
            .all(|h| h.principal == chain.principal && h.status.is_none())
    );
    let depths: Vec<u32> = chain.hops.iter().map(|h| h.depth).collect();
    assert_eq!(depths, [0, 1, 2]);
    assert!(chain.hops.iter().all(|h| h.max_depth == Some(6)));
    assert!(chain.hops.iter().all(
        |h| h.assurance == Assurance::Verified && h.signer_binding == SignerBinding::RootAnchor
    ));
    assert_eq!(chain.hops[0].link, Link::Root);
    assert!(matches!(chain.hops[1].link, Link::ParHash(_)));
    assert_eq!(
        chain.hops[2].delegator,
        Some(visado_chain::ActorId::Name("summarizer".into()))
    );
    assert_eq!(
        chain.leaf().unwrap().authority.detail_type,
        "agent_delegation"
    );
}

#[test]
fn now_equal_to_exp_is_expired() {
    // -03 changed step 5 to now < exp.
    let (_, vector) = vectors()
        .into_iter()
        .find(|(name, _)| name == "valid_chain")
        .unwrap();
    let tokens: Vec<String> = vector["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_owned())
        .collect();
    let v = verifier(&vector);
    assert!(v.check(&tokens, 299).is_ok());
    assert_eq!(
        v.check(&tokens, 300).unwrap_err().outcome().as_str(),
        "expired"
    );
}
