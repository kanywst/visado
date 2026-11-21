//! Step 6 with server-provided DPoP nonces (RFC 9449 §4.3 item 10, §9):
//! the leaf's proof is an RFC 9449 proof to the enforcement point, so it
//! carries the enforcement point's nonce when one is required.

use serde_json::{Value, json};
use visado_chain::dpop::{NonceError, Nonces};
use visado_chain_asor::{
    Action, AsorError, HttpRequest, MemoryReplayCache, Outcome, Presentation, TrustAnchor, Verifier,
};
use visado_testkit::{
    ASOR_ISSUER, asor_anchor_key, asor_child_claims, asor_root_claims, asor_sign, dpop_claims,
    dpop_jwk, pop_key, sign_dpop_proof,
};

const NOW: u64 = 1_800_000_000;
const NOW_I: i64 = 1_800_000_000;
const AUD: &str = "https://tools.example.com";
const URI: &str = "https://tools.example.com/mcp";

fn nonces() -> Nonces {
    Nonces::new(&[0x61; 32], 60).unwrap()
}

fn verifier(nonces: Option<Nonces>) -> Verifier {
    Verifier::new(
        vec![TrustAnchor::new(
            ASOR_ISSUER,
            asor_anchor_key().verifying_key(),
        )],
        vec![AUD.to_owned()],
    )
    .with_dpop_nonces(nonces)
}

fn chain() -> Vec<String> {
    let root = asor_sign(&asor_root_claims(
        "r",
        "orchestrator",
        &pop_key(1),
        &json!(["crm.*"]),
        &json!([]),
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
        &json!([]),
        AUD,
        NOW,
    ));
    vec![root, child]
}

/// The leaf holder's proof, with the claims changed by `edit`.
fn proof(chain: &[String], edit: impl FnOnce(&mut Value)) -> String {
    let key = pop_key(2);
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(&key) });
    let mut claims = dpop_claims("POST", URI, chain.last().unwrap(), "p-1", NOW);
    edit(&mut claims);
    sign_dpop_proof(&header, &claims, &key)
}

fn run(
    verifier: &Verifier,
    chain: &[String],
    proof: &str,
    replay: Option<&MemoryReplayCache>,
) -> Result<(), AsorError> {
    verifier
        .verify(
            &Presentation { chain, dpop: proof },
            &HttpRequest {
                method: "POST",
                uri: URI,
            },
            &Action {
                scope: "crm.read",
                params_json: "{}",
                totals: None,
            },
            NOW_I,
            replay.map(|r| r as &dyn visado_chain_asor::ReplayCache),
        )
        .map(|_| ())
}

#[test]
fn a_leaf_proof_with_the_nonce_is_accepted() {
    let chain = chain();
    let v = verifier(Some(nonces()));
    let nonce = nonces().issue(NOW_I);
    assert_eq!(
        run(
            &v,
            &chain,
            &proof(&chain, |c| c["nonce"] = json!(nonce)),
            None
        ),
        Ok(())
    );
}

#[test]
fn a_nonce_failure_is_holder_binding_failed_and_says_so() {
    let chain = chain();
    let v = verifier(Some(nonces()));
    let other = Nonces::new(&[0x62; 32], 60).unwrap();
    let cases: [(Option<Value>, NonceError); 5] = [
        (None, NonceError::Missing),
        (Some(json!("short")), NonceError::Malformed),
        (Some(json!(other.issue(NOW_I))), NonceError::Invalid),
        (Some(json!(nonces().issue(NOW_I - 60))), NonceError::Expired),
        (Some(json!(nonces().issue(NOW_I + 30))), NonceError::Future),
    ];
    for (i, (nonce, want)) in cases.into_iter().enumerate() {
        let p = proof(&chain, |c| {
            if let Some(nonce) = nonce {
                c["nonce"] = nonce;
            }
        });
        let err = run(&v, &chain, &p, None).unwrap_err();
        assert_eq!(err.outcome(), Outcome::HolderBindingFailed, "case {i}");
        assert_eq!(err.dpop_nonce(), Some(want), "case {i}");
        assert_eq!(err.reason(), want.reason(), "case {i}");
    }
}

#[test]
fn other_step_6_failures_carry_no_nonce_error() {
    let chain = chain();
    let v = verifier(Some(nonces()));
    // Another key: not the leaf's.
    let key = pop_key(3);
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(&key) });
    let foreign = sign_dpop_proof(
        &header,
        &dpop_claims("POST", URI, chain.last().unwrap(), "p-2", NOW),
        &key,
    );
    let err = run(&v, &chain, &foreign, None).unwrap_err();
    assert_eq!(err.outcome(), Outcome::HolderBindingFailed);
    assert_eq!(err.dpop_nonce(), None);
    // Wrong method and no nonce: the method is what fails.
    let get = proof(&chain, |c| c["htm"] = json!("GET"));
    assert_eq!(run(&v, &chain, &get, None).unwrap_err().dpop_nonce(), None);
}

#[test]
fn a_replayed_proof_with_a_nonce_is_still_refused() {
    let chain = chain();
    let v = verifier(Some(nonces()));
    let cache = MemoryReplayCache::new(16);
    let p = proof(&chain, |c| c["nonce"] = json!(nonces().issue(NOW_I)));
    assert_eq!(run(&v, &chain, &p, Some(&cache)), Ok(()));
    let err = run(&v, &chain, &p, Some(&cache)).unwrap_err();
    assert_eq!(err.outcome(), Outcome::HolderBindingFailed);
    assert_eq!(err.dpop_nonce(), None);
}

#[test]
fn a_proof_refused_for_its_nonce_is_not_recorded() {
    let chain = chain();
    let v = verifier(Some(nonces()));
    let cache = MemoryReplayCache::new(16);
    let missing = proof(&chain, |_| {});
    assert!(run(&v, &chain, &missing, Some(&cache)).is_err());
    let retry = proof(&chain, |c| c["nonce"] = json!(nonces().issue(NOW_I)));
    assert_eq!(run(&v, &chain, &retry, Some(&cache)), Ok(()));
}

#[test]
fn without_nonces_no_nonce_is_needed() {
    let chain = chain();
    assert_eq!(
        run(&verifier(None), &chain, &proof(&chain, |_| {}), None),
        Ok(())
    );
    let off = verifier(Some(nonces())).with_dpop_nonces(None);
    assert_eq!(run(&off, &chain, &proof(&chain, |_| {}), None), Ok(()));
}
