//! Cases outside the published vectors, built with local keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use visado_chain_aat::{
    AatError, Invocation, Limits, MemoryReplayCache, Presentation, ReplayCache, Step, TrustAnchor,
    Verifier,
};
use wimsey_jose::{Jwk, SigningKey};

const NOW: i64 = 1_800_000_000;
const AUDIENCE: &str = "https://tools.example";
const ISSUER: &str = "https://aat.example";
const TOOL: &str = "read_file";
const ARGS: &str = r#"{"path":"/a"}"#;

fn anchor_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x61; 32])
}

fn holder_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x62; 32])
}

fn sign(typ: &str, payload: &Value, key: &SigningKey) -> String {
    let header = json!({ "alg": "Ed25519", "typ": typ });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    format!("{input}.{sig}")
}

fn signing_input_hash(token: &str) -> String {
    let input = token.rsplit_once('.').unwrap().0;
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// Root claims granting `tools`; edit them before signing with [`root`].
fn root_claims(tools: &Value) -> Value {
    let mut jwk =
        serde_json::to_value(Jwk::from_verifying_key(&holder_key().verifying_key())).unwrap();
    jwk.as_object_mut().unwrap().remove("alg");
    json!({
        "jti": "root-1", "iss": ISSUER, "iat": NOW, "exp": NOW + 600,
        "del_depth": 0, "del_max_depth": 2,
        "cnf": { "jwk": jwk },
        "authorization_details": [{ "type": "attenuating_agent_token", "tools": tools }],
    })
}

fn root(claims: &Value) -> String {
    sign("aat+jwt", claims, &anchor_key())
}

fn wildcard_tools() -> Value {
    json!({ TOOL: { "path": { "constraint_type": "wildcard" } } })
}

fn pop(leaf: &str, leaf_jti: &str, args: &Value, key: &SigningKey) -> String {
    pop_at(leaf, leaf_jti, args, key, NOW)
}

fn pop_at(leaf: &str, leaf_jti: &str, args: &Value, key: &SigningKey, iat: i64) -> String {
    let claims = json!({
        "jti": "pop-1", "iat": iat, "aat_id": leaf_jti, "aat_hash": signing_input_hash(leaf),
        "aat_tool": TOOL, "hta": args, "aat_aud": AUDIENCE,
    });
    sign("aat-pop+jwt", &claims, key)
}

fn anchor(issuer: &str) -> TrustAnchor {
    TrustAnchor::new(issuer, anchor_key().verifying_key())
}

fn verify(verifier: &Verifier, chain: &[String], pop: &str, args: &str) -> Result<(), AatError> {
    verifier
        .verify(
            &Presentation { chain, pop },
            &Invocation {
                tool: TOOL,
                args_json: args,
            },
            NOW,
            None,
        )
        .map(drop)
}

#[test]
fn anchors_sharing_a_key_are_picked_by_iss() {
    let token = root(&root_claims(&wildcard_tools()));
    let proof = pop(&token, "root-1", &json!({ "path": "/a" }), &holder_key());
    let chain = vec![token];
    for anchors in [
        vec![anchor("https://other.example"), anchor(ISSUER)],
        vec![anchor(ISSUER), anchor("https://other.example")],
    ] {
        let verifier = Verifier::new(anchors, vec![AUDIENCE.to_owned()]);
        assert_eq!(verify(&verifier, &chain, &proof, ARGS), Ok(()));
        let decoded = visado_chain::ChainDecoder::decode(&verifier, &chain, NOW).unwrap();
        assert_eq!(decoded.root.issuer, ISSUER);
    }
    let verifier = Verifier::new(
        vec![
            anchor("https://other.example"),
            anchor("https://third.example"),
        ],
        vec![AUDIENCE.to_owned()],
    );
    let err = verify(&verifier, &chain, &proof, ARGS).unwrap_err();
    assert_eq!(err.step(), Step::S3k);
}

#[test]
fn decode_rejects_malformed_aud() {
    for aud in [
        json!([1]),
        json!(7),
        json!({}),
        json!(null),
        json!([AUDIENCE, 7]),
    ] {
        let mut claims = root_claims(&wildcard_tools());
        claims["aud"] = aud.clone();
        let chain = vec![root(&claims)];
        let verifier = Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]);
        let err = visado_chain::ChainDecoder::decode(&verifier, &chain, NOW).unwrap_err();
        assert_eq!(err.step(), Step::S6c, "{aud}");
    }
}

#[test]
fn decode_marks_no_holder_proof() {
    let mut claims = root_claims(&wildcard_tools());
    claims["aud"] = json!([AUDIENCE]);
    let token = root(&claims);
    let proof = pop(&token, "root-1", &json!({ "path": "/a" }), &holder_key());
    let chain = vec![token];
    let verifier = Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]);
    let decoded = visado_chain::ChainDecoder::decode(&verifier, &chain, NOW).unwrap();
    assert!(!decoded.holder_proof);
    assert_eq!(
        decoded.hops[0].audience.as_deref(),
        Some([AUDIENCE.to_owned()].as_slice())
    );
    let authorized = verifier
        .verify(
            &Presentation {
                chain: &chain,
                pop: &proof,
            },
            &Invocation {
                tool: TOOL,
                args_json: ARGS,
            },
            NOW,
            None,
        )
        .unwrap();
    assert!(authorized.chain.holder_proof);
}

#[test]
fn pop_signature_is_checked_before_arguments() {
    let tools = json!({ TOOL: { "path": { "constraint_type": "exact", "value": "/a" } } });
    let token = root(&root_claims(&tools));
    let chain = vec![token.clone()];
    let verifier = Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]);
    let bad_args = r#"{"path":"/b"}"#;
    let forged = pop(&token, "root-1", &json!({ "path": "/b" }), &anchor_key());
    let err = verify(&verifier, &chain, &forged, bad_args).unwrap_err();
    assert_eq!(err.step(), Step::S7b);
    let signed = pop(&token, "root-1", &json!({ "path": "/b" }), &holder_key());
    let err = verify(&verifier, &chain, &signed, bad_args).unwrap_err();
    assert_eq!(err.step(), Step::S6b);
}

/// One `any` over `n` `one_of` clauses: `n + 1` constraint nodes.
fn wide_tools(n: usize) -> Value {
    let clauses: Vec<Value> = (0..n)
        .map(|i| json!({ "constraint_type": "one_of", "values": [format!("v{i}")] }))
        .collect();
    json!({ TOOL: { "path": { "constraint_type": "any", "constraints": clauses } } })
}

#[test]
fn constraint_nodes_are_capped() {
    let token = root(&root_claims(&wide_tools(1024)));
    let chain = vec![token.clone()];
    let verifier = Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]);
    let err = visado_chain::ChainDecoder::decode(&verifier, &chain, NOW).unwrap_err();
    assert_eq!(err.step(), Step::S3n);

    let token = root(&root_claims(&wide_tools(1023)));
    let chain = vec![token.clone()];
    let args = r#"{"path":"v1022"}"#;
    let proof = pop(&token, "root-1", &json!({ "path": "v1022" }), &holder_key());
    assert_eq!(verify(&verifier, &chain, &proof, args), Ok(()));
}

/// A PoP `iat` may be ahead of the clock by the proof skew (5 s by default),
/// not by the whole window: the `jti` is remembered until `iat` plus the
/// window, so a proof from the future would hold its entry that much longer.
#[test]
fn a_pop_from_the_future_is_refused() {
    let token = root(&root_claims(&wildcard_tools()));
    let args = json!({ "path": "/a" });
    let chain = vec![token.clone()];
    let verifier = Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]);
    let ahead = |secs| pop_at(&token, "root-1", &args, &holder_key(), NOW + secs);
    assert_eq!(verify(&verifier, &chain, &ahead(5), ARGS), Ok(()));
    let err = verify(&verifier, &chain, &ahead(6), ARGS).unwrap_err();
    assert_eq!(err.step(), Step::S7g);
    assert!(err.to_string().contains("PoP iat in the future"), "{err}");
    // The past keeps the whole window.
    assert_eq!(verify(&verifier, &chain, &ahead(-30), ARGS), Ok(()));

    // Configurable up to the window.
    let lenient = verifier.with_limits(Limits {
        pop_max_future: 30,
        ..Limits::default()
    });
    assert_eq!(verify(&lenient, &chain, &ahead(30), ARGS), Ok(()));
}

/// A recorded PoP `jti` lives until `iat` plus the window, the last second
/// the proof is accepted in, and is gone after.
#[test]
fn a_pop_jti_is_remembered_while_the_pop_is_accepted() {
    let token = root(&root_claims(&wildcard_tools()));
    let proof = pop_at(
        &token,
        "root-1",
        &json!({ "path": "/a" }),
        &holder_key(),
        NOW + 5,
    );
    let chain = vec![token];
    let verifier = Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]);
    let cache = MemoryReplayCache::new(4);
    let at = |now| {
        verifier
            .verify(
                &Presentation {
                    chain: &chain,
                    pop: &proof,
                },
                &Invocation {
                    tool: TOOL,
                    args_json: ARGS,
                },
                now,
                Some(&cache as &dyn ReplayCache),
            )
            .map(drop)
    };
    assert_eq!(at(NOW), Ok(()));
    let replay = at(NOW + 35).unwrap_err();
    assert_eq!(replay.step(), Step::S7i, "iat + window is still accepted");
    assert_eq!(at(NOW + 36).unwrap_err().step(), Step::S7g);
}

/// Negative PoP limits are taken as zero, and do not panic: the PoP must
/// be dated now.
#[test]
fn negative_pop_limits_are_zero() {
    let token = root(&root_claims(&wildcard_tools()));
    let args = json!({ "path": "/a" });
    let chain = vec![token.clone()];
    let verifier =
        Verifier::new(vec![anchor(ISSUER)], vec![AUDIENCE.to_owned()]).with_limits(Limits {
            pop_window: -30,
            pop_max_future: -5,
            ..Limits::default()
        });
    assert_eq!(verifier.limits().pop_window, 0);
    assert_eq!(verifier.limits().pop_max_future, 0);
    let at = |secs| pop_at(&token, "root-1", &args, &holder_key(), NOW + secs);
    assert_eq!(verify(&verifier, &chain, &at(0), ARGS), Ok(()));
    for secs in [-10, 1] {
        let err = verify(&verifier, &chain, &at(secs), ARGS).unwrap_err();
        assert_eq!(err.step(), Step::S7g);
    }
}
