//! Cases outside the published vectors, built with local keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use visado_chain_aat::{AatError, Invocation, Presentation, Step, TrustAnchor, Verifier};
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
    let claims = json!({
        "jti": "pop-1", "iat": NOW, "aat_id": leaf_jti, "aat_hash": signing_input_hash(leaf),
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
