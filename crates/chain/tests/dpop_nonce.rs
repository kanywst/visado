//! The server-provided `nonce` check of [`visado_chain::dpop::verify`]
//! (RFC 9449 §4.3 item 10, §8, §9, §11.3).

use serde_json::{Value, json};
use visado_chain::dpop::{Expected, HttpRequest, NonceError, Nonces, Rejection, verify};
use visado_chain::jose::key_thumbprint;
use visado_testkit::{dpop_claims, dpop_jwk, pop_key, sign_dpop_proof};
use wimsey_jose::SigningKey;

const NOW: i64 = 1_800_000_000;
const URI: &str = "https://tools.td.example/mcp";
const TOKEN: &str = "access-token";

fn nonces() -> Nonces {
    Nonces::new(&[3; 32], 120).unwrap()
}

fn holder() -> SigningKey {
    pop_key(9)
}

fn proof(edit: impl FnOnce(&mut Value)) -> String {
    let key = holder();
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(&key) });
    let mut claims = dpop_claims("POST", URI, TOKEN, "j-1", NOW.unsigned_abs());
    edit(&mut claims);
    sign_dpop_proof(&header, &claims, &key)
}

fn check(proof: &str, nonces: Option<&Nonces>) -> Result<(), Rejection> {
    let jkt = key_thumbprint(&holder().verifying_key());
    let expected = Expected {
        jkt: &jkt,
        access_token: TOKEN,
        algs: &["Ed25519"],
        max_size: 8192,
        iat_window: 60,
        nonces,
    };
    let request = HttpRequest {
        method: "POST",
        uri: URI,
    };
    verify(proof, &expected, &request, NOW).map(|_| ())
}

#[test]
fn a_proof_with_a_fresh_nonce_is_accepted() {
    let n = nonces();
    let nonce = n.issue(NOW - 10);
    assert_eq!(
        check(&proof(|c| c["nonce"] = json!(nonce)), Some(&n)),
        Ok(())
    );
}

#[test]
fn without_nonces_the_claim_is_ignored() {
    assert_eq!(check(&proof(|_| {}), None), Ok(()));
    assert_eq!(
        check(&proof(|c| c["nonce"] = json!("anything")), None),
        Ok(())
    );
}

#[test]
fn each_nonce_failure_is_reported() {
    let n = nonces();
    let other = Nonces::new(&[4; 32], 120).unwrap();
    let cases: [(Value, NonceError); 7] = [
        (Value::Null, NonceError::Missing),
        (json!(42), NonceError::Malformed),
        (json!(null), NonceError::Malformed),
        (json!("not-a-nonce"), NonceError::Malformed),
        (json!(other.issue(NOW)), NonceError::Invalid),
        (json!(n.issue(NOW - 120)), NonceError::Expired),
        (json!(n.issue(NOW + 60)), NonceError::Future),
    ];
    for (i, (nonce, want)) in cases.into_iter().enumerate() {
        // `Value::Null` in the first case stands for "no claim at all".
        let p = proof(|c| {
            if i > 0 {
                c["nonce"] = nonce.clone();
            }
        });
        assert_eq!(check(&p, Some(&n)), Err(Rejection::Nonce(want)), "case {i}");
        assert_eq!(Rejection::Nonce(want).reason(), want.reason());
    }
}

#[test]
fn the_nonce_is_checked_after_every_other_check() {
    let n = nonces();
    // A proof for another method and without a nonce fails on `htm`, not
    // on the nonce: a fresh nonce would not help.
    let p = proof(|c| c["htm"] = json!("GET"));
    assert!(matches!(check(&p, Some(&n)), Err(Rejection::Proof(_))));
    // Another key is still a key mismatch.
    let key = pop_key(10);
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(&key) });
    let p = sign_dpop_proof(
        &header,
        &dpop_claims("POST", URI, TOKEN, "j-2", NOW.unsigned_abs()),
        &key,
    );
    assert_eq!(check(&p, Some(&n)), Err(Rejection::KeyMismatch));
    // A nonce in an unsigned proof is never looked at.
    let good = proof(|c| c["nonce"] = json!(n.issue(NOW)));
    let unsigned = format!("{}.", good.rsplit_once('.').unwrap().0);
    assert!(matches!(
        check(&unsigned, Some(&n)),
        Err(Rejection::Proof(_))
    ));
}
