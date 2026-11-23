//! `aud` as an array of strings (RFC 7519 §4.1.3).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use visado_txn_token::{KeySet, TxnTokenError, Validation, verify};
use wimsey_jose::SigningKey;

const NOW: u64 = 1_800_000_000;
const DOMAIN: &str = "trust-domain.example";

fn key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[9; 32])
}

fn token(aud: &Value) -> String {
    let claims = json!({
        "iat": NOW, "exp": NOW + 60, "aud": aud, "txn": "t-1", "sub": "user@example.com",
        "scope": "read", "req_wl": "spiffe://trust-domain.example/gw",
    });
    let h = URL_SAFE_NO_PAD.encode(br#"{"typ":"txntoken+jwt","alg":"Ed25519","kid":"k1"}"#);
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{h}.{p}");
    let sig = URL_SAFE_NO_PAD.encode(key().sign(input.as_bytes()));
    format!("{input}.{sig}")
}

fn check(aud: &Value) -> Result<String, TxnTokenError> {
    let keys = KeySet::new().with_key("k1", key().verifying_key());
    verify(&token(aud), &keys, &Validation::new(DOMAIN, NOW + 1)).map(|v| v.claims.aud)
}

#[test]
fn a_one_element_array_holding_the_trust_domain_is_accepted() {
    assert_eq!(check(&json!([DOMAIN])).unwrap(), DOMAIN);
}

#[test]
fn an_array_of_several_audiences_is_invalid_even_with_the_trust_domain() {
    // A Txn-Token is scoped to one trust domain (§9.2): accepting
    // ["other.example", DOMAIN] would let one token serve two domains.
    for aud in [
        json!(["other.example", DOMAIN]),
        json!([DOMAIN, "other.example"]),
        json!([DOMAIN, DOMAIN]),
    ] {
        assert!(
            matches!(
                check(&aud),
                Err(TxnTokenError::InvalidClaim { claim: "aud" })
            ),
            "{aud}"
        );
    }
}

#[test]
fn an_array_without_the_trust_domain_is_another_audience() {
    assert!(matches!(
        check(&json!(["other.example"])),
        Err(TxnTokenError::AudienceMismatch)
    ));
}

#[test]
fn an_empty_array_or_a_bad_element_is_invalid() {
    for aud in [json!([]), json!([7]), json!([""]), json!([null])] {
        assert!(
            matches!(
                check(&aud),
                Err(TxnTokenError::InvalidClaim { claim: "aud" })
            ),
            "{aud}"
        );
    }
}

#[test]
fn a_string_still_works_and_other_types_are_malformed() {
    assert_eq!(check(&json!(DOMAIN)).unwrap(), DOMAIN);
    assert!(matches!(
        check(&json!({ "aud": DOMAIN })),
        Err(TxnTokenError::Json(_))
    ));
}
