//! `RS256` Transaction Tokens, as a Transaction Token Service that signs
//! with RSA issues them. The keys in `fixtures/` are test-only.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use visado_txn_token::{KeySet, TxnTokenError, Validation, verify};
use wimsey_jose::SigningKey;

const NOW: u64 = 1_800_000_000;
const DOMAIN: &str = "trust-domain.example";

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("fixture")
}

fn public(name: &str) -> (Vec<u8>, Vec<u8>) {
    let jwk: Value = serde_json::from_str(&fixture(name)).expect("jwk");
    let part = |k: &str| URL_SAFE_NO_PAD.decode(jwk[k].as_str().unwrap()).unwrap();
    (part("n"), part("e"))
}

fn keys() -> KeySet {
    let (n, e) = public("rsa-2048.public.jwk.json");
    KeySet::new()
        .with_rsa_key("rsa-1", &n, &e)
        .expect("2048-bit key")
}

fn claims() -> Value {
    json!({
        "iat": NOW, "exp": NOW + 60, "aud": DOMAIN, "txn": "t-1", "sub": "user@example.com",
        "scope": "read", "req_wl": "spiffe://trust-domain.example/gw",
        "tctx": { "action": "BUY" },
    })
}

fn sign(header: &Header, claims: &Value) -> String {
    let der = STANDARD
        .decode(fixture("rsa-2048.private.der.b64").trim())
        .expect("der");
    encode(header, claims, &EncodingKey::from_rsa_der(&der)).expect("sign")
}

fn header(kid: Option<&str>) -> Header {
    let mut h = Header::new(Algorithm::RS256);
    h.typ = Some("txntoken+jwt".to_owned());
    h.kid = kid.map(ToOwned::to_owned);
    h
}

fn check(token: &str, keys: &KeySet) -> Result<(), TxnTokenError> {
    verify(token, keys, &Validation::new(DOMAIN, NOW + 1)).map(|_| ())
}

#[test]
fn an_rs256_token_verifies() {
    let token = sign(&header(Some("rsa-1")), &claims());
    let verified = verify(&token, &keys(), &Validation::new(DOMAIN, NOW + 1)).expect("verifies");
    assert_eq!(verified.claims.txn, "t-1");
    assert_eq!(verified.claims.tctx.unwrap()["action"], "BUY");
}

#[test]
fn an_unnamed_rsa_key_takes_a_token_without_kid() {
    let (n, e) = public("rsa-2048.public.jwk.json");
    let keys = KeySet::new().with_unnamed_rsa_key(&n, &e).unwrap();
    assert!(check(&sign(&header(None), &claims()), &keys).is_ok());
}

#[test]
fn a_tampered_rs256_token_is_rejected() {
    let token = sign(&header(Some("rsa-1")), &claims());
    let (input, sig) = token.rsplit_once('.').unwrap();
    let (h, _) = input.split_once('.').unwrap();
    let mut other = claims();
    other["scope"] = json!("read write");
    let forged = format!(
        "{h}.{}.{sig}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&other).unwrap())
    );
    assert!(matches!(
        check(&forged, &keys()),
        Err(TxnTokenError::InvalidSignature)
    ));
}

#[test]
fn a_truncated_signature_is_malformed() {
    let token = sign(&header(Some("rsa-1")), &claims());
    let (input, sig) = token.rsplit_once('.').unwrap();
    let short = &sig[..sig.len() - 8];
    assert!(matches!(
        check(&format!("{input}.{short}"), &keys()),
        Err(TxnTokenError::Malformed)
    ));
}

#[test]
fn a_key_under_2048_bits_is_refused() {
    let (n, e) = public("rsa-1024.public.jwk.json");
    assert!(matches!(
        KeySet::new().with_rsa_key("weak", &n, &e),
        Err(TxnTokenError::WeakKey)
    ));
    let (n, _) = public("rsa-2048.public.jwk.json");
    assert!(matches!(
        KeySet::new().with_rsa_key("no-e", &n, &[]),
        Err(TxnTokenError::InvalidKey(_))
    ));
}

#[test]
fn rs256_needs_an_rsa_key_and_an_rsa_key_takes_only_rs256() {
    // An RS256 header naming an Ed25519 key.
    let ed = SigningKey::from_ed25519_seed(&[3; 32]);
    let keys = keys().with_key("ed-1", ed.verifying_key());
    assert!(matches!(
        check(&sign(&header(Some("ed-1")), &claims()), &keys),
        Err(TxnTokenError::AlgorithmMismatch)
    ));
    // An Ed25519 token naming the RSA key.
    let claims: visado_txn_token::TxnTokenClaims = serde_json::from_value(claims()).unwrap();
    let token = visado_txn_token::mint(&claims, Some("rsa-1"), &ed).unwrap();
    assert!(matches!(
        check(&token, &keys),
        Err(TxnTokenError::AlgorithmMismatch)
    ));
    // `get` returns only Ed25519 and ES256 keys.
    assert!(keys.get(Some("rsa-1")).is_none());
    assert!(keys.get(Some("ed-1")).is_some());
}

#[test]
fn other_rsa_algorithms_are_not_supported() {
    for alg in [Algorithm::RS384, Algorithm::PS256] {
        let mut h = header(Some("rsa-1"));
        h.alg = alg;
        assert!(matches!(
            check(&sign(&h, &claims()), &keys()),
            Err(TxnTokenError::UnsupportedAlg { .. })
        ));
    }
}

#[test]
fn only_the_exponent_65537_is_accepted() {
    let (n, e) = public("rsa-2048.public.jwk.json");
    assert_eq!(e, [0x01, 0x00, 0x01]);
    for bad in [
        &[1][..],
        &[3],
        &[0x01, 0x00, 0x00],
        &[0x01, 0x00, 0x03],
        &[0x00, 0x01, 0x00, 0x01, 0x00],
    ] {
        assert!(
            matches!(
                KeySet::new().with_rsa_key("k", &n, bad),
                Err(TxnTokenError::InvalidKey(_))
            ),
            "{bad:?}"
        );
    }
    // Leading zero bytes do not change the value.
    assert!(KeySet::new().with_rsa_key("k", &n, &[0, 1, 0, 1]).is_ok());
}
