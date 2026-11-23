//! Minting `RS256` Transaction Tokens with an RSA key from a private JWK.
//! The keys in `fixtures/` are test-only.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation as JwtValidation, decode};
use serde_json::{Value, json};
use visado_txn_token::{
    Scope, TxnSigningKey, TxnTokenClaims, TxnTokenError, Validation, mint_with, verify,
};
use wimsey_jose::SigningKey;

const NOW: u64 = 1_800_000_000;
const DOMAIN: &str = "trust-domain.example";

fn jwk(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn claims() -> TxnTokenClaims {
    TxnTokenClaims {
        iss: Some("https://tts.example".into()),
        iat: NOW,
        aud: DOMAIN.into(),
        exp: NOW + 60,
        txn: "t-1".into(),
        sub: "user@example.com".into(),
        scope: Scope::parse("read"),
        req_wl: "spiffe://trust-domain.example/gw".into(),
        tctx: None,
        rctx: None,
    }
}

fn rsa() -> TxnSigningKey {
    TxnSigningKey::from_rsa_jwk(&jwk("rsa-2048.private.jwk.json")).expect("RSA key")
}

#[test]
fn an_rsa_key_mints_rs256_that_visado_verifies() {
    let key = rsa();
    assert_eq!(key.alg(), "RS256");
    let token = mint_with(&claims(), Some("rsa-1"), &key).unwrap();
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "txntoken+jwt");
    let verified = verify(
        &token,
        &key.key_set("rsa-1"),
        &Validation::new(DOMAIN, NOW + 1),
    )
    .unwrap();
    assert_eq!(verified.claims, claims());
}

#[test]
fn another_rs256_verifier_accepts_the_token() {
    // jsonwebtoken, with the public JWK alone, as a recipient would hold it.
    let token = mint_with(&claims(), Some("rsa-1"), &rsa()).unwrap();
    let public = jwk("rsa-2048.public.jwk.json");
    let key = DecodingKey::from_rsa_components(
        public["n"].as_str().unwrap(),
        public["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = JwtValidation::new(Algorithm::RS256);
    validation.set_audience(&[DOMAIN]);
    validation.validate_exp = false;
    let data = decode::<Value>(&token, &key, &validation).unwrap();
    assert_eq!(data.claims["txn"], "t-1");
}

#[test]
fn the_public_jwk_has_no_private_members() {
    let public = rsa().public_jwk().unwrap();
    assert_eq!(public["kty"], "RSA");
    assert_eq!(public["alg"], "RS256");
    assert_eq!(public["n"], jwk("rsa-2048.public.jwk.json")["n"]);
    for private in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(public.get(private).is_none(), "{private}");
    }
}

#[test]
fn unusable_rsa_jwks_are_refused() {
    let full = jwk("rsa-2048.private.jwk.json");
    let mut missing = full.clone();
    missing.as_object_mut().unwrap().remove("qi");
    assert!(matches!(
        TxnSigningKey::from_rsa_jwk(&missing),
        Err(TxnTokenError::InvalidKey("qi"))
    ));
    let mut ec = full.clone();
    ec["kty"] = json!("EC");
    assert!(matches!(
        TxnSigningKey::from_rsa_jwk(&ec),
        Err(TxnTokenError::InvalidKey(_))
    ));
    let mut mismatched = full.clone();
    mismatched["d"] = full["p"].clone();
    assert!(matches!(
        TxnSigningKey::from_rsa_jwk(&mismatched),
        Err(TxnTokenError::InvalidKey(_))
    ));
    let mut weak = full;
    weak["n"] = jwk("rsa-1024.public.jwk.json")["n"].clone();
    assert!(matches!(
        TxnSigningKey::from_rsa_jwk(&weak),
        Err(TxnTokenError::WeakKey)
    ));
}

#[test]
fn a_jose_key_converts_and_mints_as_before() {
    let ed = SigningKey::from_ed25519_seed(&[7; 32]);
    let a = visado_txn_token::mint(&claims(), Some("k"), &ed).unwrap();
    let b = mint_with(&claims(), Some("k"), &TxnSigningKey::from(ed)).unwrap();
    assert_eq!(a, b);
}

#[test]
fn an_rsa_signers_key_set_holds_its_key_under_the_kid() {
    let key = rsa();
    let token = mint_with(&claims(), Some("rsa-1"), &key).unwrap();
    let validation = Validation::new(DOMAIN, NOW + 1);
    assert!(verify(&token, &key.key_set("rsa-1"), &validation).is_ok());
    // Under another kid the set has no key for this token: never a silent
    // empty set standing in for a failed key.
    assert!(matches!(
        verify(&token, &key.key_set("other"), &validation),
        Err(TxnTokenError::UnknownKey)
    ));
    let other = mint_with(&claims(), Some("other"), &key).unwrap();
    assert!(verify(&other, &key.key_set("other"), &validation).is_ok());
}
