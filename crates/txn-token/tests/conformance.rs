//! Generates and runs the Transaction Token conformance vectors.
//!
//! The vectors in `conformance/txn-token/vectors.json` are the contract: this
//! test rebuilds them, fails if the file differs, and checks every case against
//! the crate. Set `VISADO_REGENERATE=1` to rewrite the file after an intended
//! change.

use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use visado_txn_token::{KeySet, Validation, verify};
use wimsey_jose::{Jwk, SigningKey};

const TRUST_DOMAIN: &str = "trust-domain.example";
const NOW: u64 = 1_800_000_000;
const MAX_LIFETIME: u64 = 300;

fn ed25519() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x11; 32])
}

fn es256() -> SigningKey {
    SigningKey::from_p256_scalar(&[0x22; 32]).expect("valid scalar")
}

fn claims() -> Value {
    json!({
        "iat": NOW - 10,
        "aud": TRUST_DOMAIN,
        "exp": NOW + 50,
        "txn": "97053963-771d-49cc-a4e3-20aad399c312",
        "sub": "d084sdrt234fsaw34tr23t",
        "scope": "trade.stocks",
        "req_wl": "spiffe://trust-domain.example/apigateway",
        "tctx": { "action": "BUY", "ticker": "MSFT", "quantity": "100" },
        "rctx": { "req_ip": "69.151.72.123", "authn": "urn:ietf:rfc:6749" }
    })
}

fn header(alg: &str, kid: &str) -> Value {
    json!({ "typ": "txntoken+jwt", "alg": alg, "kid": kid })
}

fn sign_raw(header: &Value, claims: &Value, key: &SigningKey) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let input = format!("{h}.{c}");
    let sig = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()));
    format!("{input}.{sig}")
}

fn with(mut base: Value, field: &str, value: Value) -> Value {
    base[field] = value;
    base
}

fn without(mut base: Value, field: &str) -> Value {
    base.as_object_mut().unwrap().remove(field);
    base
}

fn ed(header_patch: Option<(&str, Value)>, claims: &Value) -> String {
    let mut h = header("Ed25519", "ed");
    if let Some((k, v)) = header_patch {
        if v.is_null() {
            h.as_object_mut().unwrap().remove(k);
        } else {
            h[k] = v;
        }
    }
    sign_raw(&h, claims, &ed25519())
}

fn build() -> Value {
    let base = claims();
    let valid = vec![
        json!({ "id": "ed25519", "description": "Ed25519, all claims", "token": ed(None, &base) }),
        json!({ "id": "es256", "description": "ES256, all claims", "token": sign_raw(&header("ES256", "p256"), &base, &es256()) }),
        json!({ "id": "typ-full-media-type", "description": "typ spelled as application/txntoken+jwt", "token": ed(Some(("typ", json!("application/txntoken+jwt"))), &base) }),
        json!({ "id": "unknown-claim-ignored", "description": "recipients ignore claims they do not understand (§9.2)", "token": ed(None, &with(base.clone(), "x_vendor", json!({"a": 1}))) }),
        json!({ "id": "no-optional-claims", "description": "tctx and rctx are RECOMMENDED, not REQUIRED", "token": ed(None, &without(without(base.clone(), "tctx"), "rctx")) }),
    ];

    let good = ed(None, &base);
    let mut flipped = good.clone().into_bytes();
    let last = flipped.len() - 2;
    flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
    let flipped = String::from_utf8(flipped).unwrap();
    let parts: Vec<&str> = good.split('.').collect();

    let negative = vec![
        ("typ-jwt", "typ is JWT", ed(Some(("typ", json!("JWT"))), &base), "txn.wrong_type"),
        ("typ-missing", "no typ header", ed(Some(("typ", Value::Null)), &base), "txn.wrong_type"),
        ("alg-none", "alg none", ed(Some(("alg", json!("none"))), &base), "txn.unsupported_alg"),
        ("alg-hs256", "symmetric alg", ed(Some(("alg", json!("HS256"))), &base), "txn.unsupported_alg"),
        ("alg-mismatch", "header says ES256, key is Ed25519", ed(Some(("alg", json!("ES256"))), &base), "txn.alg_mismatch"),
        ("crit", "critical header parameter", ed(Some(("crit", json!(["exp"]))), &base), "txn.unsupported_crit"),
        ("kid-unknown", "kid not in the key set", ed(Some(("kid", json!("other"))), &base), "txn.unknown_key"),
        ("kid-missing", "no kid and no unnamed key", ed(Some(("kid", Value::Null)), &base), "txn.unknown_key"),
        ("signature", "signature altered", flipped, "txn.bad_signature"),
        ("two-parts", "two compact parts", format!("{}.{}", parts[0], parts[1]), "txn.malformed"),
        ("four-parts", "four compact parts", format!("{good}.x"), "txn.malformed"),
        ("too-long", "over the size limit", "a".repeat(16 * 1024 + 1), "txn.too_long"),
        ("aud-other", "aud is another trust domain", ed(None, &with(base.clone(), "aud", json!("other.example"))), "txn.audience_mismatch"),
        ("expired", "exp before now", ed(None, &with(base.clone(), "exp", json!(NOW - 1))), "txn.expired"),
        ("exp-now", "exp equal to now", ed(None, &with(base.clone(), "exp", json!(NOW))), "txn.expired"),
        ("iat-future", "iat after now", ed(None, &with(with(base.clone(), "iat", json!(NOW + 5)), "exp", json!(NOW + 60))), "txn.issued_in_future"),
        ("lifetime", "exp - iat over the 300 s cap", ed(None, &with(base.clone(), "exp", json!(NOW + 400))), "txn.invalid_lifetime"),
        ("exp-before-iat", "exp not after iat", ed(None, &with(with(base.clone(), "iat", json!(NOW - 10)), "exp", json!(NOW - 10))), "txn.invalid_lifetime"),
        ("req-wl-missing", "req_wl absent", ed(None, &without(base.clone(), "req_wl")), "txn.malformed"),
        ("txn-missing", "txn absent", ed(None, &without(base.clone(), "txn")), "txn.malformed"),
        ("sub-empty", "sub is empty", ed(None, &with(base.clone(), "sub", json!(""))), "txn.invalid_claim"),
        ("scope-empty", "scope is empty", ed(None, &with(base.clone(), "scope", json!(" "))), "txn.invalid_claim"),
    ]
    .into_iter()
    .map(|(id, description, token, expect)| json!({ "id": id, "description": description, "token": token, "expect": expect }))
    .collect::<Vec<_>>();

    json!({
        "format": "visado-conformance/v1",
        "suite": "txn-token",
        "spec": "draft-ietf-oauth-transaction-tokens-11",
        "validation": { "trust_domain": TRUST_DOMAIN, "now": NOW, "leeway": 0, "max_lifetime": MAX_LIFETIME },
        "keys": [
            { "kid": "ed", "jwk": Jwk::from_verifying_key(&ed25519().verifying_key()) },
            { "kid": "p256", "jwk": Jwk::from_verifying_key(&es256().verifying_key()) }
        ],
        "valid": valid,
        "negative": negative
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/txn-token/vectors.json")
}

#[test]
fn vectors_are_fresh_and_pass() {
    let generated = build();
    let rendered = serde_json::to_string_pretty(&generated).unwrap() + "\n";
    if std::env::var_os("VISADO_REGENERATE").is_some() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), &rendered).unwrap();
    }
    let on_disk = std::fs::read_to_string(path()).expect("run with VISADO_REGENERATE=1 once");
    assert_eq!(
        on_disk, rendered,
        "vectors are stale; rerun with VISADO_REGENERATE=1"
    );

    let vectors: Value = serde_json::from_str(&on_disk).unwrap();
    let mut keys = KeySet::new();
    for k in vectors["keys"].as_array().unwrap() {
        let jwk: Jwk = serde_json::from_value(k["jwk"].clone()).unwrap();
        keys = keys.with_key(k["kid"].as_str().unwrap(), jwk.to_verifying_key().unwrap());
    }
    let v = &vectors["validation"];
    let validation = Validation::new(
        v["trust_domain"].as_str().unwrap(),
        v["now"].as_u64().unwrap(),
    )
    .with_leeway(v["leeway"].as_u64().unwrap())
    .with_max_lifetime(v["max_lifetime"].as_u64().unwrap());

    for case in vectors["valid"].as_array().unwrap() {
        let token = case["token"].as_str().unwrap();
        verify(token, &keys, &validation)
            .unwrap_or_else(|e| panic!("{}: expected valid, got {}", case["id"], e.code()));
    }
    for case in vectors["negative"].as_array().unwrap() {
        let token = case["token"].as_str().unwrap();
        let err = verify(token, &keys, &validation)
            .err()
            .unwrap_or_else(|| panic!("{}: expected {}, got valid", case["id"], case["expect"]));
        assert_eq!(
            err.code(),
            case["expect"].as_str().unwrap(),
            "{}",
            case["id"]
        );
    }
}
