//! Replacement rules (§13.15) and token request parsing (§11.1).

use serde_json::{Map, Value, json};
use visado_txn_token::{
    GRANT_TYPE_TOKEN_EXCHANGE, KeySet, Replacement, Scope, TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TXN_TOKEN, TokenRequest, TxnTokenClaims, Validation, VerifiedTxnToken,
    check_replacement, fingerprint, mint, replace, verify,
};
use wimsey_jose::SigningKey;

const NOW: u64 = 1_800_000_000;

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn original() -> VerifiedTxnToken {
    let claims = TxnTokenClaims {
        iss: None,
        iat: NOW,
        aud: "td.example".into(),
        exp: NOW + 60,
        txn: "txn-1".into(),
        sub: "alice".into(),
        scope: Scope::parse("read write"),
        req_wl: "spiffe://td.example/gateway".into(),
        tctx: Some(object(&json!({ "tenant": "acme" }))),
        rctx: None,
    };
    let key = SigningKey::from_ed25519_seed(&[3; 32]);
    let token = mint(&claims, None, &key).unwrap();
    let keys = KeySet::new().with_unnamed_key(key.verifying_key());
    verify(&token, &keys, &Validation::new("td.example", NOW + 1)).unwrap()
}

#[test]
fn replacement_narrows_and_keeps_identity() {
    let old = original();
    let next = replace(
        &old,
        Replacement {
            scope: Some(Scope::parse("read")),
            tctx_additions: object(&json!({ "hop": "agent-b" })),
            req_wl: Some("spiffe://td.example/agent-b".into()),
            ..Replacement::default()
        },
        NOW + 10,
        60,
        Some(NOW + 30),
    )
    .unwrap();
    assert_eq!(next.txn, "txn-1");
    assert_eq!(next.sub, "alice");
    assert_eq!(next.scope.to_string(), "read");
    assert_eq!(next.exp, NOW + 30, "max_exp caps lifetime extension");
    assert_eq!(next.tctx.as_ref().unwrap()["tenant"], "acme");
    assert_eq!(next.req_wl, "spiffe://td.example/agent-b");
    check_replacement(&old.claims, &next).unwrap();
}

#[test]
fn replacement_cannot_widen_scope() {
    let err = replace(
        &original(),
        Replacement {
            scope: Some(Scope::parse("read admin")),
            ..Replacement::default()
        },
        NOW + 10,
        60,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code(), "txn.scope_escalation");
}

#[test]
fn replacement_cannot_change_tctx() {
    let err = replace(
        &original(),
        Replacement {
            tctx_additions: object(&json!({ "tenant": "evil" })),
            ..Replacement::default()
        },
        NOW + 10,
        60,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code(), "txn.tctx_modified");
}

#[test]
fn expired_token_cannot_be_replaced() {
    let err = replace(&original(), Replacement::default(), NOW + 60, 60, None).unwrap_err();
    assert_eq!(err.code(), "txn.expired");
}

#[test]
fn check_replacement_rejects_changed_identity() {
    let old = original().claims;
    for (field, code) in [
        ("txn", "txn.immutable_claim_changed"),
        ("sub", "txn.immutable_claim_changed"),
        ("aud", "txn.immutable_claim_changed"),
    ] {
        let mut next = old.clone();
        match field {
            "txn" => next.txn = "txn-2".into(),
            "sub" => next.sub = "mallory".into(),
            _ => next.aud = "other.example".into(),
        }
        assert_eq!(check_replacement(&old, &next).unwrap_err().code(), code);
    }
    let mut dropped = old.clone();
    dropped.tctx = None;
    assert_eq!(
        check_replacement(&old, &dropped).unwrap_err().code(),
        "txn.tctx_modified"
    );
}

#[test]
fn fingerprint_hides_the_token() {
    let fp = fingerprint("a.b.c");
    assert_eq!(fp.len(), 43);
    assert!(!fp.contains('.'));
}

fn form() -> Vec<(&'static str, &'static str)> {
    vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("requested_token_type", TOKEN_TYPE_TXN_TOKEN),
        ("audience", "td.example"),
        ("scope", "trade.stocks"),
        ("subject_token", "eyJ..."),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("request_context", r#"{"req_ip":"69.151.72.123"}"#),
        ("request_details", r#"{"action":"BUY"}"#),
    ]
}

#[test]
fn token_request_parses() {
    let request = TokenRequest::from_form(form()).unwrap();
    assert_eq!(request.audience, "td.example");
    assert_eq!(request.scope.to_string(), "trade.stocks");
    assert_eq!(request.request_details.unwrap()["action"], "BUY");
}

#[test]
fn token_request_rejects_bad_input() {
    let cases: Vec<(&str, Option<&str>)> = vec![
        ("grant_type", Some("client_credentials")),
        (
            "requested_token_type",
            Some("urn:ietf:params:oauth:token-type:access_token"),
        ),
        ("audience", None),
        ("scope", Some("  ")),
        ("subject_token", None),
        ("subject_token_type", Some(TOKEN_TYPE_REFRESH_TOKEN)),
        ("request_context", Some("[1,2]")),
        ("request_details", Some("not json")),
    ];
    for (name, value) in cases {
        let params: Vec<(&str, &str)> = form()
            .into_iter()
            .filter(|(n, _)| *n != name)
            .chain(value.map(|v| (name, v)))
            .collect();
        let err = TokenRequest::from_form(params).unwrap_err();
        assert_eq!(err.code(), "txn.invalid_request", "{name}");
    }
    let mut repeated = form();
    repeated.push(("audience", "other"));
    assert!(TokenRequest::from_form(repeated).is_err());
}
