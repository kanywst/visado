//! Caller authentication against fixed-key fixtures.

#![allow(clippy::too_many_lines, clippy::type_complexity)]

use visado_credentials::{
    Authenticated, Authenticator, Method, OAuthIssuer, RequestView, WitIssuer,
};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, oauth_jwks, pop_key, wit, wit_for,
    wit_issuer_verifying_key, wpt,
};

const AUDIENCE: &str = "https://tools.td.example/mcp";

fn authenticator() -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks))
}

fn run(auth: &Authenticator, headers: &[(&str, &str)]) -> Result<Authenticated, String> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let view = RequestView {
        method: "POST",
        scheme: "https",
        authority: "tools.td.example",
        path: "/mcp?session=1",
        headers: &headers,
        body: None,
        peer_certificate: None,
    };
    auth.authenticate(&view, NOW)
        .map_err(|e| e.code().to_owned())
}

#[test]
fn wit_and_wpt_authenticate_a_workload() {
    let auth = authenticator();
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let p = wpt(&w, &pop, AUDIENCE, "j1", None, None);
    let ok = run(
        &auth,
        &[
            ("workload-identity-token", &w),
            ("authorization", &format!("WPT {p}")),
        ],
    )
    .unwrap();
    assert_eq!(ok.caller, "spiffe://td.example/agent-a");
    assert_eq!(ok.method, Method::WitWpt);
    assert!(ok.user.is_none());
}

#[test]
fn a_bound_user_token_is_verified() {
    let auth = authenticator();
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let at = access_token("alice", "agent-a", "files.read", AUDIENCE, NOW + 300);
    let p = wpt(&w, &pop, AUDIENCE, "j2", None, Some(("x-user-token", &at)));
    let ok = run(
        &auth,
        &[
            ("workload-identity-token", &w),
            ("authorization", &format!("WPT {p}")),
            ("x-user-token", &at),
        ],
    )
    .unwrap();
    assert_eq!(ok.user.unwrap().subject, "alice");
}

#[test]
fn rejections_have_reason_codes() {
    let auth = authenticator();
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let other_domain = wit_for("spiffe://other.example/agent-x", &pop_key(9));
    let at = access_token("alice", "agent-a", "files.read", AUDIENCE, NOW + 300);
    let wrong_aud = wpt(&w, &pop, "https://elsewhere.example/mcp", "j3", None, None);
    let stolen = wpt(&w, &pop_key(2), AUDIENCE, "j4", None, None);
    let unbound = wpt(&w, &pop, AUDIENCE, "j5", None, None);
    let replayed = wpt(&w, &pop, AUDIENCE, "j6", None, None);
    let wpt_ok = |p: &str| format!("WPT {p}");

    run(
        &auth,
        &[
            ("workload-identity-token", &w),
            ("authorization", &wpt_ok(&replayed)),
        ],
    )
    .unwrap();

    let cases: Vec<(&str, Vec<(&str, String)>, &str)> = vec![
        ("nothing", vec![], "credential.missing"),
        (
            "wit without proof",
            vec![("workload-identity-token", w.clone())],
            "wpt.missing",
        ),
        (
            "foreign trust domain",
            vec![
                ("workload-identity-token", other_domain),
                ("authorization", wpt_ok(&unbound)),
            ],
            "wit.untrusted_domain",
        ),
        (
            "wrong audience",
            vec![
                ("workload-identity-token", w.clone()),
                ("authorization", wpt_ok(&wrong_aud)),
            ],
            "wpt.invalid",
        ),
        (
            "proof signed by another key",
            vec![
                ("workload-identity-token", w.clone()),
                ("authorization", wpt_ok(&stolen)),
            ],
            "wpt.invalid",
        ),
        (
            "replayed proof",
            vec![
                ("workload-identity-token", w.clone()),
                ("authorization", wpt_ok(&replayed)),
            ],
            "wpt.replay",
        ),
        (
            "user token not bound",
            vec![
                ("workload-identity-token", w.clone()),
                ("authorization", wpt_ok(&unbound)),
                ("x-user-token", at.clone()),
            ],
            "credential.unbound_user_token",
        ),
        (
            "two WITs",
            vec![
                ("workload-identity-token", w.clone()),
                ("workload-identity-token", w.clone()),
            ],
            "credential.repeated_header",
        ),
        (
            "expired access token",
            vec![(
                "authorization",
                format!(
                    "Bearer {}",
                    access_token("alice", "c", "s", AUDIENCE, NOW - 100)
                ),
            )],
            "token.expired",
        ),
        (
            "access token for another audience",
            vec![(
                "authorization",
                format!(
                    "Bearer {}",
                    access_token("alice", "c", "s", "https://other", NOW + 100)
                ),
            )],
            "token.invalid",
        ),
        (
            "tampered access token",
            vec![("authorization", format!("Bearer {at}x"))],
            "token.invalid",
        ),
    ];
    for (name, headers, code) in cases {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        assert_eq!(run(&auth, &headers).unwrap_err(), code, "{name}");
    }
}

#[test]
fn bearer_only_caller_is_the_client() {
    let auth = authenticator();
    let at = access_token("alice", "mcp-client", "files.read", AUDIENCE, NOW + 300);
    let ok = run(&auth, &[("authorization", &format!("Bearer {at}"))]).unwrap();
    assert_eq!(ok.caller, "mcp-client");
    assert_eq!(ok.method, Method::Bearer);
    assert_eq!(ok.user.unwrap().scope.as_deref(), Some("files.read"));
}

#[test]
fn an_access_token_exposes_its_actor_claim_and_key() {
    use serde_json::json;
    use visado_testkit::signed_access_token;
    let auth = authenticator();
    let claims = json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "c1",
        "iat": NOW - 5, "exp": NOW + 300, "jti": "at-1",
        "act": { "sub": "c1", "act": { "sub": "agent-0" } },
    });
    let token = format!("Bearer {}", signed_access_token(&claims));
    let user = run(&auth, &[("authorization", &token)])
        .unwrap()
        .user
        .unwrap();
    assert_eq!(user.act, Some(claims["act"].clone()));
    assert_eq!(user.id.as_deref(), Some("at-1"));
    assert_eq!(user.issued_at, Some(NOW - 5));
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(oauth_jwks()).unwrap();
    assert_eq!(
        user.key_thumbprint,
        jwks.keys[0]
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .unwrap()
    );

    let plain = access_token("alice", "c1", "s", AUDIENCE, NOW + 300);
    let user = run(&auth, &[("authorization", &format!("Bearer {plain}"))])
        .unwrap()
        .user
        .unwrap();
    assert!(user.act.is_none());
}

#[test]
fn access_token_edge_cases() {
    use serde_json::json;
    use visado_testkit::signed_access_token;
    let auth = authenticator();
    let base = json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "c1", "exp": NOW + 300,
    });
    let with = |key: &str, value: serde_json::Value| {
        let mut claims = base.clone();
        claims[key] = value;
        format!("Bearer {}", signed_access_token(&claims))
    };

    let bound = with("cnf", json!({ "jkt": "abc" }));
    assert_eq!(
        run(&auth, &[("authorization", &bound)]).unwrap_err(),
        "token.sender_constrained"
    );

    let early = with("nbf", json!(NOW + 3600));
    assert_eq!(
        run(&auth, &[("authorization", &early)]).unwrap_err(),
        "token.invalid"
    );

    let scp = with("scp", json!(["files.read", "files.write"]));
    let ok = run(&auth, &[("authorization", &scp)]).unwrap();
    assert_eq!(
        ok.user.unwrap().scope.as_deref(),
        Some("files.read files.write")
    );
}

#[test]
fn long_jti_is_rejected() {
    let auth = authenticator();
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let p = wpt(&w, &pop, AUDIENCE, &"j".repeat(300), None, None);
    let err = run(
        &auth,
        &[
            ("workload-identity-token", &w),
            ("authorization", &format!("WPT {p}")),
        ],
    )
    .unwrap_err();
    assert_eq!(err, "wpt.invalid");
}

#[test]
fn issuers_need_prefixes_when_several_are_trusted() {
    let jwks = || serde_json::from_value(oauth_jwks()).unwrap();
    let two = Authenticator::new()
        .with_oauth_issuer(OAuthIssuer::new("https://a", "x", jwks()))
        .with_oauth_issuer(OAuthIssuer::new("https://b", "x", jwks()));
    assert!(two.check().is_err());
    let prefixed = Authenticator::new()
        .with_oauth_issuer(OAuthIssuer::new("https://a", "x", jwks()).with_subject_prefix("a:"))
        .with_oauth_issuer(OAuthIssuer::new("https://b", "x", jwks()).with_subject_prefix("b:"));
    assert!(prefixed.check().is_ok());

    let auth = Authenticator::new().with_oauth_issuer(
        OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks()).with_subject_prefix("idp:"),
    );
    let at = access_token("alice", "c1", "s", AUDIENCE, NOW + 300);
    let ok = run(&auth, &[("authorization", &format!("Bearer {at}"))]).unwrap();
    assert_eq!(ok.caller, "idp:c1");
    assert_eq!(ok.user.unwrap().subject, "idp:alice");
}
