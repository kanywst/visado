//! Workloads that present a SPIFFE JWT-SVID as a bearer token.

use serde_json::{Value, json};
use visado_credentials::{
    Authenticated, Authenticator, JwtBundle, Method, OAuthIssuer, RequestView,
};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, jwt_bundle, jwt_svid, oauth_jwks,
    signed_jwt_svid,
};

const AGENT: &str = "spiffe://td.example/agent-a";
const AUDIENCE: &str = "spiffe://td.example/visado";

fn authenticator() -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new()
        .with_jwt_bundle(JwtBundle::from_spiffe_bundle(TRUST_DOMAIN, &jwt_bundle()).unwrap())
        .with_jwt_svid_audience(AUDIENCE)
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks))
}

fn run(auth: &Authenticator, headers: &[(&str, &str)]) -> Result<Authenticated, String> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let view = RequestView {
        method: "GET",
        scheme: "https",
        authority: "tools.td.example",
        path: "/mcp",
        headers: &headers,
        body: None,
        peer_certificate: None,
    };
    auth.authenticate(&view, NOW)
        .map_err(|e| e.code().to_owned())
}

/// The code and the detail of a rejection.
fn failure(auth: &Authenticator, authorization: &str) -> String {
    let headers = vec![("authorization".to_owned(), authorization.to_owned())];
    let view = RequestView {
        method: "GET",
        scheme: "https",
        authority: "tools.td.example",
        path: "/mcp",
        headers: &headers,
        body: None,
        peer_certificate: None,
    };
    let err = auth.authenticate(&view, NOW).unwrap_err();
    format!("{} {err}", err.code())
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn claims() -> Value {
    json!({ "sub": AGENT, "aud": AUDIENCE, "exp": NOW + 300 })
}

#[test]
fn a_jwt_svid_authenticates_the_workload() {
    let auth = authenticator();
    let ok = run(
        &auth,
        &[(
            "authorization",
            &bearer(&jwt_svid(AGENT, AUDIENCE, NOW + 300)),
        )],
    )
    .unwrap();
    assert_eq!(ok.caller, AGENT);
    assert_eq!(ok.method, Method::JwtSvid);
    assert!(ok.user.is_none());
    assert!(ok.proof_key.is_none());

    // RS256 and `typ: JOSE` or no `typ` at all.
    for header in [
        json!({ "alg": "RS256", "kid": "svid-rs", "typ": "JOSE" }),
        json!({ "alg": "ES256", "kid": "svid-es" }),
    ] {
        let token = signed_jwt_svid(&header, &claims());
        assert_eq!(
            run(&auth, &[("authorization", &bearer(&token))])
                .unwrap()
                .caller,
            AGENT
        );
    }

    // An access token from the OAuth issuer still goes the OAuth way.
    let at = access_token("alice", "client-1", "s", AUDIENCE, NOW + 300);
    let ok = run(&auth, &[("authorization", &bearer(&at))]).unwrap();
    assert_eq!(ok.method, Method::Bearer);
}

#[test]
fn rejections_have_reason_codes() {
    let auth = authenticator();
    let with = |key: &str, value: Value| {
        let mut c = claims();
        c[key] = value;
        signed_jwt_svid(&json!({ "alg": "ES256", "kid": "svid-es" }), &c)
    };
    let without = |key: &str| {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(key);
        signed_jwt_svid(&json!({ "alg": "ES256", "kid": "svid-es" }), &c)
    };
    let header = |h: Value| signed_jwt_svid(&h, &claims());

    let cases: Vec<(&str, String, &str)> = vec![
        (
            "expired",
            jwt_svid(AGENT, AUDIENCE, NOW - 60),
            "jwt_svid.invalid|expired",
        ),
        (
            "another audience",
            jwt_svid(AGENT, "spiffe://td.example/other", NOW + 300),
            "jwt_svid.invalid|InvalidAudience",
        ),
        (
            "no audience",
            without("aud"),
            "jwt_svid.invalid|Missing required claim: aud",
        ),
        ("no exp", without("exp"), "jwt_svid.invalid|exp"),
        (
            "not yet valid",
            with("nbf", json!(NOW + 3600)),
            "jwt_svid.invalid|not yet valid",
        ),
        (
            "another trust domain",
            jwt_svid("spiffe://other.example/agent-x", AUDIENCE, NOW + 300),
            "jwt_svid.untrusted_domain|untrusted",
        ),
        (
            "typ not JWT",
            header(json!({ "alg": "ES256", "kid": "svid-es", "typ": "at+jwt" })),
            "jwt_svid.invalid|typ",
        ),
        (
            "unknown kid",
            header(json!({ "alg": "ES256", "kid": "nope" })),
            "jwt_svid.invalid|no trusted key",
        ),
        (
            "no kid with two keys",
            header(json!({ "alg": "ES256" })),
            "jwt_svid.invalid|no trusted key",
        ),
        (
            "alg not the key's",
            header(json!({ "alg": "RS256", "kid": "svid-es" })),
            "jwt_svid.invalid|does not match the key",
        ),
        (
            "tampered",
            format!("{}x", jwt_svid(AGENT, AUDIENCE, NOW + 300)),
            "jwt_svid.invalid|malformed base64url",
        ),
    ];
    for (name, token, expected) in cases {
        let (code, detail) = expected.split_once('|').unwrap();
        let failure = failure(&auth, &bearer(&token));
        assert!(
            failure.starts_with(&format!("{code} ")),
            "{name}: {failure}"
        );
        assert!(failure.contains(detail), "{name}: {failure}");
    }

    // An algorithm outside RS256 and ES256 is refused before any key is used.
    let none = {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"svid-es"}"#);
        let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims()).unwrap());
        format!("{h}.{c}.AAAA")
    };
    assert_eq!(
        run(&auth, &[("authorization", &bearer(&none))]).unwrap_err(),
        "jwt_svid.invalid"
    );

    let svid = jwt_svid(AGENT, AUDIENCE, NOW + 300);
    assert_eq!(
        run(
            &auth,
            &[
                ("authorization", &bearer(&svid)),
                ("x-user-token", "anything")
            ]
        )
        .unwrap_err(),
        "credential.unbound_user_token"
    );
}

#[test]
fn without_a_bundle_a_jwt_svid_is_an_unknown_access_token() {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    let auth =
        Authenticator::new().with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks));
    let svid = jwt_svid(AGENT, AUDIENCE, NOW + 300);
    assert!(run(&auth, &[("authorization", &bearer(&svid))]).is_err());
}

#[test]
fn bundles_and_audiences_are_checked() {
    assert!(JwtBundle::from_spiffe_bundle(TRUST_DOMAIN, &json!({})).is_err());
    assert!(JwtBundle::from_spiffe_bundle(TRUST_DOMAIN, &json!({ "keys": [] })).is_err());
    let mut no_kid = jwt_bundle();
    no_kid["keys"][0].as_object_mut().unwrap().remove("kid");
    assert!(JwtBundle::from_spiffe_bundle(TRUST_DOMAIN, &no_kid).is_err());

    let without_audience = Authenticator::new()
        .with_jwt_bundle(JwtBundle::from_spiffe_bundle(TRUST_DOMAIN, &jwt_bundle()).unwrap());
    assert!(without_audience.check().is_err());
    assert!(authenticator().check().is_ok());
}
