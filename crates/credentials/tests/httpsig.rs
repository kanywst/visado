//! WIT callers that sign the request (draft-ietf-wimse-http-signature-08).

#![allow(clippy::too_many_lines)]

use visado_credentials::{
    Authenticated, Authenticator, Method, OAuthIssuer, RequestView, WitIssuer,
};
use visado_testkit::{
    NOW, OAUTH_ISSUER, SignatureSpec, TRUST_DOMAIN, access_token, content_digest, http_signature,
    oauth_jwks, pop_key, signature_request, wit, wit_for, wit_issuer_verifying_key,
};
use wimsey_httpsig::{SignatureParams, WIMSE_TAG};

const HOST: &str = "tools.td.example";
const PATH: &str = "/mcp?session=1";
const AUDIENCE: &str = "https://tools.td.example/mcp";

fn authenticator() -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks))
}

/// Runs a POST. Without a body or a length header it says `content-length: 0`,
/// since a POST is otherwise assumed to carry a body.
fn run(
    auth: &Authenticator,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    now: u64,
) -> Result<Authenticated, String> {
    let announced = headers
        .iter()
        .any(|(n, _)| n == "content-length" || n == "transfer-encoding");
    if body.is_none() && !announced {
        return run_raw(
            auth,
            &with(headers.to_vec(), "content-length", "0"),
            body,
            now,
        );
    }
    run_raw(auth, headers, body, now)
}

fn run_raw(
    auth: &Authenticator,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    now: u64,
) -> Result<Authenticated, String> {
    let view = RequestView {
        method: "POST",
        scheme: "https",
        authority: HOST,
        path: PATH,
        headers,
        body,
        peer_certificate: None,
    };
    auth.authenticate(&view, now)
        .map_err(|e| e.code().to_owned())
}

fn spec(nonce: &str) -> SignatureSpec<'_> {
    SignatureSpec {
        nonce,
        created: NOW,
        audience: AUDIENCE,
        cover: &[],
    }
}

/// `headers` plus a WIT for `agent-a` and a signature over all of them.
fn signed(seed: u8, headers: &[(&str, &str)], spec: &SignatureSpec<'_>) -> Vec<(String, String)> {
    let pop = pop_key(seed);
    let w = wit("agent-a", &pop);
    let mut all: Vec<(&str, &str)> = headers.to_vec();
    all.push(("workload-identity-token", &w));
    let (input, signature) = http_signature("POST", HOST, PATH, &all, &pop, spec);
    let mut out: Vec<(String, String)> = all
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    out.push(("signature-input".into(), input));
    out.push(("signature".into(), signature));
    out
}

fn with(mut headers: Vec<(String, String)>, name: &str, value: &str) -> Vec<(String, String)> {
    headers.push((name.to_owned(), value.to_owned()));
    headers
}

fn replace(mut headers: Vec<(String, String)>, name: &str, value: &str) -> Vec<(String, String)> {
    for (n, v) in &mut headers {
        if n == name {
            value.clone_into(v);
        }
    }
    headers
}

#[test]
fn a_signed_request_authenticates_the_workload() {
    let auth = authenticator();
    let ok = run(&auth, &signed(1, &[], &spec("n1")), None, NOW).unwrap();
    assert_eq!(ok.caller, "spiffe://td.example/agent-a");
    assert_eq!(ok.method, Method::WitHttpSig);
    assert!(ok.user.is_none());
    assert_eq!(
        ok.proof_key.unwrap().to_raw_bytes(),
        pop_key(1).verifying_key().to_raw_bytes()
    );
}

#[test]
fn the_body_must_match_a_covered_digest() {
    let auth = authenticator();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
    let digest = content_digest(body);
    let headers = signed(1, &[("content-digest", &digest)], &spec("d1"));
    run(&auth, &headers, Some(body), NOW).unwrap();

    let headers = signed(1, &[("content-digest", &digest)], &spec("d2"));
    assert_eq!(
        run(&auth, &headers, Some(b"{}"), NOW).unwrap_err(),
        "httpsig.invalid",
        "another body"
    );
    let headers = signed(1, &[("content-digest", &digest)], &spec("d3"));
    assert_eq!(
        run(&auth, &headers, None, NOW).unwrap_err(),
        "httpsig.invalid",
        "body not sent by the proxy"
    );
    let headers = with(
        signed(1, &[("content-digest", &digest)], &spec("d4")),
        "x-envoy-auth-partial-body",
        "true",
    );
    assert_eq!(
        run(&auth, &headers, Some(body), NOW).unwrap_err(),
        "httpsig.invalid",
        "partial body"
    );

    // An empty body with the digest of an empty body is fine without one.
    let empty = content_digest(b"");
    let headers = signed(1, &[("content-digest", &empty)], &spec("d5"));
    run(&auth, &headers, None, NOW).unwrap();

    // A body the signature does not cover through Content-Digest is refused,
    // whether the proxy sent it or only Content-Length or chunking announces it.
    let headers = signed(1, &[], &spec("d6"));
    assert_eq!(
        run(&auth, &headers, Some(body), NOW).unwrap_err(),
        "httpsig.invalid",
        "uncovered body"
    );
    let headers = with(signed(1, &[], &spec("d7")), "content-length", "42");
    assert_eq!(
        run(&auth, &headers, None, NOW).unwrap_err(),
        "httpsig.invalid",
        "announced body"
    );
    let headers = with(signed(1, &[], &spec("d8")), "transfer-encoding", "chunked");
    assert_eq!(
        run(&auth, &headers, None, NOW).unwrap_err(),
        "httpsig.invalid",
        "chunked body"
    );
    // A POST with no length header at all (HTTP/2) is assumed to carry one.
    let headers = signed(1, &[], &spec("d9"));
    assert_eq!(
        run_raw(&auth, &headers, None, NOW).unwrap_err(),
        "httpsig.invalid",
        "unannounced body"
    );
}

#[test]
fn a_user_token_must_be_covered() {
    let auth = authenticator();
    let at = access_token("alice", "agent-a", "files.read", AUDIENCE, NOW + 300);
    let ok = run(
        &auth,
        &signed(
            1,
            &[("x-user-token", &at)],
            &SignatureSpec {
                cover: &["x-user-token"],
                ..spec("u1")
            },
        ),
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(ok.user.unwrap().subject, "alice");

    let uncovered = with(signed(1, &[], &spec("u2")), "x-user-token", &at);
    assert_eq!(
        run(&auth, &uncovered, None, NOW).unwrap_err(),
        "httpsig.invalid"
    );
}

/// A rejection case: name, headers, path, time and expected detail.
type Case<'a> = (&'a str, Vec<(String, String)>, &'a str, u64, &'a str);

/// The code and the detail of a rejection.
fn failure(auth: &Authenticator, headers: &[(String, String)], path: &str, now: u64) -> String {
    let headers = &with(headers.to_vec(), "content-length", "0");
    let view = RequestView {
        method: "POST",
        scheme: "https",
        authority: HOST,
        path,
        headers,
        body: None,
        peer_certificate: None,
    };
    let err = auth.authenticate(&view, now).unwrap_err();
    format!("{} {err}", err.code())
}

#[test]
fn rejections_do_not_say_which_check_failed() {
    let auth = authenticator();
    let pop = pop_key(1);

    let replayed = signed(1, &[], &spec("r1"));
    run(&auth, &replayed, None, NOW).unwrap();

    let custom = |params: &SignatureParams, cover_wit: bool, nonce: Option<&str>| {
        let w = wit("agent-a", &pop);
        let request = signature_request("POST", HOST, PATH, &[("workload-identity-token", &w)]);
        let mut components = wimsey_httpsig::request_components(&request);
        if !cover_wit {
            components.pop();
        }
        let mut params = params.clone();
        params.nonce = nonce.map(ToOwned::to_owned);
        let s = wimsey_httpsig::sign(&request, &components, &params, "wimse", &pop).unwrap();
        vec![
            ("workload-identity-token".to_owned(), w),
            ("signature-input".to_owned(), s.signature_input),
            ("signature".to_owned(), s.signature),
        ]
    };
    let profile = SignatureParams {
        created: Some(NOW),
        expires: Some(NOW + 60),
        tag: Some(WIMSE_TAG.to_owned()),
        wimse_aud: Some(AUDIENCE.to_owned()),
        ..SignatureParams::default()
    };
    run(&auth, &custom(&profile, true, Some("c0")), None, NOW).unwrap();

    let foreign = {
        let w = wit_for("spiffe://other.example/agent-x", &pop);
        let (input, signature) = http_signature(
            "POST",
            HOST,
            PATH,
            &[("workload-identity-token", &w)],
            &pop,
            &spec("f1"),
        );
        vec![
            ("workload-identity-token".to_owned(), w),
            ("signature-input".to_owned(), input),
            ("signature".to_owned(), signature),
        ]
    };
    let elsewhere = SignatureSpec {
        audience: "https://elsewhere.example/mcp",
        ..spec("a1")
    };
    let long = SignatureParams {
        expires: Some(NOW + 3600),
        ..profile.clone()
    };
    let keyid = SignatureParams {
        keyid: Some("k".into()),
        ..profile.clone()
    };

    let cases: Vec<Case<'_>> = vec![
        ("replayed nonce", replayed, PATH, NOW + 1, "replayed"),
        (
            "signed by another key",
            signed_by_other(),
            PATH,
            NOW,
            "verification failed",
        ),
        (
            "another audience",
            signed(1, &[], &elsewhere),
            PATH,
            NOW,
            "audience",
        ),
        (
            "expired",
            signed(1, &[], &spec("e1")),
            PATH,
            NOW + 120,
            "expired",
        ),
        (
            "created in the future",
            signed(1, &[], &spec("e2")),
            PATH,
            NOW - 120,
            "future",
        ),
        (
            "window too long",
            custom(&long, true, Some("w1")),
            PATH,
            NOW,
            "lifetime",
        ),
        ("no nonce", custom(&profile, true, None), PATH, NOW, "nonce"),
        (
            "keyid present",
            custom(&keyid, true, Some("k1")),
            PATH,
            NOW,
            "keyid",
        ),
        (
            "WIT not covered",
            custom(&profile, false, Some("wc")),
            PATH,
            NOW,
            "workload-identity-token",
        ),
        (
            "foreign trust domain",
            foreign,
            PATH,
            NOW,
            "untrusted trust domain",
        ),
        (
            "another query",
            signed(1, &[], &spec("q1")),
            "/mcp?session=2",
            NOW,
            "verification failed",
        ),
    ];
    for (name, headers, path, now, detail) in cases {
        let failure = failure(&auth, &headers, path, now);
        assert!(failure.starts_with("httpsig.invalid "), "{name}: {failure}");
        assert!(failure.contains(detail), "{name}: {failure}");
    }
}

fn signed_by_other() -> Vec<(String, String)> {
    let w = wit("agent-a", &pop_key(1));
    let (input, signature) = http_signature(
        "POST",
        HOST,
        PATH,
        &[("workload-identity-token", &w)],
        &pop_key(2),
        &spec("o1"),
    );
    vec![
        ("workload-identity-token".to_owned(), w),
        ("signature-input".to_owned(), input),
        ("signature".to_owned(), signature),
    ]
}

#[test]
fn another_signature_from_an_intermediary_is_ignored() {
    let auth = authenticator();
    let headers = signed(1, &[], &spec("i1"));
    let headers = with(
        with(
            headers,
            "signature-input",
            "proxy=(\"@method\");created=1800000000",
        ),
        "signature",
        "proxy=:AAAA:",
    );
    run(&auth, &headers, None, NOW).unwrap();
}

#[test]
fn credential_shapes_that_are_refused() {
    let auth = authenticator();
    let at = access_token("alice", "agent-a", "files.read", AUDIENCE, NOW + 300);
    let bearer = with(
        signed(1, &[], &spec("b1")),
        "authorization",
        &format!("Bearer {at}"),
    );
    assert_eq!(
        run(&auth, &bearer, None, NOW).unwrap_err(),
        "credential.ambiguous"
    );

    let huge = replace(
        signed(1, &[], &spec("h1")),
        "signature-input",
        &"a".repeat(20_000),
    );
    assert_eq!(
        run(&auth, &huge, None, NOW).unwrap_err(),
        "credential.too_large"
    );

    let unsigned = vec![
        (
            "workload-identity-token".to_owned(),
            wit("agent-a", &pop_key(1)),
        ),
        ("signature".to_owned(), "wimse=:AAAA:".to_owned()),
    ];
    assert_eq!(run(&auth, &unsigned, None, NOW).unwrap_err(), "wpt.missing");
}

#[test]
fn a_nonce_stays_recorded_through_the_last_accepted_second() {
    let auth = authenticator();
    let headers = signed(1, &[], &spec("last"));
    // `expires` is NOW + 60 and the leeway 30, so NOW + 90 is the last second
    // the signature is accepted in.
    run(&auth, &headers, None, NOW + 90).unwrap();
    for _ in 0..3 {
        assert_eq!(
            run(&auth, &headers, None, NOW + 90).unwrap_err(),
            "httpsig.invalid"
        );
    }
    assert_eq!(
        run(&auth, &headers, None, NOW + 91).unwrap_err(),
        "httpsig.invalid"
    );
}
