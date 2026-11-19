//! DPoP-bound access tokens (RFC 9449) as `Authorization: DPoP`.

use serde_json::{Value, json};
use visado_chain::jose::key_thumbprint as jwk_thumbprint;
use visado_credentials::{
    Authenticated, Authenticator, Method, OAuthIssuer, RequestView, WitIssuer,
};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, dpop_access_token, dpop_claims, dpop_jwk,
    dpop_proof, oauth_jwks, pop_key, sign_dpop_proof, signed_access_token, wit,
    wit_issuer_verifying_key, wpt,
};
use wimsey_jose::SigningKey;

const AUDIENCE: &str = "https://tools.td.example/mcp";
/// The request URI as the proof names it: no query.
const HTU: &str = "https://tools.td.example/mcp";

fn authenticator() -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks))
}

fn run_as(
    auth: &Authenticator,
    method: &str,
    headers: &[(&str, &str)],
) -> Result<Authenticated, String> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let view = RequestView {
        method,
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

fn run(auth: &Authenticator, headers: &[(&str, &str)]) -> Result<Authenticated, String> {
    run_as(auth, "POST", headers)
}

fn holder() -> SigningKey {
    pop_key(7)
}

fn token() -> String {
    dpop_access_token(
        "alice",
        "mcp-client",
        "files.read",
        AUDIENCE,
        NOW + 300,
        &holder(),
    )
}

/// Sends `token` as `Authorization: DPoP` with `proof`.
fn send(auth: &Authenticator, token: &str, proof: &str) -> Result<Authenticated, String> {
    run(
        auth,
        &[("authorization", &format!("DPoP {token}")), ("dpop", proof)],
    )
}

/// A proof by `key` with `alg`, with the claims changed by `edit`.
fn proof_with(key: &SigningKey, alg: &str, token: &str, edit: impl FnOnce(&mut Value)) -> String {
    let header = json!({ "alg": alg, "typ": "dpop+jwt", "jwk": dpop_jwk(key) });
    let mut claims = dpop_claims("POST", HTU, token, "p-1", NOW);
    edit(&mut claims);
    sign_dpop_proof(&header, &claims, key)
}

#[test]
fn a_dpop_bound_token_authenticates_its_client() {
    let auth = authenticator();
    let at = token();
    let ok = send(
        &auth,
        &at,
        &dpop_proof(&holder(), "POST", HTU, &at, "p-1", NOW),
    )
    .unwrap();
    assert_eq!(ok.caller, "mcp-client");
    assert_eq!(ok.method, Method::OAuthDpop);
    assert_eq!(ok.user.unwrap().subject, "alice");
    let key = ok.proof_key.expect("the proof key is the caller's key");
    assert_eq!(
        jwk_thumbprint(&key),
        jwk_thumbprint(&holder().verifying_key())
    );
}

#[test]
fn eddsa_and_es256_proofs_are_accepted() {
    let auth = authenticator();
    let at = token();
    let eddsa = proof_with(&holder(), "EdDSA", &at, |_| {});
    assert!(send(&auth, &at, &eddsa).is_ok());

    let p256 = SigningKey::from_p256_scalar(&[7; 32]).unwrap();
    let at = dpop_access_token(
        "alice",
        "mcp-client",
        "files.read",
        AUDIENCE,
        NOW + 300,
        &p256,
    );
    let es256 = proof_with(&p256, "ES256", &at, |_| {});
    assert!(send(&auth, &at, &es256).is_ok());
    // The alg must fit the key.
    let mislabeled = proof_with(&p256, "Ed25519", &at, |c| c["jti"] = json!("p-2"));
    assert_eq!(send(&auth, &at, &mislabeled).unwrap_err(), "dpop.invalid");
}

#[test]
fn htu_ignores_query_and_normalizes_scheme_host_and_port() {
    let auth = authenticator();
    let at = token();
    for (i, htu) in [
        "https://tools.td.example/mcp?other=2",
        "HTTPS://Tools.TD.example:443/mcp",
        "https://tools.td.example/mcp#frag",
    ]
    .iter()
    .enumerate()
    {
        let proof = proof_with(&holder(), "Ed25519", &at, |c| {
            c["htu"] = json!(htu);
            c["jti"] = json!(format!("htu-{i}"));
        });
        assert!(send(&auth, &at, &proof).is_ok(), "{htu}");
    }
}

#[test]
fn every_proof_check_is_enforced() {
    let auth = authenticator();
    let at = token();
    let key = holder();
    let cases: Vec<(&str, String)> = vec![
        ("wrong htm", dpop_proof(&key, "GET", HTU, &at, "p-1", NOW)),
        (
            "wrong htu path",
            dpop_proof(
                &key,
                "POST",
                "https://tools.td.example/other",
                &at,
                "p-1",
                NOW,
            ),
        ),
        (
            "wrong htu host",
            dpop_proof(&key, "POST", "https://evil.example/mcp", &at, "p-1", NOW),
        ),
        (
            "wrong htu scheme",
            dpop_proof(&key, "POST", "http://tools.td.example/mcp", &at, "p-1", NOW),
        ),
        (
            "stale iat",
            dpop_proof(&key, "POST", HTU, &at, "p-1", NOW - 61),
        ),
        (
            "future iat",
            dpop_proof(&key, "POST", HTU, &at, "p-1", NOW + 61),
        ),
        (
            "ath over another token",
            dpop_proof(&key, "POST", HTU, "other", "p-1", NOW),
        ),
        (
            "no ath",
            proof_with(&key, "Ed25519", &at, |c| {
                c.as_object_mut().unwrap().remove("ath");
            }),
        ),
        (
            "no jti",
            proof_with(&key, "Ed25519", &at, |c| {
                c.as_object_mut().unwrap().remove("jti");
            }),
        ),
        (
            "empty jti",
            proof_with(&key, "Ed25519", &at, |c| c["jti"] = json!("")),
        ),
        (
            "long jti",
            proof_with(&key, "Ed25519", &at, |c| c["jti"] = json!("j".repeat(257))),
        ),
        (
            "string iat",
            proof_with(&key, "Ed25519", &at, |c| c["iat"] = json!(NOW.to_string())),
        ),
        ("not a JWS", "abc.def".to_owned()),
    ];
    for (name, proof) in cases {
        assert_eq!(
            send(&auth, &at, &proof).unwrap_err(),
            "dpop.invalid",
            "{name}"
        );
    }
    // The window holds at its edge.
    assert!(
        send(
            &auth,
            &at,
            &dpop_proof(&key, "POST", HTU, &at, "edge", NOW - 60)
        )
        .is_ok()
    );
}

#[test]
fn the_header_must_be_a_public_asymmetric_dpop_key() {
    let auth = authenticator();
    let at = token();
    let key = holder();
    let claims = dpop_claims("POST", HTU, &at, "p-1", NOW);
    let jwk = dpop_jwk(&key);
    let mut private = jwk.clone();
    private["d"] = json!("AAAA");
    let header = |alg: &str, typ: &str, jwk: &Value| json!({ "alg": alg, "typ": typ, "jwk": jwk });
    let cases = [
        (
            "private key in jwk",
            header("Ed25519", "dpop+jwt", &private),
        ),
        ("wrong typ", header("Ed25519", "JWT", &jwk)),
        ("HS256", header("HS256", "dpop+jwt", &jwk)),
        (
            "symmetric jwk",
            header(
                "HS256",
                "dpop+jwt",
                &json!({ "kty": "oct", "k": "c2VjcmV0" }),
            ),
        ),
        ("RS256", header("RS256", "dpop+jwt", &jwk)),
        ("none", header("none", "dpop+jwt", &jwk)),
        (
            "crit",
            json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": jwk, "crit": ["x"] }),
        ),
        ("no jwk", json!({ "alg": "Ed25519", "typ": "dpop+jwt" })),
    ];
    for (name, header) in cases {
        let proof = sign_dpop_proof(&header, &claims, &key);
        assert_eq!(
            send(&auth, &at, &proof).unwrap_err(),
            "dpop.invalid",
            "{name}"
        );
    }

    // The header names the holder's key but another key signed it.
    let forged = sign_dpop_proof(&header("Ed25519", "dpop+jwt", &jwk), &claims, &pop_key(8));
    assert_eq!(send(&auth, &at, &forged).unwrap_err(), "dpop.invalid");
}

#[test]
fn the_token_must_be_bound_to_the_proof_key() {
    let auth = authenticator();
    let at = token();
    // A valid proof by another key.
    let other = dpop_proof(&pop_key(8), "POST", HTU, &at, "p-1", NOW);
    assert_eq!(send(&auth, &at, &other).unwrap_err(), "dpop.binding");

    // A bearer token sent with the DPoP scheme.
    let bearer = access_token("alice", "mcp-client", "files.read", AUDIENCE, NOW + 300);
    let proof = dpop_proof(&holder(), "POST", HTU, &bearer, "p-2", NOW);
    assert_eq!(send(&auth, &bearer, &proof).unwrap_err(), "dpop.binding");

    // Other confirmation members cannot be satisfied with DPoP.
    let jkt = jwk_thumbprint(&holder().verifying_key());
    let mixed = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "c1",
        "exp": NOW + 300, "cnf": { "jkt": jkt, "x5t#S256": "abc" },
    }));
    let proof = dpop_proof(&holder(), "POST", HTU, &mixed, "p-3", NOW);
    assert_eq!(
        send(&auth, &mixed, &proof).unwrap_err(),
        "token.sender_constrained"
    );
}

#[test]
fn the_token_is_verified_as_usual() {
    let auth = authenticator();
    let expired = dpop_access_token("alice", "c", "s", AUDIENCE, NOW - 60, &holder());
    let proof = dpop_proof(&holder(), "POST", HTU, &expired, "p-1", NOW);
    assert_eq!(send(&auth, &expired, &proof).unwrap_err(), "token.expired");

    let jkt = jwk_thumbprint(&holder().verifying_key());
    let no_client = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "exp": NOW + 300,
        "cnf": { "jkt": jkt },
    }));
    let proof = dpop_proof(&holder(), "POST", HTU, &no_client, "p-2", NOW);
    assert_eq!(
        send(&auth, &no_client, &proof).unwrap_err(),
        "token.no_client"
    );

    assert_eq!(
        run(&auth, &[("authorization", "DPoP "), ("dpop", "x")]).unwrap_err(),
        "credential.missing"
    );
}

#[test]
fn a_proof_is_accepted_once_per_key() {
    let auth = authenticator();
    let at = token();
    let proof = dpop_proof(&holder(), "POST", HTU, &at, "once", NOW);
    assert!(send(&auth, &at, &proof).is_ok());
    assert_eq!(send(&auth, &at, &proof).unwrap_err(), "dpop.replay");

    // The same jti from another key is another proof.
    let other = pop_key(9);
    let at = dpop_access_token(
        "bob",
        "mcp-client",
        "files.read",
        AUDIENCE,
        NOW + 300,
        &other,
    );
    let proof = dpop_proof(&other, "POST", HTU, &at, "once", NOW);
    assert!(send(&auth, &at, &proof).is_ok());
}

#[test]
fn exactly_one_proof_is_required() {
    let auth = authenticator();
    let at = token();
    let a = dpop_proof(&holder(), "POST", HTU, &at, "a", NOW);
    let b = dpop_proof(&holder(), "POST", HTU, &at, "b", NOW);
    let scheme = format!("DPoP {at}");
    assert_eq!(
        run(&auth, &[("authorization", &scheme)]).unwrap_err(),
        "dpop.invalid"
    );
    assert_eq!(
        run(
            &auth,
            &[("authorization", &scheme), ("dpop", &a), ("dpop", &b)]
        )
        .unwrap_err(),
        "dpop.invalid"
    );
    // Two proofs a proxy joined into one line.
    assert_eq!(
        run(
            &auth,
            &[("authorization", &scheme), ("dpop", &format!("{a}, {b}"))]
        )
        .unwrap_err(),
        "dpop.invalid"
    );
    assert_eq!(
        run(
            &auth,
            &[("authorization", &scheme), ("dpop", &"a".repeat(17 * 1024))]
        )
        .unwrap_err(),
        "credential.too_large"
    );
}

#[test]
fn a_bound_token_without_its_proof_is_refused() {
    let auth = authenticator();
    let at = token();
    // RFC 9449 §7.1: downgrade to Bearer, with or without a proof alongside.
    let proof = dpop_proof(&holder(), "POST", HTU, &at, "p-1", NOW);
    for headers in [
        vec![("authorization", format!("Bearer {at}"))],
        vec![("authorization", format!("Bearer {at}")), ("dpop", proof)],
    ] {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        assert_eq!(run(&auth, &headers).unwrap_err(), "token.dpop_bound");
    }

    // As a user token next to a workload's own proof.
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let p = wpt(&w, &pop, AUDIENCE, "j1", None, Some(("x-user-token", &at)));
    assert_eq!(
        run(
            &auth,
            &[
                ("workload-identity-token", &w),
                ("authorization", &format!("WPT {p}")),
                ("x-user-token", &at),
            ],
        )
        .unwrap_err(),
        "token.dpop_bound"
    );
}

#[test]
fn the_iat_window_is_configurable() {
    let auth = authenticator().with_dpop_iat_window(5);
    let at = token();
    let old = dpop_proof(&holder(), "POST", HTU, &at, "p-1", NOW - 10);
    assert_eq!(send(&auth, &at, &old).unwrap_err(), "dpop.invalid");
    let fresh = dpop_proof(&holder(), "POST", HTU, &at, "p-2", NOW - 5);
    assert!(send(&auth, &at, &fresh).is_ok());
}

#[test]
fn htm_is_the_request_method() {
    let auth = authenticator();
    let at = token();
    let proof = dpop_proof(&holder(), "GET", HTU, &at, "p-1", NOW);
    let headers = [("authorization", format!("DPoP {at}")), ("dpop", proof)];
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert!(run_as(&auth, "GET", &headers).is_ok());
}
