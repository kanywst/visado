//! OAuth access tokens signed `RS256` and `ES256`, as bearer tokens and
//! DPoP-bound, besides the `EdDSA` tokens of the other tests.

use serde_json::{Value, json};
use visado_chain::jose::key_thumbprint;
use visado_credentials::{Authenticator, Method, OAuthIssuer, RequestView};
use visado_testkit::{NOW, dpop_proof, jwt_bundle, pop_key, signed_jwt_svid};

const ISSUER: &str = "https://idp.example";
const AUDIENCE: &str = "https://tools.td.example";

/// The testkit's `ES256` ("svid-es") and `RS256` ("svid-rs") keys as an
/// OAuth issuer's JWKS.
fn authenticator() -> Authenticator {
    let keys: Vec<Value> = jwt_bundle()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["use"] == "jwt-svid")
        .map(|k| {
            let mut k = k.clone();
            k["use"] = json!("sig");
            k
        })
        .collect();
    let jwks = serde_json::from_value(json!({ "keys": keys })).unwrap();
    Authenticator::new().with_oauth_issuer(OAuthIssuer::new(ISSUER, AUDIENCE, jwks))
}

fn token(alg: &str, kid: &str, extra: &Value) -> String {
    let mut claims = json!({
        "iss": ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "c-1",
        "scope": "files.read", "iat": NOW - 5, "exp": NOW + 300,
    });
    for (k, v) in extra.as_object().unwrap() {
        claims[k] = v.clone();
    }
    signed_jwt_svid(&json!({ "alg": alg, "kid": kid, "typ": "at+jwt" }), &claims)
}

fn run(auth: &Authenticator, headers: &[(&str, String)]) -> Result<Method, String> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.clone()))
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
        .map(|a| a.method)
        .map_err(|e| e.code().to_owned())
}

#[test]
fn rs256_and_es256_bearer_tokens_are_accepted() {
    let auth = authenticator();
    for (alg, kid) in [("RS256", "svid-rs"), ("ES256", "svid-es")] {
        let at = token(alg, kid, &json!({}));
        assert_eq!(
            run(&auth, &[("authorization", format!("Bearer {at}"))]),
            Ok(Method::Bearer),
            "{alg}"
        );
    }
}

#[test]
fn the_alg_must_fit_the_key() {
    let auth = authenticator();
    // An RS256 signature under the ES256 key's kid.
    let at = token("RS256", "svid-es", &json!({}));
    assert_eq!(
        run(&auth, &[("authorization", format!("Bearer {at}"))]),
        Err("token.invalid".to_owned())
    );
}

#[test]
fn rs256_and_es256_tokens_can_be_dpop_bound() {
    let auth = authenticator();
    let holder = pop_key(5);
    let jkt = key_thumbprint(&holder.verifying_key());
    for (i, (alg, kid)) in [("RS256", "svid-rs"), ("ES256", "svid-es")]
        .into_iter()
        .enumerate()
    {
        let at = token(alg, kid, &json!({ "cnf": { "jkt": jkt } }));
        let proof = dpop_proof(
            &holder,
            "GET",
            "https://tools.td.example/mcp",
            &at,
            &format!("p-{i}"),
            NOW,
        );
        assert_eq!(
            run(
                &auth,
                &[("authorization", format!("DPoP {at}")), ("dpop", proof)]
            ),
            Ok(Method::OAuthDpop),
            "{alg}"
        );
        assert_eq!(
            run(&auth, &[("authorization", format!("Bearer {at}"))]),
            Err("token.dpop_bound".to_owned()),
            "{alg}"
        );
    }
}
