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

/// A JWKS key is used only for what it says it is for (RFC 7517 §4.2-4.4):
/// a `use` other than `sig`, `key_ops` without `verify`, or an `alg` other
/// than the token's keeps it from verifying the token.
#[test]
fn a_key_verifies_only_what_it_is_published_for() {
    use visado_testkit::{OAUTH_ISSUER, access_token, oauth_jwks};
    let token = access_token("alice", "c-1", "files.read", AUDIENCE, NOW + 300);
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut jwks = oauth_jwks();
        edit(&mut jwks["keys"][0]);
        let jwks = serde_json::from_value(jwks).unwrap();
        let auth =
            Authenticator::new().with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks));
        run(&auth, &[("authorization", format!("Bearer {token}"))])
    };
    assert_eq!(with(&|_| {}), Ok(Method::Bearer));
    assert_eq!(with(&|k| k["alg"] = json!("EdDSA")), Ok(Method::Bearer));
    assert_eq!(
        with(&|k| {
            k.as_object_mut().unwrap().remove("use");
            k["key_ops"] = json!(["verify"]);
        }),
        Ok(Method::Bearer)
    );
    for (what, edit) in [
        (
            "use enc",
            &(|k: &mut Value| k["use"] = json!("enc")) as &dyn Fn(&mut Value),
        ),
        ("use other", &|k: &mut Value| k["use"] = json!("wit-svid")),
        ("alg", &|k: &mut Value| k["alg"] = json!("ES256")),
        ("key_ops", &|k: &mut Value| {
            k.as_object_mut().unwrap().remove("use");
            k["key_ops"] = json!(["encrypt"]);
        }),
    ] {
        assert_eq!(with(edit), Err("token.invalid".to_owned()), "{what}");
    }
}

/// Without a `kid`, a token verifies only when the set holds exactly one key
/// in total, and that key passes the `use`, `key_ops` and `alg` checks. A
/// second key, even one for encryption, refuses it.
#[test]
fn without_a_kid_the_set_must_hold_one_key() {
    use visado_testkit::{OAUTH_ISSUER, oauth_jwks};
    let claims = json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "c-1",
        "iat": NOW - 5, "exp": NOW + 300,
    });
    let header = json!({ "typ": "at+jwt", "alg": "EdDSA" });
    let token = visado_testkit::sign_dpop_proof(&header, &claims, &visado_testkit::oauth_key());
    let with = |jwks: Value| {
        let jwks = serde_json::from_value(jwks).unwrap();
        let auth =
            Authenticator::new().with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks));
        run(&auth, &[("authorization", format!("Bearer {token}"))])
    };
    assert_eq!(with(oauth_jwks()), Ok(Method::Bearer));

    // The one key must still be a signing key for this alg.
    let mut enc_only = oauth_jwks();
    enc_only["keys"][0]["use"] = json!("enc");
    assert_eq!(with(enc_only), Err("token.invalid".to_owned()));
    let mut other_alg = oauth_jwks();
    other_alg["keys"][0]["alg"] = json!("ES256");
    assert_eq!(with(other_alg), Err("token.invalid".to_owned()));

    // A second key, for encryption or for signing, refuses a kid-less token.
    for usage in ["enc", "sig"] {
        let mut jwks = oauth_jwks();
        let mut second = jwks["keys"][0].clone();
        second["use"] = json!(usage);
        second["kid"] = json!("k-2");
        jwks["keys"].as_array_mut().unwrap().push(second);
        assert_eq!(with(jwks), Err("token.invalid".to_owned()), "{usage}");
    }
}
