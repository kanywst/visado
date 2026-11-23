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

/// Without a `kid`, the one key that may verify the token is used, even
/// when the set also holds an encryption key.
#[test]
fn without_a_kid_only_signing_keys_count() {
    use visado_testkit::{OAUTH_ISSUER, oauth_jwks};
    let claims = json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "c-1",
        "iat": NOW - 5, "exp": NOW + 300,
    });
    let header = json!({ "typ": "at+jwt", "alg": "EdDSA" });
    let token = visado_testkit::sign_dpop_proof(&header, &claims, &visado_testkit::oauth_key());
    let mut jwks = oauth_jwks();
    let mut enc = jwks["keys"][0].clone();
    enc["use"] = json!("enc");
    enc["kid"] = json!("enc-1");
    jwks["keys"].as_array_mut().unwrap().push(enc);
    let jwks = serde_json::from_value(jwks).unwrap();
    let auth =
        Authenticator::new().with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks));
    assert_eq!(
        run(&auth, &[("authorization", format!("Bearer {token}"))]),
        Ok(Method::Bearer)
    );
}
