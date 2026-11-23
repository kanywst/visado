//! A delegation-chain token (an asor Delegation Token or an AAT) is never an
//! access token, even when its issuer and key are also a trusted OAuth
//! issuer's: on the access-token path it would skip the chain checks.

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use visado_credentials::{Authenticated, Authenticator, OAuthIssuer, RequestView};
use visado_testkit::{
    NOW, OAUTH_ISSUER, dpop_proof, oauth_jwks, oauth_key, pop_key, signed_access_token,
};
use wimsey_jose::SigningKey;

const AUDIENCE: &str = "https://tools.td.example/mcp";
const HTU: &str = "https://tools.td.example/mcp";

fn authenticator() -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new().with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks))
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
        path: "/mcp",
        headers: &headers,
        body: None,
        peer_certificate: None,
    };
    auth.authenticate(&view, NOW)
        .map_err(|e| e.code().to_owned())
}

fn holder() -> SigningKey {
    pop_key(7)
}

/// The claims of a root asor Delegation Token that the OAuth issuer's key
/// signed, with a top-level `scope` and the leaf holder's `cnf.jkt`.
fn delegation_claims() -> Value {
    json!({
        "iss": OAUTH_ISSUER, "sub": "user:alice", "client_id": "agent-a", "aud": AUDIENCE,
        "scope": "files.read", "iat": NOW - 5, "exp": NOW + 300, "jti": "dt-1",
        "del_depth": 0, "del_max_depth": 2,
        "cnf": { "jkt": visado_chain::jose::key_thumbprint(&holder().verifying_key()) },
        "authorization_details": [
            { "type": "agent_delegation", "scopes": ["files.read"], "constraints": {} }
        ],
    })
}

/// Sends `token` as `Authorization: DPoP` with a fresh proof by the holder.
fn send_dpop(auth: &Authenticator, token: &str) -> Result<Authenticated, String> {
    static JTI: AtomicUsize = AtomicUsize::new(0);
    let jti = format!("p-{}", JTI.fetch_add(1, Ordering::Relaxed));
    let proof = dpop_proof(&holder(), "POST", HTU, token, &jti, NOW);
    run(
        auth,
        &[
            ("authorization", &format!("DPoP {token}")),
            ("dpop", &proof),
        ],
    )
}

/// Signs `claims` with the OAuth issuer's key under `typ`.
fn signed_with_typ(typ: &str, claims: &Value) -> String {
    let header = json!({ "typ": typ, "alg": "EdDSA", "kid": "idp-1" });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let input = format!("{h}.{c}");
    let sig = URL_SAFE_NO_PAD.encode(oauth_key().sign(input.as_bytes()));
    format!("{input}.{sig}")
}

#[test]
fn a_delegation_token_with_a_leaf_proof_is_not_an_access_token() {
    let auth = authenticator();
    let dt = signed_access_token(&delegation_claims());
    assert_eq!(send_dpop(&auth, &dt).unwrap_err(), "token.delegation");
}

#[test]
fn each_chain_claim_marks_a_delegation_token() {
    let auth = authenticator();
    let plain = |claims: &mut Value| {
        let object = claims.as_object_mut().unwrap();
        for claim in ["del_depth", "del_max_depth", "authorization_details"] {
            object.remove(claim);
        }
    };
    // Without any chain claim the same token is an ordinary DPoP-bound one.
    let mut claims = delegation_claims();
    plain(&mut claims);
    let ok = send_dpop(&auth, &signed_access_token(&claims)).unwrap();
    assert_eq!(ok.caller, "agent-a");

    for (claim, value) in [
        ("del_depth", json!(1)),
        ("del_max_depth", json!(2)),
        ("par_hash", json!("abc")),
        (
            "status",
            json!({ "status_list": { "idx": 0, "uri": "https://s" } }),
        ),
        ("aat_id", json!("x")),
        ("aat_hash", json!("x")),
        ("aat_tool", json!("x")),
        ("aat_aud", json!("x")),
        ("hta", json!({})),
        (
            "authorization_details",
            json!([{ "type": "agent_delegation" }]),
        ),
        (
            "authorization_details",
            json!([{ "type": "other" }, { "type": "attenuating_agent_token" }]),
        ),
    ] {
        let mut claims = delegation_claims();
        plain(&mut claims);
        claims[claim] = value;
        let token = signed_access_token(&claims);
        assert_eq!(
            send_dpop(&auth, &token).unwrap_err(),
            "token.delegation",
            "{claim}"
        );
    }

    // authorization_details of another type is not a chain.
    let mut claims = delegation_claims();
    plain(&mut claims);
    claims["authorization_details"] = json!([{ "type": "payment_initiation" }]);
    send_dpop(&auth, &signed_access_token(&claims)).unwrap();
}

#[test]
fn a_delegation_token_is_refused_as_a_bearer_token_too() {
    let auth = authenticator();
    let mut claims = delegation_claims();
    claims.as_object_mut().unwrap().remove("cnf");
    let dt = signed_access_token(&claims);
    assert_eq!(
        run(&auth, &[("authorization", &format!("Bearer {dt}"))]).unwrap_err(),
        "token.delegation"
    );
}

#[test]
fn an_aat_typ_is_not_an_access_token() {
    let auth = authenticator();
    let mut claims = delegation_claims();
    let object = claims.as_object_mut().unwrap();
    for claim in ["del_depth", "del_max_depth", "authorization_details"] {
        object.remove(claim);
    }
    for typ in ["aat+jwt", "application/aat+jwt", "AAT+JWT", "aat-pop+jwt"] {
        let token = signed_with_typ(typ, &claims);
        assert_eq!(
            send_dpop(&auth, &token).unwrap_err(),
            "token.delegation",
            "{typ}"
        );
    }
    send_dpop(&auth, &signed_with_typ("at+jwt", &claims)).unwrap();
}
