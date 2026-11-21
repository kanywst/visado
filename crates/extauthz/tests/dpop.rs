//! The gate with OAuth clients presenting DPoP-bound access tokens
//! (RFC 9449).

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_aat::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, OAuthIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    AAT_ISSUER, NOW, OAUTH_ISSUER, TRUST_DOMAIN, aat_anchor_key, aat_pop, aat_root,
    dpop_access_token, dpop_claims, dpop_jwk, dpop_proof, oauth_jwks, pop_key, sign_dpop_proof,
    signed_access_token,
};
use visado_txn_token::{KeySet, Scope, TxnTokenClaims, Validation, verify};
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const AUDIENCE: &str = "https://tools.td.example";
const URI: &str = "https://tools.td.example/mcp";
const ALGS: &str = r#"algs="ES256 EdDSA Ed25519""#;

type Seen = Arc<Mutex<Option<EvaluationRequest>>>;

/// Allows everything and remembers the last request.
struct RecordingPdp(Seen);

impl Pdp for RecordingPdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        if let Ok(mut last) = self.0.lock() {
            *last = Some(request.clone());
        }
        Ok(Decision {
            allowed: true,
            context: None,
        })
    }
}

fn txn_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x51; 32])
}

fn gate() -> (Gate<RecordingPdp>, Seen) {
    let config = GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: txn_key(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::from(["mcp-client".to_owned()]),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: Some(Verifier::new(
            vec![TrustAnchor::new(
                AAT_ISSUER,
                aat_anchor_key().verifying_key(),
            )],
            vec![AUDIENCE.to_owned()],
        )),
        asor: None,
        act: Some(visado_chain_act::Verifier::new()),
        require_chain: false,
    };
    let authenticator = Authenticator::new().with_oauth_issuer(OAuthIssuer::new(
        OAUTH_ISSUER,
        AUDIENCE,
        serde_json::from_value(oauth_jwks()).unwrap(),
    ));
    let seen = Seen::default();
    (
        Gate::new(config, authenticator, RecordingPdp(seen.clone())),
        seen,
    )
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

fn request(headers: Vec<(&str, String)>, body: Option<&str>) -> CheckInput {
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers: headers
            .into_iter()
            .map(|(n, v)| (n.to_owned(), v))
            .collect(),
        body: body.map(|b| b.as_bytes().to_vec()),
        peer_certificate: None,
    }
}

/// `Authorization: DPoP <token>` with `proof`.
fn dpop_call(token: &str, proof: String) -> CheckInput {
    request(
        vec![("authorization", format!("DPoP {token}")), ("dpop", proof)],
        None,
    )
}

fn denied(outcome: &Outcome) -> (u16, &str, Option<&str>) {
    match outcome {
        Outcome::Deny {
            status,
            code,
            challenge,
            ..
        } => (*status, code.as_str(), challenge.as_deref()),
        Outcome::Allow { .. } => panic!("expected deny"),
    }
}

fn minted(outcome: &Outcome) -> TxnTokenClaims {
    let Outcome::Allow { set, .. } = outcome else {
        panic!("expected allow, got {outcome:?}")
    };
    let token = &set.iter().find(|(n, _)| n == "txn-token").unwrap().1;
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    verify(token, &keys, &Validation::new(TRUST_DOMAIN, NOW + 1))
        .unwrap()
        .claims
}

fn invalid_proof() -> String {
    format!(r#"DPoP error="invalid_dpop_proof", {ALGS}"#)
}

fn invalid_token() -> String {
    format!(r#"DPoP error="invalid_token", {ALGS}"#)
}

#[tokio::test]
async fn a_dpop_client_gets_a_transaction_token() {
    let (gate, seen) = gate();
    let at = token();
    let outcome = gate
        .check(
            &dpop_call(&at, dpop_proof(&holder(), "POST", URI, &at, "p-1", NOW)),
            NOW,
            "t1",
        )
        .await;
    let claims = minted(&outcome);
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.req_wl, "oauth-client:mcp-client");
    assert_eq!(claims.tctx.unwrap()["auth_method"], json!("oauth-dpop"));
    let pdp = seen.lock().unwrap().clone().unwrap();
    assert_eq!(pdp.subject.kind, "client");
    assert_eq!(pdp.context.unwrap()["auth_method"], json!("oauth-dpop"));
    let Outcome::Allow { remove, .. } = &outcome else {
        unreachable!()
    };
    for header in ["authorization", "dpop"] {
        assert!(remove.contains(&header.to_owned()), "{header} is removed");
    }
}

#[tokio::test]
async fn proof_failures_are_invalid_dpop_proof() {
    let (gate, _) = gate();
    let at = token();
    let key = holder();
    let jwk = dpop_jwk(&key);
    let mut private = jwk.clone();
    private["d"] = json!("AAAA");
    let claims = dpop_claims("POST", URI, &at, "p-x", NOW);
    let mut no_ath = claims.clone();
    no_ath.as_object_mut().unwrap().remove("ath");
    let header = |alg: &str, jwk: &Value| json!({ "alg": alg, "typ": "dpop+jwt", "jwk": jwk });

    let cases: Vec<(&str, String)> = vec![
        ("wrong htm", dpop_proof(&key, "PUT", URI, &at, "p-1", NOW)),
        (
            "wrong htu",
            dpop_proof(
                &key,
                "POST",
                "https://tools.td.example/admin",
                &at,
                "p-2",
                NOW,
            ),
        ),
        (
            "stale iat",
            dpop_proof(&key, "POST", URI, &at, "p-3", NOW - 120),
        ),
        (
            "wrong ath",
            dpop_proof(&key, "POST", URI, "another-token", "p-4", NOW),
        ),
        (
            "missing ath",
            sign_dpop_proof(&header("Ed25519", &jwk), &no_ath, &key),
        ),
        (
            "private key in jwk",
            sign_dpop_proof(&header("Ed25519", &private), &claims, &key),
        ),
        (
            "symmetric alg",
            sign_dpop_proof(
                &header("HS256", &json!({ "kty": "oct", "k": "c2VjcmV0" })),
                &claims,
                &key,
            ),
        ),
    ];
    for (name, proof) in cases {
        let outcome = gate.check(&dpop_call(&at, proof), NOW, "t").await;
        assert_eq!(
            denied(&outcome),
            (401, "dpop.invalid", Some(invalid_proof().as_str())),
            "{name}"
        );
    }

    // Missing, and two proofs.
    let missing = request(vec![("authorization", format!("DPoP {at}"))], None);
    assert_eq!(
        denied(&gate.check(&missing, NOW, "t").await),
        (401, "dpop.invalid", Some(invalid_proof().as_str()))
    );
    let two = request(
        vec![
            ("authorization", format!("DPoP {at}")),
            ("dpop", dpop_proof(&key, "POST", URI, &at, "p-5", NOW)),
            ("dpop", dpop_proof(&key, "POST", URI, &at, "p-6", NOW)),
        ],
        None,
    );
    assert_eq!(
        denied(&gate.check(&two, NOW, "t").await),
        (401, "dpop.invalid", Some(invalid_proof().as_str()))
    );

    // Replay.
    let proof = dpop_proof(&key, "POST", URI, &at, "once", NOW);
    assert!(matches!(
        gate.check(&dpop_call(&at, proof.clone()), NOW, "t").await,
        Outcome::Allow { .. }
    ));
    assert_eq!(
        denied(&gate.check(&dpop_call(&at, proof), NOW, "t").await),
        (401, "dpop.replay", Some(invalid_proof().as_str()))
    );
}

#[tokio::test]
async fn binding_failures_are_invalid_token() {
    let (gate, _) = gate();
    let at = token();

    // A proof by another key.
    let other = dpop_proof(&pop_key(8), "POST", URI, &at, "p-1", NOW);
    assert_eq!(
        denied(&gate.check(&dpop_call(&at, other), NOW, "t").await),
        (401, "dpop.binding", Some(invalid_token().as_str()))
    );

    // The bound token sent as a bearer token (RFC 9449 §7.1).
    let downgrade = request(vec![("authorization", format!("Bearer {at}"))], None);
    assert_eq!(
        denied(&gate.check(&downgrade, NOW, "t").await),
        (401, "token.dpop_bound", Some(invalid_token().as_str()))
    );

    // Any other token failure under the DPoP scheme.
    let expired = dpop_access_token("alice", "mcp-client", "s", AUDIENCE, NOW - 60, &holder());
    let proof = dpop_proof(&holder(), "POST", URI, &expired, "p-2", NOW);
    assert_eq!(
        denied(&gate.check(&dpop_call(&expired, proof), NOW, "t").await),
        (401, "token.expired", Some(invalid_token().as_str()))
    );
}

#[tokio::test]
async fn bearer_failures_advertise_dpop() {
    let (gate, _) = gate();
    let bearer = request(vec![("authorization", "Bearer nope".into())], None);
    let bearer_challenge = format!("Bearer, DPoP {ALGS}");
    assert_eq!(
        denied(&gate.check(&bearer, NOW, "t").await),
        (401, "token.invalid", Some(bearer_challenge.as_str()))
    );
    let none = request(vec![], None);
    assert_eq!(
        denied(&gate.check(&none, NOW, "t").await),
        (401, "credential.missing", Some(bearer_challenge.as_str()))
    );
}

#[tokio::test]
async fn a_dpop_client_holds_an_aat_chain_with_its_proof_key_but_cannot_forward() {
    let (gate, _) = gate();
    let at = token();
    let tools = json!({ "read_file": { "path": { "constraint_type": "wildcard" } } });
    let args = json!({ "path": "/data/report.pdf" });
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": { "name": "read_file", "arguments": args } })
    .to_string();
    let call = |chain_holder: &SigningKey, n: &str| {
        let root = aat_root(&format!("root-{n}"), chain_holder, &tools, NOW, 1, AUDIENCE);
        let pop = aat_pop(
            &format!("pop-{n}"),
            &root,
            &format!("root-{n}"),
            chain_holder,
            "read_file",
            &args,
            AUDIENCE,
            NOW,
        );
        request(
            vec![
                ("authorization", format!("DPoP {at}")),
                ("dpop", dpop_proof(&holder(), "POST", URI, &at, n, NOW)),
                ("aat-chain", root),
                ("aat-pop", pop),
            ],
            Some(&body),
        )
    };
    let outcome = gate.check(&call(&holder(), "c1"), NOW, "t").await;
    assert!(minted(&outcome).tctx.unwrap().contains_key("chain"));
    let outcome = gate.check(&call(&pop_key(8), "c2"), NOW, "t").await;
    assert_eq!(denied(&outcome).1, "chain.holder_mismatch");

    // Even listed in internal_callers, an OAuth client cannot forward a
    // Transaction Token.
    let Outcome::Allow { set, .. } = gate
        .check(
            &dpop_call(&at, dpop_proof(&holder(), "POST", URI, &at, "f1", NOW)),
            NOW,
            "t",
        )
        .await
    else {
        panic!("expected allow")
    };
    let mut forwarded = dpop_call(&at, dpop_proof(&holder(), "POST", URI, &at, "f2", NOW));
    forwarded
        .headers
        .push(("txn-token".into(), set[0].1.clone()));
    assert_eq!(
        denied(&gate.check(&forwarded, NOW, "t").await).1,
        "txn.untrusted_hop"
    );
}

#[tokio::test]
async fn a_dpop_client_presents_an_act_chain_naming_itself() {
    let (gate, seen) = gate();
    let jkt = visado_chain_aat::jwk_thumbprint(&holder().verifying_key());
    let token_with = |actor: &str| {
        signed_access_token(&json!({
            "iss": OAUTH_ISSUER, "sub": "alice", "aud": AUDIENCE, "client_id": "mcp-client",
            "scope": "files.read", "iat": NOW - 5, "exp": NOW + 300, "jti": format!("at-{actor}"),
            "cnf": { "jkt": jkt },
            "act": { "sub": actor, "act": { "sub": "planner" } },
        }))
    };

    let at = token_with("mcp-client");
    let outcome = gate
        .check(
            &dpop_call(&at, dpop_proof(&holder(), "POST", URI, &at, "a-1", NOW)),
            NOW,
            "t1",
        )
        .await;
    let claims = minted(&outcome);
    assert_eq!(claims.sub, "alice");
    let chain = &seen.lock().unwrap().clone().unwrap().context.unwrap()["chain"];
    assert_eq!(chain["actor"]["sub"], json!("mcp-client"));
    assert_eq!(chain["caller_kind"], json!("client"));
    assert!(
        chain.get("prior_actors").is_none(),
        "prior actors stay out of the PDP"
    );

    // The current actor must be the client that proved the key.
    let at = token_with("someone-else");
    let outcome = gate
        .check(
            &dpop_call(&at, dpop_proof(&holder(), "POST", URI, &at, "a-2", NOW)),
            NOW,
            "t2",
        )
        .await;
    assert_eq!(denied(&outcome).1, "act.actor_mismatch");
}
