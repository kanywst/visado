//! RFC 8693 `act` chains through the gate: the user's access token says
//! that a client or workload acts for the user, and the current actor must
//! be the caller.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_act::Verifier;
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    AAT_ISSUER, NOW, OAUTH_ISSUER, SignatureSpec, TRUST_DOMAIN, aat_anchor_key, http_signature,
    oauth_jwks, pop_key, signed_access_token, wit, wit_issuer_verifying_key, wpt,
};
use visado_txn_token::{KeySet, Scope, TxnTokenClaims, Validation, mint, verify};
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const URI: &str = "https://tools.td.example/mcp";
const AGENT: &str = "spiffe://td.example/agent-b";

/// Allows everything and keeps each request's context.
#[derive(Default, Clone)]
struct RecordingPdp(Arc<Mutex<Vec<Map<String, Value>>>>);

impl Pdp for RecordingPdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        self.0
            .lock()
            .unwrap()
            .push(request.context.clone().unwrap_or_default());
        Ok(Decision {
            allowed: true,
            context: None,
        })
    }
}

fn txn_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x51; 32])
}

fn gate_config() -> GateConfig {
    GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: txn_key().into(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::new(),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: None,
        asor: None,
        act: Some(Verifier::new()),
        require_chain: false,
    }
}

fn gate_with(config: GateConfig) -> Gate<RecordingPdp> {
    gate_recording(config, RecordingPdp::default())
}

fn gate_recording(config: GateConfig, pdp: RecordingPdp) -> Gate<RecordingPdp> {
    let authenticator = Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(
            OAUTH_ISSUER,
            URI,
            serde_json::from_value(oauth_jwks()).unwrap(),
        ));
    Gate::new(config, authenticator, pdp)
}

fn gate() -> Gate<RecordingPdp> {
    gate_with(gate_config())
}

/// An access token for alice issued to `client_id`, with `act` when given.
fn token(client_id: &str, act: Option<Value>) -> String {
    let mut claims = json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": URI, "client_id": client_id,
        "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60, "jti": "at-1",
    });
    if let Some(act) = act {
        claims["act"] = act;
    }
    signed_access_token(&claims)
}

fn request(headers: Vec<(String, String)>) -> CheckInput {
    CheckInput {
        method: "GET".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers,
        body: None,
        peer_certificate: None,
    }
}

/// A bearer call with `token`.
fn bearer(token: &str) -> CheckInput {
    request(vec![("authorization".into(), format!("Bearer {token}"))])
}

/// A call by the workload agent-b (WIT and WPT) carrying `token` as the
/// user token, bound through the WPT `oth`.
fn workload(token: &str, n: u32) -> CheckInput {
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(
        &w,
        &key,
        URI,
        &format!("w{n}"),
        None,
        Some(("x-user-token", token)),
    );
    request(vec![
        ("authorization".into(), format!("WPT {p}")),
        ("workload-identity-token".into(), w),
        ("x-user-token".into(), token.to_owned()),
    ])
}

fn denial(outcome: &Outcome) -> (u16, &str) {
    match outcome {
        Outcome::Deny { status, code, .. } => (*status, code),
        Outcome::Allow { .. } => (200, "allow"),
    }
}

fn minted_chain(outcome: &Outcome) -> Value {
    let Outcome::Allow { set, .. } = outcome else {
        panic!("{outcome:?}")
    };
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    let claims = verify(&set[0].1, &keys, &Validation::new(TRUST_DOMAIN, NOW))
        .unwrap()
        .claims;
    claims.tctx.unwrap()["chain"].clone()
}

#[tokio::test]
async fn a_workload_acting_for_the_user_is_allowed() {
    let act = json!({ "sub": AGENT, "act": { "sub": "user-agent-0" } });
    let pdp = RecordingPdp::default();
    let gate = gate_recording(gate_config(), pdp.clone());
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 1), NOW, "t")
        .await;
    let chain = minted_chain(&outcome);
    assert_eq!(chain["profile"], "rfc8693-act");
    assert_eq!(chain["principal"], "alice");
    assert_eq!(chain["issuer"], OAUTH_ISSUER);
    assert_eq!(chain["actor"], json!({ "iss": OAUTH_ISSUER, "sub": AGENT }));
    assert_eq!(chain["depth"], 1);
    assert_eq!(
        chain["prior_actors"],
        json!([{ "iss": OAUTH_ISSUER, "sub": "user-agent-0" }])
    );

    // The PDP sees the current actor only (RFC 8693 §4.1).
    let seen = Value::Object(pdp.0.lock().unwrap().last().unwrap().clone());
    let pdp_chain = &seen["chain"];
    assert_eq!(pdp_chain["actor"]["sub"], AGENT);
    assert_eq!(pdp_chain["caller_kind"], "workload");
    assert_eq!(chain["caller_kind"], "workload");
    assert_eq!(pdp_chain["principal"], "alice");
    assert!(pdp_chain.get("prior_actors").is_none());
    assert!(pdp_chain.get("depth").is_none());
    assert!(!seen.to_string().contains("user-agent-0"));
}

#[tokio::test]
async fn a_bearer_caller_cannot_present_an_act_chain() {
    // The client is the current actor, but it proved no key for the request.
    let act = json!({ "sub": "client-1" });
    let outcome = gate()
        .check(&bearer(&token("client-1", Some(act))), NOW, "t")
        .await;
    assert_eq!(denial(&outcome), (403, "chain.unbound_caller"));
}

#[tokio::test]
async fn the_current_actor_must_be_the_caller() {
    let gate = gate();
    // The caller is only a prior actor.
    let act = json!({ "sub": "spiffe://td.example/agent-c", "act": { "sub": AGENT } });
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 1), NOW, "t")
        .await;
    assert_eq!(denial(&outcome), (403, "act.actor_mismatch"));

    // A token issued for another actor.
    let act = json!({ "sub": "spiffe://td.example/agent-c" });
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 2), NOW, "t")
        .await;
    assert_eq!(denial(&outcome), (403, "act.actor_mismatch"));
}

#[tokio::test]
async fn a_mapping_binds_an_actor_name_to_a_caller() {
    let mut config = gate_config();
    config.act = Some(
        Verifier::new()
            .with_actor("agent-b-client", AGENT)
            .with_actor(AGENT, "spiffe://td.example/agent-c"),
    );
    let gate = gate_with(config);
    let act = json!({ "sub": "agent-b-client" });
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 1), NOW, "t")
        .await;
    assert_eq!(minted_chain(&outcome)["actor"]["sub"], "agent-b-client");

    // A mapped name is bound only to its mapped caller, even when it is the
    // caller's own identifier.
    let act = json!({ "sub": AGENT });
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 2), NOW, "t")
        .await;
    assert_eq!(denial(&outcome), (403, "act.actor_mismatch"));
}

#[tokio::test]
async fn a_malformed_act_claim_is_denied() {
    let mut config = gate_config();
    config.act = Some(Verifier::new().with_max_actors(2));
    let gate = gate_with(config);
    let cases = [
        (json!(AGENT), "act.not_object"),
        (Value::Null, "act.not_object"),
        (json!({ "sub": AGENT, "act": [] }), "act.not_object"),
        (json!({ "iss": OAUTH_ISSUER }), "act.missing_sub"),
        (
            json!({ "sub": AGENT, "act": { "sub": 1 } }),
            "act.missing_sub",
        ),
        (json!({ "sub": AGENT, "iss": 2 }), "act.bad_issuer"),
        (
            json!({ "sub": AGENT, "act": { "sub": "a", "act": { "sub": "b" } } }),
            "act.too_deep",
        ),
    ];
    for (n, (act, code)) in (1..).zip(cases) {
        let outcome = gate
            .check(&workload(&token("c", Some(act.clone())), n), NOW, "t")
            .await;
        assert_eq!(denial(&outcome), (403, code), "{act}");
    }
}

#[tokio::test]
async fn one_chain_format_per_request() {
    let act = json!({ "sub": AGENT });
    for header in ["aat-chain", "agent-delegation-chain"] {
        let mut input = workload(&token("c", Some(act.clone())), 1);
        input.headers.push((header.into(), "x.y.z".into()));
        assert_eq!(
            denial(&gate().check(&input, NOW, "t").await),
            (400, "chain.ambiguous"),
            "{header}"
        );
    }
}

#[tokio::test]
async fn configuration() {
    // Without [act], a token with an act claim is refused, not read as the
    // user's own.
    let mut config = gate_config();
    config.act = None;
    let act = json!({ "sub": AGENT });
    let outcome = gate_with(config)
        .check(&workload(&token("c", Some(act.clone())), 1), NOW, "t")
        .await;
    assert_eq!(denial(&outcome), (403, "chain.unsupported"));

    // A required chain: a token without act is denied, one with act passes.
    let mut config = gate_config();
    config.require_chain = true;
    let gate = gate_with(config);
    let outcome = gate.check(&workload(&token("c", None), 1), NOW, "t").await;
    assert_eq!(denial(&outcome), (403, "chain.required"));
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 2), NOW, "t")
        .await;
    assert_eq!(denial(&outcome).1, "allow");

    // A token without act is unaffected by [act], for a bearer caller too.
    let outcome = gate_with(gate_config())
        .check(&bearer(&token("client-1", None)), NOW, "t")
        .await;
    assert_eq!(denial(&outcome).1, "allow");
}

/// A Transaction Token from an earlier hop, issued by this gate for `sub`.
fn inbound_txn(sub: &str) -> String {
    let claims = TxnTokenClaims {
        iss: None,
        iat: NOW - 1,
        aud: TRUST_DOMAIN.into(),
        exp: NOW + 30,
        txn: "txn-upstream".into(),
        sub: sub.into(),
        scope: Scope::parse("tools.call"),
        req_wl: "spiffe://td.example/agent-a".into(),
        tctx: None,
        rctx: None,
    };
    mint(&claims, Some("txn-1"), &txn_key()).unwrap()
}

/// agent-b forwards `txn` with `token` as the user token, both bound
/// through its WPT.
fn forwarding(token: &str, txn: &str, n: u32) -> CheckInput {
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(
        &w,
        &key,
        URI,
        &format!("f{n}"),
        Some(txn),
        Some(("x-user-token", token)),
    );
    request(vec![
        ("authorization".into(), format!("WPT {p}")),
        ("workload-identity-token".into(), w),
        ("x-user-token".into(), token.to_owned()),
        ("txn-token".into(), txn.to_owned()),
    ])
}

#[tokio::test]
async fn a_forwarded_transaction_records_the_act_chain() {
    let mut config = gate_config();
    config.internal_callers = BTreeSet::from([AGENT.to_owned()]);
    let gate = gate_with(config);
    let act = json!({ "sub": AGENT, "act": { "sub": "user-agent-0" } });

    let outcome = gate
        .check(
            &forwarding(&token("c", Some(act.clone())), &inbound_txn("alice"), 1),
            NOW,
            "t",
        )
        .await;
    let Outcome::Allow { set, txn, .. } = &outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(txn, "txn-upstream");
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    let claims = verify(&set[0].1, &keys, &Validation::new(TRUST_DOMAIN, NOW))
        .unwrap()
        .claims;
    assert_eq!(claims.sub, "alice");
    let chain = &claims.tctx.unwrap()[&format!("chain:{AGENT}")];
    assert_eq!(chain["profile"], "rfc8693-act");
    assert_eq!(chain["prior_actors"][0]["sub"], "user-agent-0");

    // The user token is about alice, the transaction about bob.
    let outcome = gate
        .check(
            &forwarding(&token("c", Some(act)), &inbound_txn("bob"), 2),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denial(&outcome), (403, "chain.principal_mismatch"));
}

/// agent-b signs the request with an HTTP message signature that covers
/// `token` as the user token.
fn signed(token: &str, nonce: &str) -> CheckInput {
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let headers = [
        ("x-user-token", token),
        ("workload-identity-token", w.as_str()),
    ];
    let spec = SignatureSpec {
        nonce,
        created: NOW,
        audience: URI,
        cover: &["x-user-token"],
    };
    let (signature_input, signature) = http_signature("POST", HOST, "/mcp", &headers, &key, &spec);
    let mut input = request(
        headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
    );
    input.method = "POST".into();
    input
        .headers
        .push(("signature-input".into(), signature_input));
    input.headers.push(("signature".into(), signature));
    input.headers.push(("content-length".into(), "0".into()));
    input
}

#[tokio::test]
async fn an_act_chain_rides_on_a_signed_request() {
    let gate = gate();
    let act = json!({ "sub": AGENT });
    let outcome = gate
        .check(&signed(&token("c", Some(act)), "n1"), NOW, "t")
        .await;
    assert_eq!(minted_chain(&outcome)["actor"]["sub"], AGENT);
    let act = json!({ "sub": "spiffe://td.example/agent-c" });
    let outcome = gate
        .check(&signed(&token("c", Some(act)), "n2"), NOW, "t")
        .await;
    assert_eq!(denial(&outcome), (403, "act.actor_mismatch"));
}

#[tokio::test]
async fn a_subject_prefix_applies_to_the_principal_not_to_the_actor() {
    let authenticator = Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(
            OAuthIssuer::new(
                OAUTH_ISSUER,
                URI,
                serde_json::from_value(oauth_jwks()).unwrap(),
            )
            .with_subject_prefix("idp:"),
        );
    let gate = Gate::new(gate_config(), authenticator, RecordingPdp::default());
    let act = json!({ "sub": AGENT });
    let outcome = gate
        .check(&workload(&token("c", Some(act.clone())), 1), NOW, "t")
        .await;
    let chain = minted_chain(&outcome);
    assert_eq!(chain["principal"], "idp:alice");
    assert_eq!(chain["actor"]["sub"], AGENT);
    // The bearer client is idp:c; it cannot present a chain at all.
    let act = json!({ "sub": "idp:c" });
    let outcome = gate.check(&bearer(&token("c", Some(act))), NOW, "t").await;
    assert_eq!(denial(&outcome), (403, "chain.unbound_caller"));
}

#[tokio::test]
async fn an_actor_named_by_another_issuer_is_recorded_with_it() {
    let act = json!({ "sub": AGENT, "iss": "https://wit.td.example",
                      "act": { "sub": "user-agent-0", "iss": "https://other.example" } });
    let pdp = RecordingPdp::default();
    let gate = gate_recording(gate_config(), pdp.clone());
    let outcome = gate
        .check(&workload(&token("c", Some(act)), 1), NOW, "t")
        .await;
    let chain = minted_chain(&outcome);
    assert_eq!(
        chain["actor"],
        json!({ "iss": "https://wit.td.example", "sub": AGENT })
    );
    assert_eq!(chain["prior_actors"][0]["iss"], "https://other.example");
    let seen = Value::Object(pdp.0.lock().unwrap().last().unwrap().clone());
    assert_eq!(seen["chain"]["actor"]["iss"], "https://wit.td.example");
    assert!(!seen.to_string().contains("other.example"));
}

fn aat_verifier() -> visado_chain_aat::Verifier {
    visado_chain_aat::Verifier::new(
        vec![visado_chain_aat::TrustAnchor::new(
            AAT_ISSUER,
            aat_anchor_key().verifying_key(),
        )],
        vec!["https://tools.td.example".to_owned()],
    )
}

#[tokio::test]
async fn an_act_claim_next_to_an_aat_chain_is_ambiguous_without_act() {
    let mut config = gate_config();
    config.act = None;
    config.aat = Some(aat_verifier());
    let mut input = workload(&token("c", Some(json!({ "sub": AGENT }))), 1);
    input.headers.push(("aat-chain".into(), "x.y.z".into()));
    assert_eq!(
        denial(&gate_with(config).check(&input, NOW, "t").await),
        (400, "chain.ambiguous")
    );
}

#[tokio::test]
async fn an_act_chain_satisfies_a_chain_required_with_aat() {
    let mut config = gate_config();
    config.aat = Some(aat_verifier());
    config.require_chain = true;
    let gate = gate_with(config);
    let outcome = gate
        .check(
            &workload(&token("c", Some(json!({ "sub": AGENT }))), 1),
            NOW,
            "t",
        )
        .await;
    assert_eq!(minted_chain(&outcome)["profile"], "rfc8693-act");
    let outcome = gate.check(&workload(&token("c", None), 2), NOW, "t").await;
    assert_eq!(denial(&outcome), (403, "chain.required"));
}
