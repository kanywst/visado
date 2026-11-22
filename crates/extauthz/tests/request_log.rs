//! The request log behind the chain view: what a decision leaves in it, and
//! that no token, proof, signature or body does.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_aat::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::recent::{Decision as Verdict, PdpResult};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome, RequestLog};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, oauth_jwks, pop_key, signed_access_token, wit, wit_at,
    wit_issuer_verifying_key, wpt, wpt_at,
};
use visado_txn_token::Scope;
use wimsey_jose::{Jwk, SigningKey};

const AAT_HOST: &str = "tools.example.com";
const ACT_HOST: &str = "tools.td.example";
const ACT_URI: &str = "https://tools.td.example/mcp";
const AGENT_B: &str = "spiffe://td.example/agent-b";

/// Allows or denies everything.
struct FixedPdp(bool);

impl Pdp for FixedPdp {
    async fn evaluate(&self, _: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Ok(Decision {
            allowed: self.0,
            context: None,
        })
    }
}

fn config(host: &str) -> GateConfig {
    GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: SigningKey::from_ed25519_seed(&[0x51; 32]).into(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::new(),
        allowed_authorities: BTreeSet::from([host.to_owned()]),
        aat: None,
        asor: None,
        act: None,
        require_chain: false,
    }
}

/// Vector J.1 of the published AAT suite, as a request from its holder
/// (`pop_key(2)` in the testkit).
fn aat_gate_and_call(log: &Arc<RequestLog>) -> (Gate<FixedPdp>, CheckInput, u64) {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/aat/aat-jws-vectors.json"
    ))
    .unwrap();
    let suite: Value = serde_json::from_str(&text).unwrap();
    let vector = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "J.1")
        .unwrap();
    let anchors = suite["trust_anchors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let mut jwk = a["jwk"].clone();
            jwk["alg"] = "Ed25519".into();
            let jwk: Jwk = serde_json::from_value(jwk).unwrap();
            TrustAnchor::new(a["iss"].as_str().unwrap(), jwk.to_verifying_key().unwrap())
        })
        .collect();
    let audience = suite["params"]["audience"].as_str().unwrap().to_owned();
    let now = vector["now"].as_u64().unwrap();
    let mut config = config(AAT_HOST);
    config.aat = Some(Verifier::new(anchors, vec![audience]));
    let gate = Gate::new(
        config,
        Authenticator::new().with_wit_issuer(
            WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
        ),
        FixedPdp(true),
    )
    .with_request_log(Arc::clone(log));

    let chain: Vec<&str> = vector["presentation"]["aat_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    let pop = pop_key(2);
    let w = wit_at("spiffe://td.example/orchestrator", &pop, now);
    let p = wpt_at(
        &w,
        &pop,
        &format!("https://{AAT_HOST}/mcp"),
        "w1",
        None,
        None,
        now,
    );
    let tool = vector["tool"].as_str().unwrap();
    let args = vector["args_json"].as_str().unwrap();
    let call = CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: AAT_HOST.into(),
        path: "/mcp".into(),
        headers: vec![
            ("aat-chain".into(), chain.join(",")),
            (
                "aat-pop".into(),
                vector["presentation"]["aat_pop"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
            ("authorization".into(), format!("WPT {p}")),
            ("workload-identity-token".into(), w),
        ],
        body: Some(
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
            )
            .into_bytes(),
        ),
        peer_certificate: None,
    };
    (gate, call, now)
}

/// Every piece of a credential that could leak: each compact JWS part and
/// each whole value.
fn credential_parts(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|value| {
            let mut parts: Vec<String> = value
                .split(['.', ' ', ','])
                .filter(|p| p.len() >= 16)
                .map(str::to_owned)
                .collect();
            parts.push(value);
            parts
        })
        .collect()
}

#[tokio::test]
async fn an_allowed_aat_chain_is_recorded_without_its_tokens() {
    let log = Arc::new(RequestLog::new(8));
    let (gate, call, now) = aat_gate_and_call(&log);
    let outcome = gate.check(&call, now, "check-1").await;
    let Outcome::Allow { set, txn, .. } = &outcome else {
        panic!("{outcome:?}")
    };

    let summary = log.get("check-1").expect("recorded");
    assert_eq!(summary.decision, Verdict::Allow);
    assert_eq!(summary.status, 200);
    assert_eq!(summary.code, "ok");
    assert_eq!(summary.txn.as_deref(), Some(txn.as_str()));
    assert_eq!(summary.time, now);
    assert_eq!(
        summary.caller.as_deref(),
        Some("spiffe://td.example/orchestrator")
    );
    assert_eq!(summary.auth_method, Some("wit-wpt"));
    assert_eq!(summary.pdp, Some(PdpResult::Allow));
    assert_eq!(summary.resource, format!("https://{AAT_HOST}/mcp"));
    let chain = summary.chain.as_ref().expect("chain");
    assert_eq!(chain.profile, "aat-02");
    assert!(chain.holder_proof);
    assert_eq!(chain.hops.len(), 1, "J.1 is a root token");
    assert_eq!(chain.hops[0].link, "root");
    assert!(chain.hops.iter().all(|h| h.assurance == "verified"));

    let json = serde_json::to_string(&log.recent(10)).unwrap();
    let mut secrets: Vec<String> = call.headers.iter().map(|(_, v)| v.clone()).collect();
    secrets.extend(set.iter().map(|(_, v)| v.clone()));
    for part in credential_parts(secrets) {
        assert!(!json.contains(&part), "credential material in {json}");
    }
    let body = String::from_utf8(call.body.clone().unwrap()).unwrap();
    assert!(!json.contains(&body));
    assert!(!json.contains("arguments"), "{json}");
}

#[tokio::test]
async fn an_act_chain_shows_prior_actors_as_declared() {
    let log = Arc::new(RequestLog::new(8));
    let mut config = config(ACT_HOST);
    config.act = Some(visado_chain_act::Verifier::new());
    let gate = Gate::new(
        config,
        Authenticator::new()
            .with_wit_issuer(
                WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
            )
            .with_oauth_issuer(OAuthIssuer::new(
                OAUTH_ISSUER,
                ACT_URI,
                serde_json::from_value(oauth_jwks()).unwrap(),
            )),
        FixedPdp(false),
    )
    .with_request_log(Arc::clone(&log));
    let user = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": ACT_URI, "client_id": "c",
        "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60, "jti": "at-1",
        "act": { "sub": AGENT_B, "act": { "sub": "user-agent-0" } },
    }));
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(&w, &key, ACT_URI, "w1", None, Some(("x-user-token", &user)));
    let call = CheckInput {
        method: "GET".into(),
        scheme: "https".into(),
        authority: ACT_HOST.into(),
        path: "/mcp".into(),
        headers: vec![
            ("authorization".into(), format!("WPT {p}")),
            ("workload-identity-token".into(), w),
            ("x-user-token".into(), user),
        ],
        body: None,
        peer_certificate: None,
    };
    let outcome = gate.check(&call, NOW, "check-act").await;
    assert!(
        matches!(&outcome, Outcome::Deny { code, .. } if code == "pdp.deny"),
        "{outcome:?}"
    );

    let summary = log.get("check-act").unwrap();
    assert_eq!(summary.decision, Verdict::Deny);
    assert_eq!(summary.status, 403);
    assert_eq!(summary.code, "pdp.deny");
    assert_eq!(summary.pdp, Some(PdpResult::Deny));
    assert_eq!(summary.principal.as_deref(), Some("alice"));
    let chain = summary.chain.as_ref().unwrap();
    assert_eq!(chain.profile, "rfc8693-act");
    assert_eq!(chain.principal.as_deref(), Some("alice"));
    let actors: Vec<(&str, &str)> = chain
        .hops
        .iter()
        .map(|h| (h.actor.as_str(), h.assurance))
        .collect();
    assert_eq!(
        actors,
        [("user-agent-0", "declared"), (AGENT_B, "verified")]
    );

    let json = serde_json::to_string(&summary).unwrap();
    for part in credential_parts(call.headers.iter().map(|(_, v)| v.clone())) {
        assert!(!json.contains(&part), "credential material in {json}");
    }
}

#[tokio::test]
async fn a_failed_authentication_is_recorded_without_a_caller() {
    let log = Arc::new(RequestLog::new(2));
    let gate = Gate::new(config(ACT_HOST), Authenticator::new(), FixedPdp(true))
        .with_request_log(Arc::clone(&log));
    let call = CheckInput {
        method: "GET".into(),
        scheme: "https".into(),
        authority: ACT_HOST.into(),
        path: "/mcp".into(),
        headers: vec![("authorization".into(), "Bearer not-a-token".into())],
        body: None,
        peer_certificate: None,
    };
    for id in ["a", "b", "c"] {
        gate.check(&call, NOW, id).await;
    }
    let ids: Vec<String> = log.recent(10).into_iter().map(|s| s.id).collect();
    assert_eq!(ids, ["c", "b"]);
    let summary = log.get("c").unwrap();
    assert_eq!(summary.decision, Verdict::Deny);
    assert_eq!(summary.status, 401);
    assert_eq!(summary.caller, None);
    assert_eq!(summary.txn, None);
    assert_eq!(summary.pdp, None);
    assert_eq!(summary.chain, None);
    assert!(
        !serde_json::to_string(&summary)
            .unwrap()
            .contains("not-a-token")
    );
}
