//! The audit record of the longest chain the gate accepts lists every one
//! of its actors, and a chain one hop longer is refused before it is
//! recorded.

#![allow(clippy::unused_async_trait_impl)]

mod support;

use std::collections::BTreeSet;

use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain::invariants::MAX_HOPS;
use visado_chain_act::{MAX_ACTORS_LIMIT, Verifier};
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, oauth_jwks, pop_key, signed_access_token, wit,
    wit_issuer_verifying_key, wpt,
};
use visado_txn_token::Scope;
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const BASE: &str = "https://tools.td.example";
const AGENT: &str = "spiffe://td.example/agent-b";

struct AllowPdp;

impl Pdp for AllowPdp {
    async fn evaluate(&self, _: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Ok(Decision {
            allowed: true,
            context: None,
        })
    }
}

fn gate() -> Gate<AllowPdp> {
    Gate::new(
        GateConfig {
            trust_domain: TRUST_DOMAIN.into(),
            signing_key: SigningKey::from_ed25519_seed(&[0x51; 32]),
            kid: "txn-1".into(),
            txn_lifetime: 60,
            default_scope: Scope::parse("tools.call"),
            internal_callers: BTreeSet::new(),
            allowed_authorities: BTreeSet::from([HOST.to_owned()]),
            aat: None,
            asor: None,
            act: Some(Verifier::new().with_max_actors(MAX_ACTORS_LIMIT)),
            require_chain: false,
        },
        Authenticator::new()
            .with_wit_issuer(
                WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
            )
            .with_oauth_issuer(OAuthIssuer::new(
                OAUTH_ISSUER,
                format!("{BASE}/mcp"),
                serde_json::from_value(oauth_jwks()).unwrap(),
            )),
        AllowPdp,
    )
}

/// The actors of an `act` chain of `len` hops, first hop first: agent-b is
/// the current (last) actor.
fn actors(len: usize) -> Vec<String> {
    let mut actors: Vec<String> = (1..len)
        .map(|i| format!("spiffe://td.example/hop-{i}"))
        .collect();
    actors.push(AGENT.to_owned());
    actors
}

/// agent-b's request with alice's user token whose `act` claim nests
/// `actors`, the last one outermost.
fn request(actors: &[String], jti: &str) -> CheckInput {
    let act = actors.iter().fold(Value::Null, |inner, sub| {
        if inner.is_null() {
            json!({ "sub": sub })
        } else {
            json!({ "sub": sub, "act": inner })
        }
    });
    let token = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": format!("{BASE}/mcp"),
        "client_id": "c", "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60,
        "act": act,
    }));
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(
        &w,
        &key,
        &format!("{BASE}/tickets"),
        jti,
        None,
        Some(("x-user-token", &token)),
    );
    CheckInput {
        method: "GET".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/tickets".into(),
        headers: vec![
            ("authorization".into(), format!("WPT {p}")),
            ("workload-identity-token".into(), w),
            ("x-user-token".into(), token),
        ],
        body: None,
        peer_certificate: None,
    }
}

#[tokio::test]
async fn the_longest_chain_is_recorded_with_every_actor() {
    assert_eq!(MAX_ACTORS_LIMIT, MAX_HOPS);
    let capture = support::Capture::start();
    let gate = gate();

    let longest = actors(MAX_HOPS);
    let allowed = gate.check(&request(&longest, "w1"), NOW, "c1").await;
    assert!(matches!(allowed, Outcome::Allow { .. }), "{allowed:?}");
    let longer = actors(MAX_HOPS + 1);
    let refused = gate.check(&request(&longer, "w2"), NOW, "c2").await;
    assert!(matches!(refused, Outcome::Deny { .. }), "{refused:?}");

    let records = capture.logs.records();
    assert_eq!(records.len(), 2);
    let recorded: Vec<String> = serde_json::from_str(&records[0].chain_actors).unwrap();
    assert_eq!(records[0].chain_hops, u32::try_from(MAX_HOPS).unwrap());
    assert_eq!(recorded, longest);
    assert_eq!(records[1].chain_hops, 0);
    assert_eq!(records[1].chain_actors, "[]");
}
