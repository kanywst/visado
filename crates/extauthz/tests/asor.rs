//! A two-hop asor delegation through the gate: agent A (key 1) holds the
//! root and delegates `crm.read` with a smaller row cap to agent B (key 2),
//! which calls the tool with a DPoP proof of its key.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;

use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_asor::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    ASOR_ISSUER, NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, asor_anchor_key, asor_child_claims,
    asor_root_claims, asor_sign, dpop_proof, oauth_jwks, pop_key, wit, wit_issuer_verifying_key,
    wpt,
};
use visado_txn_token::{KeySet, Scope, Validation, verify};
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const AUDIENCE: &str = "https://tools.td.example";
const URI: &str = "https://tools.td.example/mcp";

/// Allows everything, and checks that the chain reached the PDP.
struct ChainPdp;

impl Pdp for ChainPdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        let chain = &request.context.as_ref().unwrap()["chain"];
        assert_eq!(chain["profile"], "asor-03");
        assert_eq!(chain["principal"], "user:alice");
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
        signing_key: txn_key(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::new(),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: None,
        asor: Some(Verifier::new(
            vec![TrustAnchor::new(
                ASOR_ISSUER,
                asor_anchor_key().verifying_key(),
            )],
            vec![AUDIENCE.to_owned()],
        )),
        act: None,
        require_chain: false,
    }
}

fn gate_with(config: GateConfig) -> Gate<ChainPdp> {
    let authenticator = Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(
            OAUTH_ISSUER,
            AUDIENCE,
            serde_json::from_value(oauth_jwks()).unwrap(),
        ));
    Gate::new(config, authenticator, ChainPdp)
}

fn gate() -> Gate<ChainPdp> {
    gate_with(gate_config())
}

/// Root held by agent A, child held by agent B with `child_scopes`.
fn chain(child_scopes: &Value) -> Vec<String> {
    let root = asor_sign(&asor_root_claims(
        "root-1",
        "spiffe://td.example/agent-a",
        &pop_key(1),
        &json!(["crm.*"]),
        &json!([{ "key": "rows", "max": 1000 }]),
        AUDIENCE,
        NOW,
        3,
    ));
    let child = asor_sign(&asor_child_claims(
        "child-1",
        "spiffe://td.example/agent-b",
        &root,
        &pop_key(2),
        1,
        child_scopes,
        &json!([{ "key": "rows", "max": 100 }]),
        AUDIENCE,
        NOW,
    ));
    vec![root, child]
}

/// An MCP `tools/call` from a workload holding `wit_seed`'s key, carrying
/// `chain` and a DPoP proof by `dpop_seed`'s key when that is given.
fn call(
    chain: &[String],
    wit_seed: u8,
    dpop_seed: Option<u8>,
    tool: &str,
    args: &Value,
    n: u32,
) -> CheckInput {
    let holder = pop_key(wit_seed);
    let w = wit("agent-b", &holder);
    let p = wpt(&w, &holder, URI, &format!("w{n}"), None, None);
    let leaf = chain.last().unwrap();
    let mut headers = vec![
        ("agent-delegation-chain".into(), chain.join(",")),
        ("authorization".into(), format!("WPT {p}")),
        ("workload-identity-token".into(), w),
    ];
    if let Some(seed) = dpop_seed {
        headers.push((
            "dpop".into(),
            dpop_proof(&pop_key(seed), "POST", URI, leaf, &format!("d{n}"), NOW),
        ));
    }
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers,
        body: Some(
            json!({ "jsonrpc": "2.0", "id": n, "method": "tools/call",
                    "params": { "name": tool, "arguments": args } })
            .to_string()
            .into_bytes(),
        ),
        peer_certificate: None,
    }
}

fn denial(outcome: &Outcome) -> (u16, &str) {
    match outcome {
        Outcome::Deny { status, code, .. } => (*status, code),
        Outcome::Allow { .. } => (200, "allow"),
    }
}

fn narrow() -> Vec<String> {
    chain(&json!(["crm.read"]))
}

#[tokio::test]
async fn a_delegated_call_within_the_grant_is_allowed() {
    let input = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 50 }), 1);
    let outcome = gate().check(&input, NOW, "txn-asor").await;
    let Outcome::Allow { set, remove, .. } = &outcome else {
        panic!("{outcome:?}")
    };
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    let claims = verify(&set[0].1, &keys, &Validation::new(TRUST_DOMAIN, NOW))
        .unwrap()
        .claims;
    let chain = &claims.tctx.unwrap()["chain"];
    assert_eq!(chain["profile"], "asor-03");
    assert_eq!(chain["depth"], 1);
    assert!(remove.contains(&"agent-delegation-chain".to_owned()));
    assert!(remove.contains(&"dpop".to_owned()));
}

#[tokio::test]
async fn a_call_outside_the_grant_is_denied() {
    let gate = gate();
    let input = call(&narrow(), 2, Some(2), "crm.write", &json!({}), 1);
    let outcome = gate.check(&input, NOW, "t").await;
    assert_eq!(denial(&outcome), (403, "asor.scope_not_granted"));
    let input = call(
        &narrow(),
        2,
        Some(2),
        "crm.read",
        &json!({ "rows": 500 }),
        2,
    );
    let outcome = gate.check(&input, NOW, "t").await;
    assert_eq!(denial(&outcome), (403, "asor.ceiling_exceeded"));
}

#[tokio::test]
async fn a_widened_scope_is_denied() {
    let widened = chain(&json!(["crm.read", "mail.send"]));
    let outcome = gate()
        .check(
            &call(&widened, 2, Some(2), "mail.send", &json!({}), 1),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denial(&outcome), (403, "asor.not_narrower"));
}

#[tokio::test]
async fn the_chain_must_be_held_by_the_caller() {
    // A workload with key 3 presents agent B's chain with a proof by key 2.
    let outcome = gate()
        .check(
            &call(&narrow(), 3, Some(2), "crm.read", &json!({ "rows": 1 }), 1),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denial(&outcome), (403, "chain.holder_mismatch"));
    // Or with a proof by its own key, which is not the leaf key.
    let outcome = gate()
        .check(
            &call(&narrow(), 3, Some(3), "crm.read", &json!({ "rows": 1 }), 2),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denial(&outcome), (403, "asor.holder_binding_failed"));
}

#[tokio::test]
async fn a_missing_or_replayed_proof_is_denied() {
    let gate = gate();
    let outcome = gate
        .check(
            &call(&narrow(), 2, None, "crm.read", &json!({ "rows": 1 }), 1),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denial(&outcome), (401, "chain.missing_pop"));
    let first = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), 2);
    assert_eq!(denial(&gate.check(&first, NOW, "t").await).1, "allow");
    let mut again = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), 3);
    let proof = first.headers.iter().find(|(n, _)| n == "dpop").unwrap();
    again.headers.retain(|(n, _)| n != "dpop");
    again.headers.push(proof.clone());
    assert_eq!(
        denial(&gate.check(&again, NOW, "t").await),
        (403, "asor.holder_binding_failed")
    );
}

#[tokio::test]
async fn bindings_and_configuration() {
    let gate = gate();
    // A bearer-only caller cannot present a chain.
    let token = access_token("alice", "client-1", "tools.call", AUDIENCE, NOW + 60);
    let mut bearer = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), 1);
    bearer
        .headers
        .retain(|(n, _)| n == "agent-delegation-chain" || n == "dpop");
    bearer
        .headers
        .push(("authorization".into(), format!("Bearer {token}")));
    assert_eq!(
        denial(&gate.check(&bearer, NOW, "t").await),
        (403, "chain.unbound_caller")
    );

    // Both chain formats at once.
    let mut both = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), 2);
    both.headers.push(("aat-chain".into(), "x.y.z".into()));
    assert_eq!(
        denial(&gate.check(&both, NOW, "t").await),
        (400, "chain.ambiguous")
    );

    // asor not configured.
    let mut config = gate_config();
    config.asor = None;
    let input = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), 3);
    assert_eq!(
        denial(&gate_with(config).check(&input, NOW, "t").await),
        (403, "chain.unsupported")
    );

    // A chain is required and the request has none.
    let mut config = gate_config();
    config.require_chain = true;
    let mut none = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), 4);
    none.headers
        .retain(|(n, _)| n != "agent-delegation-chain" && n != "dpop");
    assert_eq!(
        denial(&gate_with(config).check(&none, NOW, "t").await),
        (403, "chain.required")
    );
}

#[tokio::test]
async fn a_forwarded_transaction_must_be_about_the_chain_principal() {
    use visado_txn_token::{TxnTokenClaims, mint};
    let mut config = gate_config();
    config.internal_callers = BTreeSet::from(["spiffe://td.example/agent-b".to_owned()]);
    let gate = gate_with(config);
    let forward = |sub: &str, n: u32| {
        let txn = mint(
            &TxnTokenClaims {
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
            },
            Some("txn-1"),
            &txn_key(),
        )
        .unwrap();
        let mut input = call(&narrow(), 2, Some(2), "crm.read", &json!({ "rows": 1 }), n);
        let key = pop_key(2);
        let w = wit("agent-b", &key);
        let p = wpt(&w, &key, URI, &format!("f{n}"), Some(&txn), None);
        input
            .headers
            .retain(|(h, _)| h != "authorization" && h != "workload-identity-token");
        input
            .headers
            .push(("authorization".into(), format!("WPT {p}")));
        input.headers.push(("workload-identity-token".into(), w));
        input.headers.push(("txn-token".into(), txn));
        input
    };
    // The chain's principal (sub) is user:alice.
    let outcome = gate.check(&forward("user:alice", 1), NOW, "t").await;
    assert_eq!(denial(&outcome).1, "allow");
    let outcome = gate.check(&forward("user:bob", 2), NOW, "t").await;
    assert_eq!(denial(&outcome), (403, "chain.principal_mismatch"));
}
