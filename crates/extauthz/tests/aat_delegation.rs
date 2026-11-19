//! A two-hop AAT delegation minted by the testkit: agent A holds the root and
//! delegates a narrower grant to agent B, which calls the tool.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;

use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_aat::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, WitIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    AAT_ISSUER, NOW, TRUST_DOMAIN, aat_anchor_key, aat_child, aat_pop, aat_root, pop_key, wit,
    wit_issuer_verifying_key, wpt,
};
use visado_txn_token::Scope;
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const AUDIENCE: &str = "https://tools.td.example";

struct AllowPdp;

impl Pdp for AllowPdp {
    async fn evaluate(&self, _: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Ok(Decision {
            allowed: true,
            context: None,
        })
    }
}

fn gate_config() -> GateConfig {
    GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: SigningKey::from_ed25519_seed(&[0x51; 32]),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::new(),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: Some(Verifier::new(
            vec![TrustAnchor::new(
                AAT_ISSUER,
                aat_anchor_key().verifying_key(),
            )],
            vec![AUDIENCE.to_owned()],
        )),
        require_chain: false,
    }
}

fn gate() -> Gate<AllowPdp> {
    let authenticator = Authenticator::new().with_wit_issuer(
        WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
    );
    Gate::new(gate_config(), authenticator, AllowPdp)
}

/// Agent A (key 1) holds `read_file` on any path and `delete_file`; it
/// delegates `read_file` on one path only to agent B (key 2).
fn chain() -> (String, String) {
    let root = aat_root(
        "root-1",
        &pop_key(1),
        &json!({
            "read_file": { "path": { "constraint_type": "wildcard" } },
            "delete_file": { "path": { "constraint_type": "wildcard" } },
        }),
        NOW,
        3,
        AUDIENCE,
    );
    let child = aat_child(
        "child-1",
        &root,
        &pop_key(1),
        &pop_key(2),
        &json!({
            "read_file": { "path": { "constraint_type": "one_of", "values": ["/data/report.pdf"] } },
        }),
        1,
        3,
        NOW,
    );
    (root, child)
}

fn call(workload: &str, seed: u8, tool: &str, args: &Value, n: u32) -> CheckInput {
    let (root, child) = chain();
    let holder = pop_key(seed);
    let w = wit(workload, &holder);
    let p = wpt(
        &w,
        &holder,
        &format!("https://{HOST}/mcp"),
        &format!("w{n}"),
        None,
        None,
    );
    let pop = aat_pop(
        &format!("p{n}"),
        &child,
        "child-1",
        &holder,
        tool,
        args,
        AUDIENCE,
        NOW,
    );
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers: vec![
            ("aat-chain".into(), format!("{root},{child}")),
            ("aat-pop".into(), pop),
            ("authorization".into(), format!("WPT {p}")),
            ("workload-identity-token".into(), w),
        ],
        body: Some(
            json!({ "jsonrpc": "2.0", "id": n, "method": "tools/call",
                    "params": { "name": tool, "arguments": args } })
            .to_string()
            .into_bytes(),
        ),
        peer_certificate: None,
    }
}

fn code(outcome: &Outcome) -> &str {
    match outcome {
        Outcome::Deny { code, .. } => code,
        Outcome::Allow { .. } => "allow",
    }
}

#[tokio::test]
async fn agent_b_may_use_only_what_it_was_given() {
    let gate = gate();
    let read = json!({ "path": "/data/report.pdf" });
    assert_eq!(
        code(
            &gate
                .check(&call("agent-b", 2, "read_file", &read, 1), NOW, "t")
                .await
        ),
        "allow"
    );

    let other_path = json!({ "path": "/etc/passwd" });
    let denied = gate
        .check(&call("agent-b", 2, "read_file", &other_path, 2), NOW, "t")
        .await;
    assert!(code(&denied).starts_with("aat."), "{}", code(&denied));

    let delete = gate
        .check(&call("agent-b", 2, "delete_file", &read, 3), NOW, "t")
        .await;
    assert!(code(&delete).starts_with("aat."), "{}", code(&delete));

    // Another workload presenting agent B's chain, signing the proof with its
    // own key.
    let stolen = gate
        .check(&call("agent-z", 9, "read_file", &read, 4), NOW, "t")
        .await;
    assert!(code(&stolen).starts_with("aat."), "{}", code(&stolen));
}

#[tokio::test]
async fn bodies_that_are_not_one_tool_call_are_refused() {
    let gate = gate();
    let read = json!({ "path": "/data/report.pdf" });
    let mut batch = call("agent-b", 2, "read_file", &read, 10);
    batch.body = Some(
        format!(
            "[{}]",
            String::from_utf8(batch.body.clone().unwrap()).unwrap()
        )
        .into_bytes(),
    );
    assert_eq!(
        code(&gate.check(&batch, NOW, "t").await),
        "chain.bad_invocation"
    );

    let mut missing = call("agent-b", 2, "read_file", &read, 11);
    missing.body = None;
    assert_eq!(
        code(&gate.check(&missing, NOW, "t").await),
        "chain.bad_invocation"
    );

    let mut other_method = call("agent-b", 2, "read_file", &read, 13);
    other_method.body = Some(r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#.into());
    assert_eq!(
        code(&gate.check(&other_method, NOW, "t").await),
        "chain.bad_invocation"
    );

    let mut query = call("agent-b", 2, "read_file", &read, 14);
    query.method = "GET".into();
    query.body = None;
    query.path = "/mcp?anything=1".into();
    assert_eq!(
        code(&gate.check(&query, NOW, "t").await),
        "chain.bad_invocation"
    );

    let mut garbage = call("agent-b", 2, "read_file", &read, 12);
    garbage.body = Some("not json".into());
    assert_eq!(
        code(&gate.check(&garbage, NOW, "t").await),
        "chain.bad_invocation"
    );

    // A body that is not UTF-8 is not decoded lossily into an allowed call.
    let mut binary = call("agent-b", 2, "read_file", &read, 15);
    if let Some(body) = binary.body.as_mut() {
        body.extend_from_slice(&[0xff, 0xfe]);
    }
    assert_eq!(
        code(&gate.check(&binary, NOW, "t").await),
        "chain.bad_invocation"
    );
}

#[tokio::test]
async fn a_bearer_caller_cannot_present_a_chain() {
    let jwks = serde_json::from_value(visado_testkit::oauth_jwks()).unwrap();
    let mut config = gate_config();
    config.aat = Some(Verifier::new(
        vec![TrustAnchor::new(
            AAT_ISSUER,
            aat_anchor_key().verifying_key(),
        )],
        vec![AUDIENCE.to_owned()],
    ));
    let gate = Gate::new(
        config,
        Authenticator::new().with_oauth_issuer(visado_credentials::OAuthIssuer::new(
            visado_testkit::OAUTH_ISSUER,
            format!("https://{HOST}/mcp"),
            jwks,
        )),
        AllowPdp,
    );
    let read = json!({ "path": "/data/report.pdf" });
    let mut request = call("agent-b", 2, "read_file", &read, 20);
    let at = visado_testkit::access_token(
        "alice",
        "client-1",
        "tools.call",
        &format!("https://{HOST}/mcp"),
        NOW + 300,
    );
    request
        .headers
        .retain(|(n, _)| n != "authorization" && n != "workload-identity-token");
    request
        .headers
        .push(("authorization".into(), format!("Bearer {at}")));
    assert_eq!(
        code(&gate.check(&request, NOW, "t").await),
        "chain.unbound_caller"
    );
}

#[tokio::test]
async fn a_required_chain_cannot_be_left_out() {
    let mut config = gate_config();
    config.require_chain = true;
    let gate = Gate::new(
        config,
        Authenticator::new().with_wit_issuer(
            WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
        ),
        AllowPdp,
    );
    let mut request = call(
        "agent-b",
        2,
        "read_file",
        &json!({ "path": "/data/report.pdf" }),
        30,
    );
    request
        .headers
        .retain(|(n, _)| n != "aat-chain" && n != "aat-pop");
    assert_eq!(
        code(&gate.check(&request, NOW, "t").await),
        "chain.required"
    );
}

#[tokio::test]
async fn a_chain_on_a_forwarded_transaction_is_recorded_in_the_token() {
    let mut config = gate_config();
    config.internal_callers = BTreeSet::from([
        "spiffe://td.example/agent-a".to_owned(),
        "spiffe://td.example/agent-b".to_owned(),
    ]);
    let gate = Gate::new(
        config,
        Authenticator::new().with_wit_issuer(
            WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
        ),
        AllowPdp,
    );

    // Hop 1: agent-a calls without a chain and gets a fresh Transaction Token.
    let a = pop_key(1);
    let wit_a = wit("agent-a", &a);
    let proof_a = wpt(
        &wit_a,
        &a,
        &format!("https://{HOST}/tickets"),
        "h1",
        None,
        None,
    );
    let mut first = call("agent-a", 1, "read_file", &json!({}), 40);
    first.method = "GET".into();
    first.path = "/tickets".into();
    first.body = None;
    first.headers = vec![
        ("authorization".into(), format!("WPT {proof_a}")),
        ("workload-identity-token".into(), wit_a),
    ];
    let Outcome::Allow { set, .. } = gate.check(&first, NOW, "txn-fwd").await else {
        panic!("hop 1 should pass")
    };
    let inbound = set[0].1.clone();

    // Hop 2: agent-b forwards it with its own chain.
    let read = json!({ "path": "/data/report.pdf" });
    let mut second = call("agent-b", 2, "read_file", &read, 41);
    let b = pop_key(2);
    let wit_b = wit("agent-b", &b);
    let proof_b = wpt(
        &wit_b,
        &b,
        &format!("https://{HOST}/mcp"),
        "h2",
        Some(&inbound),
        None,
    );
    second
        .headers
        .retain(|(n, _)| n != "authorization" && n != "workload-identity-token");
    second
        .headers
        .push(("authorization".into(), format!("WPT {proof_b}")));
    second
        .headers
        .push(("workload-identity-token".into(), wit_b));
    second.headers.push(("txn-token".into(), inbound.clone()));
    let Outcome::Allow { set, .. } = gate.check(&second, NOW, "unused").await else {
        panic!("hop 2 should pass")
    };
    let outbound = &set[0].1;
    assert_ne!(outbound, &inbound, "the token is replaced");

    let keys = visado_txn_token::KeySet::new().with_key(
        "txn-1",
        SigningKey::from_ed25519_seed(&[0x51; 32]).verifying_key(),
    );
    let old = visado_txn_token::verify(
        &inbound,
        &keys,
        &visado_txn_token::Validation::new(TRUST_DOMAIN, NOW),
    )
    .unwrap()
    .claims;
    let new = visado_txn_token::verify(
        outbound,
        &keys,
        &visado_txn_token::Validation::new(TRUST_DOMAIN, NOW),
    )
    .unwrap()
    .claims;
    visado_txn_token::check_replacement(&old, &new).unwrap();
    assert_eq!(new.txn, "txn-fwd");
    assert!(new.exp <= old.exp, "the lifetime does not grow");
    let tctx = new.tctx.unwrap();
    assert_eq!(
        tctx["chain:spiffe://td.example/agent-b"]["profile"],
        "aat-02"
    );
}
