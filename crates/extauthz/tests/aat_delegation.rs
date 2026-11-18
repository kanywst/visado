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

fn gate() -> Gate<AllowPdp> {
    let config = GateConfig {
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
    };
    let authenticator = Authenticator::new().with_wit_issuer(
        WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
    );
    Gate::new(config, authenticator, AllowPdp)
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
            .to_string(),
        ),
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
