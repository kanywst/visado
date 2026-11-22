//! The audit record as the server writes it: one JSON event per decision
//! under `visado::audit`, every member of the schema present, the records
//! hash-chained, and no token in any of them.

#![allow(clippy::unused_async_trait_impl)]

mod support;

use std::collections::BTreeSet;

use serde_json::json;
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_act::Verifier;
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::audit::{AUDIT_VERSION, AuditRecord, ChainBreak, verify_chain};
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

/// The members of the record, in schema order (docs/audit.md).
const MEMBERS: [&str; 25] = [
    "audit_version",
    "seq",
    "prev",
    "id",
    "txn",
    "time",
    "agent",
    "auth_method",
    "sender_constrained",
    "principal",
    "chain_profile",
    "chain_issuer",
    "chain_hops",
    "chain_actors",
    "depth_semantics",
    "resource",
    "tool",
    "action",
    "decision",
    "status",
    "reason",
    "detail",
    "pdp",
    "remediation",
    "hash",
];

/// Denies anything under `/admin/`, allows the rest.
struct PathPdp;

impl Pdp for PathPdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Ok(Decision {
            allowed: !request.resource.id.contains("/admin/"),
            context: None,
        })
    }
}

fn gate() -> Gate<PathPdp> {
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
            act: Some(Verifier::new()),
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
        PathPdp,
    )
}

/// agent-b's request for `path`, with alice's user token whose `act` names
/// agent-b when `user` is set.
fn request(method: &str, path: &str, jti: &str, user: bool, body: Option<&str>) -> CheckInput {
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let token = user.then(|| {
        signed_access_token(&json!({
            "iss": OAUTH_ISSUER, "sub": "alice", "aud": format!("{BASE}/mcp"),
            "client_id": "c", "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60,
            "act": { "sub": AGENT, "act": { "sub": "spiffe://td.example/agent-a" } },
        }))
    });
    let p = wpt(
        &w,
        &key,
        &format!("{BASE}{path}"),
        jti,
        None,
        token.as_deref().map(|t| ("x-user-token", t)),
    );
    let mut headers = vec![
        ("authorization".into(), format!("WPT {p}")),
        ("workload-identity-token".into(), w),
    ];
    if let Some(t) = token {
        headers.push(("x-user-token".into(), t));
    }
    CheckInput {
        method: method.into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: path.into(),
        headers,
        body: body.map(|b| b.as_bytes().to_vec()),
        peer_certificate: None,
    }
}

#[tokio::test]
async fn each_decision_writes_one_complete_chained_record() {
    let capture = support::Capture::start();
    let gate = gate();

    let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/data/report.pdf"}}}"#;
    let inputs = [
        // Allowed, for alice through an `act` chain, calling an MCP tool.
        request("POST", "/mcp", "w1", true, Some(call)),
        // Denied by the PDP.
        request("GET", "/admin/roles", "w2", false, None),
        // No credentials at all.
        CheckInput {
            headers: Vec::new(),
            ..request("GET", "/tickets", "w3", false, None)
        },
    ];
    let mut outcomes = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        outcomes.push(gate.check(input, NOW, &format!("check-{i}")).await);
    }
    assert!(matches!(outcomes[0], Outcome::Allow { .. }), "{outcomes:?}");
    assert!(
        matches!(&outcomes[1], Outcome::Deny { code, .. } if code == "pdp.deny"),
        "{outcomes:?}"
    );
    assert!(
        matches!(&outcomes[2], Outcome::Deny { status: 401, .. }),
        "{outcomes:?}"
    );

    let text = capture.logs.text();
    let events = capture.logs.audit_events();
    assert_eq!(
        events.len(),
        inputs.len(),
        "one record per decision: {text}"
    );

    let mut records = Vec::new();
    for event in &events {
        let fields = event["fields"].as_object().unwrap();
        let names: Vec<&str> = fields.keys().map(String::as_str).collect();
        let mut expected = MEMBERS.to_vec();
        expected.sort_unstable();
        let mut names_sorted = names.clone();
        names_sorted.sort_unstable();
        assert_eq!(names_sorted, expected, "members of {event}");
        let record: AuditRecord = serde_json::from_value(event["fields"].clone()).unwrap();
        assert_eq!(record.audit_version, AUDIT_VERSION);
        records.push(record);
    }
    assert_eq!(verify_chain(&records), Ok(()));
    assert_eq!(records[0].seq, 0);
    assert_eq!(records[2].seq, 2);
    check_allowed(&records[0]);
    check_refused(&records[1]);
    check_anonymous(&records[2]);
    assert_eq!(records[1].prev, records[0].hash);

    // Changing any record breaks the chain.
    let mut tampered = records.clone();
    tampered[1].decision = "allow".into();
    assert_eq!(verify_chain(&tampered), Err(ChainBreak::Altered(1)));

    // No credential, nor any of its signatures, reaches the log.
    for input in &inputs {
        for (_, value) in &input.headers {
            let signature = value.rsplit(['.', ' ']).next().unwrap();
            assert!(!text.contains(signature), "a credential reached the log");
        }
    }
}

fn check_allowed(allowed: &AuditRecord) {
    assert_eq!(allowed.id, "check-0");
    assert_eq!(allowed.txn, "check-0");
    assert_eq!(allowed.time, NOW);
    assert_eq!(allowed.agent, AGENT);
    assert_eq!(allowed.auth_method, "wit-wpt");
    assert!(allowed.sender_constrained);
    assert_eq!(allowed.principal, "alice");
    assert_eq!(allowed.chain_profile, "rfc8693-act");
    assert_eq!(allowed.chain_issuer, OAUTH_ISSUER);
    assert_eq!(allowed.chain_hops, 2);
    assert_eq!(
        allowed.chain_actors,
        r#"["spiffe://td.example/agent-a","spiffe://td.example/agent-b"]"#
    );
    assert_eq!(allowed.depth_semantics, "uncapped");
    assert_eq!(allowed.resource, format!("{BASE}/mcp"));
    assert_eq!(allowed.tool, "read_file");
    assert_eq!(allowed.action, "POST");
    assert_eq!(allowed.decision, "allow");
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.reason, "ok");
    assert_eq!(allowed.detail, "");
    assert_eq!(allowed.pdp, "allow");
    assert_eq!(allowed.remediation, "none");
}

fn check_refused(refused: &AuditRecord) {
    assert_eq!(refused.principal, AGENT);
    assert_eq!(refused.tool, "");
    assert_eq!(refused.chain_profile, "");
    assert_eq!(refused.chain_hops, 0);
    assert_eq!(refused.chain_actors, "[]");
    assert_eq!(refused.depth_semantics, "");
    assert_eq!(refused.decision, "deny");
    assert_eq!(refused.status, 403);
    assert_eq!(refused.reason, "pdp.deny");
    assert_eq!(refused.pdp, "deny");
    assert_eq!(refused.remediation, "refused");
}

fn check_anonymous(anonymous: &AuditRecord) {
    assert_eq!(anonymous.id, "check-2");
    assert_eq!(anonymous.txn, "");
    assert_eq!(anonymous.agent, "");
    assert_eq!(anonymous.auth_method, "");
    assert!(!anonymous.sender_constrained);
    assert_eq!(anonymous.reason, "credential.missing");
    assert_ne!(anonymous.detail, "");
    assert_eq!(anonymous.pdp, "not_asked");
    assert_eq!(anonymous.remediation, "reauthenticate");
}
