//! JWS-looking text that a request puts in any text member of the audit
//! record (the path, an MCP tool name, the user token's `sub` or `act`)
//! never reaches the record or the log, whether the request was refused
//! before authentication or allowed.

#![allow(clippy::unused_async_trait_impl)]

mod support;

use std::collections::BTreeSet;

use serde_json::json;
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_act::Verifier;
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

/// A compact JWS, `{"alg":"EdDSA"}` and `{"sub":"<n>"}` with a fake
/// signature.
fn jws(n: u8) -> String {
    format!("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiI{n}In0.c2lnbmF0dXJl{n}")
}

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
        AllowPdp,
    )
}

fn anonymous(method: &str, path: &str, body: Option<String>) -> CheckInput {
    CheckInput {
        method: method.into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: path.into(),
        headers: Vec::new(),
        body: body.map(String::into_bytes),
        peer_certificate: None,
    }
}

/// agent-b's request for alice-as-`sub`, through an intermediate actor
/// named `via`.
fn authenticated(sub: &str, via: &str) -> CheckInput {
    let token = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": sub, "aud": format!("{BASE}/mcp"),
        "client_id": "c", "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60,
        "act": { "sub": AGENT, "act": { "sub": via } },
    }));
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(
        &w,
        &key,
        &format!("{BASE}/tickets"),
        "w1",
        None,
        Some(("x-user-token", &token)),
    );
    CheckInput {
        headers: vec![
            ("authorization".into(), format!("WPT {p}")),
            ("workload-identity-token".into(), w),
            ("x-user-token".into(), token),
        ],
        ..anonymous("GET", "/tickets", None)
    }
}

#[tokio::test]
async fn jws_looking_text_never_reaches_the_record() {
    let capture = support::Capture::start();
    let gate = gate();
    let tokens: Vec<String> = (1..=6).map(jws).collect();

    let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": { "name": tokens[1], "arguments": {} } })
    .to_string();
    let inputs = [
        // Refused before authentication, a token in the path.
        anonymous("GET", &format!("/tickets/{}", tokens[0]), None),
        // Refused before authentication, a token as the MCP tool name.
        anonymous("POST", "/mcp", Some(call)),
        // A token just short of where the resource is cut.
        anonymous("GET", &format!("/{}{}", "a".repeat(220), tokens[2]), None),
        // Allowed, a token as the principal and as an actor.
        authenticated(&tokens[3], &tokens[4]),
        // A token as the HTTP method.
        anonymous(&tokens[5], "/tickets", None),
    ];
    let mut outcomes = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        outcomes.push(gate.check(input, NOW, &format!("c{i}")).await);
    }
    for outcome in &outcomes[..3] {
        assert!(
            matches!(outcome, Outcome::Deny { status: 401, .. }),
            "{outcome:?}"
        );
    }
    assert!(matches!(outcomes[3], Outcome::Allow { .. }), "{outcomes:?}");

    let records = capture.logs.records();
    assert_eq!(records.len(), inputs.len());
    assert_eq!(records[0].resource, format!("{BASE}/tickets/[token]"));
    assert_eq!(records[1].tool, "[token]");
    // Scrubbed before it is cut: cut first, the record would keep the
    // token's start and end with `…`.
    assert_eq!(
        records[2].resource,
        format!("{BASE}/{}[token]", "a".repeat(220))
    );
    assert_eq!(records[3].principal, "[token]");
    assert_eq!(records[3].chain_actors, format!(r#"["[token]","{AGENT}"]"#));
    assert_eq!(records[4].action, "[token]");

    let text = capture.logs.text();
    for token in &tokens {
        assert!(!text.contains(token.as_str()), "a token reached the log");
        let (header, _) = token.split_once('.').unwrap();
        for record in &records {
            let json = serde_json::to_string(record).unwrap();
            assert!(!json.contains(&header[..8]), "a token start in {json}");
        }
    }
}
