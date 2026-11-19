//! The audit record of a denied RFC 8693 `act` chain. In its own test binary:
//! a scoped tracing subscriber does not see events reliably while other
//! tests run on other threads.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

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
const URI: &str = "https://tools.td.example/mcp";
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

/// Collects what the log writes.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn the_audit_detail_names_the_actor_and_not_the_token() {
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let gate = Gate::new(
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
                URI,
                serde_json::from_value(oauth_jwks()).unwrap(),
            )),
        AllowPdp,
    );
    let user = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": URI, "client_id": "c",
        "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60,
        "act": { "sub": "spiffe://td.example/agent-c" },
    }));
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(&w, &key, URI, "w1", None, Some(("x-user-token", &user)));
    let input = CheckInput {
        method: "GET".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers: vec![
            ("authorization".into(), format!("WPT {p}")),
            ("workload-identity-token".into(), w),
            ("x-user-token".into(), user),
        ],
        body: None,
        peer_certificate: None,
    };
    let outcome = gate.check(&input, NOW, "t").await;
    assert!(
        matches!(&outcome, Outcome::Deny { code, .. } if code == "act.actor_mismatch"),
        "{outcome:?}"
    );

    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("act.actor_mismatch"), "{text}");
    assert!(text.contains("spiffe://td.example/agent-c"), "{text}");
    assert!(text.contains(AGENT), "{text}");
    // No credential, nor any of its signatures, reaches the log.
    for (_, value) in &input.headers {
        let signature = value.rsplit(['.', ' ']).next().unwrap();
        assert!(!text.contains(signature), "a credential reached the log");
    }
}
