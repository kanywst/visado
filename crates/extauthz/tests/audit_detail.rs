//! A credential whose claim does not parse is refused with a fixed
//! description in `detail`: the claim's value, which can be personal data,
//! never reaches the audit record or the log.

#![allow(clippy::unused_async_trait_impl)]

mod support;

use std::collections::BTreeSet;

use serde_json::json;
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_act::Verifier;
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, oauth_jwks, signed_access_token, wit_issuer_verifying_key,
};
use visado_txn_token::Scope;
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const BASE: &str = "https://tools.td.example";

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
            signing_key: SigningKey::from_ed25519_seed(&[0x51; 32]).into(),
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

const PERSONAL: &str = "alice.personal@example.com";

#[tokio::test]
async fn a_malformed_claim_is_described_not_quoted() {
    let capture = support::Capture::start();
    let gate = gate();
    // `nbf` must be a number; serde's message would quote the string.
    let token = signed_access_token(&json!({
        "iss": OAUTH_ISSUER, "sub": "bob", "aud": format!("{BASE}/mcp"),
        "client_id": "c", "scope": "tools.call", "iat": NOW - 5, "exp": NOW + 60,
        "nbf": PERSONAL,
    }));
    let input = CheckInput {
        method: "GET".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/tickets".into(),
        headers: vec![("authorization".into(), format!("Bearer {token}"))],
        body: None,
        peer_certificate: None,
    };
    let outcome = gate.check(&input, NOW, "c0").await;
    assert!(
        matches!(&outcome, Outcome::Deny { status: 401, code, .. } if code == "token.invalid"),
        "{outcome:?}"
    );

    let records = capture.logs.records();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].detail,
        "invalid access token: a claim is malformed"
    );
    assert!(
        !capture.logs.text().contains(PERSONAL),
        "a claim value reached the log"
    );
}
