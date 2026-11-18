//! The decision pipeline end to end, with a stand-in PDP.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;

use envoy_types::ext_authz::v3::pb::{Authorization, CheckRequest};
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request};
use envoy_types::pb::envoy::service::auth::v3::{AttributeContext, check_response::HttpResponse};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, ExtAuthz, Gate, GateConfig, Outcome};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, oauth_jwks, pop_key, wit,
    wit_issuer_verifying_key, wpt,
};
use visado_txn_token::{KeySet, Scope, Validation, verify};
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const AUDIENCE: &str = "https://tools.td.example/admin/roles";

/// Allows a call only when the scope covers the action the path implies.
struct ScopePdp;

impl Pdp for ScopePdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        let scope = request
            .context
            .as_ref()
            .and_then(|c| c["scope"].as_str())
            .unwrap_or("");
        let needs = if request.resource.id.contains("/admin/") {
            "roles.write"
        } else {
            "tickets.read"
        };
        Ok(Decision {
            allowed: scope.split(' ').any(|s| s == needs),
            context: None,
        })
    }
}

struct DownPdp;

impl Pdp for DownPdp {
    async fn evaluate(&self, _: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Err(PdpError::Unavailable("connection refused".into()))
    }
}

fn txn_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x51; 32])
}

fn gate<P: Pdp>(pdp: P) -> Gate<P> {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    let authenticator = Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, AUDIENCE, jwks));
    let config = GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: txn_key(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tickets.read"),
        internal_callers: BTreeSet::from(["spiffe://td.example/agent-a".to_owned()]),
    };
    Gate::new(config, authenticator, pdp)
}

fn input(path: &str, headers: &[(&str, &str)]) -> CheckInput {
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: path.into(),
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).into(), (*v).into()))
            .collect(),
    }
}

fn minted(outcome: &Outcome) -> visado_txn_token::TxnTokenClaims {
    let Outcome::Allow { set, .. } = outcome else {
        panic!("expected allow, got {outcome:?}")
    };
    let token = &set.iter().find(|(n, _)| n == "txn-token").unwrap().1;
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    verify(token, &keys, &Validation::new(TRUST_DOMAIN, NOW + 1))
        .unwrap()
        .claims
}

fn denied(outcome: &Outcome) -> (u16, &str) {
    match outcome {
        Outcome::Deny { status, code, .. } => (*status, code.as_str()),
        Outcome::Allow { .. } => panic!("expected deny"),
    }
}

#[tokio::test]
async fn user_scope_flows_into_the_transaction_token() {
    let gate = gate(ScopePdp);
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let at = access_token(
        "alice",
        "agent-a",
        "roles.write tickets.read",
        AUDIENCE,
        NOW + 300,
    );
    let p = wpt(&w, &pop, AUDIENCE, "j1", None, Some(("x-user-token", &at)));
    let outcome = gate
        .check(
            &input(
                "/admin/roles",
                &[
                    ("workload-identity-token", &w),
                    ("authorization", &format!("WPT {p}")),
                    ("x-user-token", &at),
                ],
            ),
            NOW,
            "txn-1",
        )
        .await;
    let claims = minted(&outcome);
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.req_wl, "spiffe://td.example/agent-a");
    assert_eq!(claims.scope.to_string(), "roles.write tickets.read");
    let Outcome::Allow { remove, .. } = outcome else {
        unreachable!()
    };
    assert!(remove.contains(&"authorization".to_owned()));
    assert!(remove.contains(&"x-user-token".to_owned()));
}

/// The agent-to-agent escalation case: agent B, recruited by agent A on a
/// read-only ticket triage, tries to assign a role. B's scope is the one A was
/// given, so the PDP refuses.
#[tokio::test]
async fn a_recruited_agent_cannot_widen_authority() {
    let gate = gate(ScopePdp);

    // Hop 1: agent A, acting for a low-privilege user, reads tickets.
    let pop_a = pop_key(1);
    let wit_a = wit("agent-a", &pop_a);
    let at = access_token("bob", "agent-a", "tickets.read", AUDIENCE, NOW + 300);
    let p = wpt(
        &wit_a,
        &pop_a,
        "https://tools.td.example/tickets",
        "a1",
        None,
        Some(("x-user-token", &at)),
    );
    let hop1 = gate
        .check(
            &input(
                "/tickets",
                &[
                    ("workload-identity-token", &wit_a),
                    ("authorization", &format!("WPT {p}")),
                    ("x-user-token", &at),
                ],
            ),
            NOW,
            "txn-esc",
        )
        .await;
    let Outcome::Allow { set, .. } = &hop1 else {
        panic!("hop 1 should pass: {hop1:?}")
    };
    let txn_token = set[0].1.clone();

    // Hop 2: agent A forwards the transaction to the admin API.
    let p2 = wpt(&wit_a, &pop_a, AUDIENCE, "a2", Some(&txn_token), None);
    let hop2 = gate
        .check(
            &input(
                "/admin/roles",
                &[
                    ("workload-identity-token", &wit_a),
                    ("authorization", &format!("WPT {p2}")),
                    ("txn-token", &txn_token),
                ],
            ),
            NOW,
            "ignored",
        )
        .await;
    assert_eq!(denied(&hop2), (403, "pdp.deny"));
}

#[tokio::test]
async fn a_forwarded_token_keeps_its_transaction() {
    let gate = gate(ScopePdp);
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let first = gate
        .check(
            &input(
                "/tickets",
                &[
                    ("workload-identity-token", &w),
                    (
                        "authorization",
                        &format!(
                            "WPT {}",
                            wpt(
                                &w,
                                &pop,
                                "https://tools.td.example/tickets",
                                "f1",
                                None,
                                None
                            )
                        ),
                    ),
                ],
            ),
            NOW,
            "txn-keep",
        )
        .await;
    let token = {
        let Outcome::Allow { set, .. } = &first else {
            panic!()
        };
        set[0].1.clone()
    };
    let p = wpt(
        &w,
        &pop,
        "https://tools.td.example/tickets",
        "f2",
        Some(&token),
        None,
    );
    let second = gate
        .check(
            &input(
                "/tickets",
                &[
                    ("workload-identity-token", &w),
                    ("authorization", &format!("WPT {p}")),
                    ("txn-token", &token),
                ],
            ),
            NOW,
            "txn-new",
        )
        .await;
    assert_eq!(minted(&second).txn, "txn-keep");
}

#[tokio::test]
async fn rejections() {
    let gate = gate(ScopePdp);
    assert_eq!(
        denied(&gate.check(&input("/tickets", &[]), NOW, "t").await),
        (401, "credential.missing")
    );

    // An outside caller may not bring its own Transaction Token.
    let pop = pop_key(2);
    let w = wit("agent-z", &pop);
    let forged = "eyJhbGciOiJub25lIn0.e30.";
    let p = wpt(
        &w,
        &pop,
        "https://tools.td.example/tickets",
        "z1",
        Some(forged),
        None,
    );
    let outcome = gate
        .check(
            &input(
                "/tickets",
                &[
                    ("workload-identity-token", &w),
                    ("authorization", &format!("WPT {p}")),
                    ("txn-token", forged),
                ],
            ),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&outcome), (403, "txn.untrusted_hop"));

    // A PDP outage denies.
    let down = self::gate(DownPdp);
    let at = access_token("alice", "client-1", "tickets.read", AUDIENCE, NOW + 300);
    let outcome = down
        .check(
            &input("/tickets", &[("authorization", &format!("Bearer {at}"))]),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&outcome), (403, "pdp.unavailable"));
}

#[tokio::test]
async fn grpc_service_maps_outcomes() {
    let service = ExtAuthz::new(gate(ScopePdp));
    let mut headers = std::collections::HashMap::new();
    headers.insert("authorization".to_owned(), "Bearer nope".to_owned());
    let request = CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(Request {
                http: Some(HttpRequest {
                    method: "GET".into(),
                    host: HOST.into(),
                    path: "/tickets".into(),
                    scheme: "https".into(),
                    headers,
                    ..HttpRequest::default()
                }),
                ..Request::default()
            }),
            ..AttributeContext::default()
        }),
    };
    let response = service
        .check(tonic::Request::new(request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.status.unwrap().code,
        tonic::Code::PermissionDenied as i32
    );
    let Some(HttpResponse::DeniedResponse(denied)) = response.http_response else {
        panic!()
    };
    assert_eq!(denied.status.unwrap().code, 401);
    assert!(denied.body.contains("token.invalid"));
}
