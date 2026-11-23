//! The decision pipeline end to end, with a stand-in PDP.

#![allow(clippy::unused_async_trait_impl, clippy::too_many_lines)]

use std::collections::{BTreeSet, HashMap};

use envoy_types::ext_authz::v3::pb::{Authorization, CheckRequest, HeaderAppendAction};
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request};
use envoy_types::pb::envoy::service::auth::v3::{AttributeContext, check_response::HttpResponse};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_credentials::{Authenticator, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, ExtAuthz, Gate, GateConfig, Outcome};
use visado_testkit::{
    NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, oauth_jwks, pop_key, signed_access_token, wit,
    wit_issuer_verifying_key, wpt,
};
use visado_txn_token::{KeySet, Scope, TxnTokenClaims, Validation, verify};
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const TICKETS: &str = "https://tools.td.example/tickets";
const ADMIN: &str = "https://tools.td.example/admin/roles";

/// Allows a call only when the scope covers what the path needs.
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

fn config() -> GateConfig {
    GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: txn_key(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tickets.read"),
        internal_callers: BTreeSet::from([
            "spiffe://td.example/agent-a".to_owned(),
            "spiffe://td.example/agent-b".to_owned(),
        ]),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: None,
        asor: None,
        act: None,
        require_chain: false,
    }
}

fn authenticator(audience: &str) -> Authenticator {
    let jwks = serde_json::from_value(oauth_jwks()).unwrap();
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(OAUTH_ISSUER, audience, jwks))
}

fn gate<P: Pdp>(pdp: P) -> Gate<P> {
    Gate::new(config(), authenticator(ADMIN), pdp)
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
        body: None,
        peer_certificate: None,
    }
}

/// A WIT, a WPT for the request target and the optional extra headers.
fn wimse_call(
    workload: &str,
    seed: u8,
    path: &str,
    jti: &str,
    txn: Option<&str>,
    user: Option<&str>,
) -> CheckInput {
    let pop = pop_key(seed);
    let w = wit(workload, &pop);
    let audience = format!("https://{HOST}{path}");
    let p = wpt(
        &w,
        &pop,
        &audience,
        jti,
        txn,
        user.map(|u| ("x-user-token", u)),
    );
    let mut headers = vec![
        ("workload-identity-token", w.clone()),
        ("authorization", format!("WPT {p}")),
    ];
    if let Some(txn) = txn {
        headers.push(("txn-token", txn.to_owned()));
    }
    if let Some(user) = user {
        headers.push(("x-user-token", user.to_owned()));
    }
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    input(path, &headers)
}

fn minted(outcome: &Outcome) -> (String, TxnTokenClaims) {
    let Outcome::Allow { set, .. } = outcome else {
        panic!("expected allow, got {outcome:?}")
    };
    let token = set
        .iter()
        .find(|(n, _)| n == "txn-token")
        .unwrap()
        .1
        .clone();
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    let claims = verify(&token, &keys, &Validation::new(TRUST_DOMAIN, NOW + 1))
        .unwrap()
        .claims;
    (token, claims)
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
    let at = access_token(
        "alice",
        "agent-a",
        "roles.write tickets.read",
        ADMIN,
        NOW + 300,
    );
    let outcome = gate
        .check(
            &wimse_call("agent-a", 1, "/admin/roles", "j1", None, Some(&at)),
            NOW,
            "txn-1",
        )
        .await;
    let (_, claims) = minted(&outcome);
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.req_wl, "spiffe://td.example/agent-a");
    assert_eq!(claims.scope.to_string(), "roles.write tickets.read");
    let Outcome::Allow { remove, .. } = outcome else {
        unreachable!()
    };
    for header in ["authorization", "workload-identity-token", "x-user-token"] {
        assert!(remove.contains(&header.to_owned()), "{header} is removed");
    }
}

#[tokio::test]
async fn a_renamed_user_token_header_is_still_removed() {
    let gate = Gate::new(
        config(),
        authenticator(ADMIN).with_user_token_header("X-Access-Token"),
        ScopePdp,
    );
    let at = access_token("alice", "agent-a", "roles.write", ADMIN, NOW + 300);
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let p = wpt(&w, &pop, ADMIN, "r1", None, Some(("x-access-token", &at)));
    let outcome = gate
        .check(
            &input(
                "/admin/roles",
                &[
                    ("workload-identity-token", &w),
                    ("authorization", &format!("WPT {p}")),
                    ("x-access-token", &at),
                ],
            ),
            NOW,
            "t",
        )
        .await;
    let Outcome::Allow { remove, .. } = outcome else {
        panic!("{outcome:?}")
    };
    assert!(remove.contains(&"x-access-token".to_owned()));
}

/// The agent-to-agent escalation case: a low-privilege user's request is
/// triaged by agent A, which hands the transaction to agent B. B tries to
/// assign a role. The Transaction Token carries the user's read-only scope, so
/// the PDP refuses.
#[tokio::test]
async fn a_recruited_agent_cannot_widen_authority() {
    let gate = gate(ScopePdp);
    let at = access_token("bob", "agent-a", "tickets.read", ADMIN, NOW + 300);
    let hop1 = gate
        .check(
            &wimse_call("agent-a", 1, "/tickets", "a1", None, Some(&at)),
            NOW,
            "txn-esc",
        )
        .await;
    let (token, claims) = minted(&hop1);
    assert_eq!(claims.sub, "bob");

    let hop2 = gate
        .check(
            &wimse_call("agent-b", 2, "/admin/roles", "b1", Some(&token), None),
            NOW,
            "x",
        )
        .await;
    assert_eq!(denied(&hop2), (403, "pdp.deny"));

    let hop2_read = gate
        .check(
            &wimse_call("agent-b", 2, "/tickets", "b2", Some(&token), None),
            NOW,
            "x",
        )
        .await;
    let (forwarded, claims) = minted(&hop2_read);
    assert_eq!(forwarded, token, "the token is forwarded unchanged");
    assert_eq!(claims.txn, "txn-esc");
}

#[tokio::test]
async fn forwarding_is_limited_to_internal_workloads() {
    let gate = gate(ScopePdp);
    let first = gate
        .check(
            &wimse_call("agent-a", 1, "/tickets", "f1", None, None),
            NOW,
            "txn-keep",
        )
        .await;
    let (token, _) = minted(&first);

    let outsider = gate
        .check(
            &wimse_call("agent-z", 9, "/tickets", "z1", Some(&token), None),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&outsider), (403, "txn.untrusted_hop"));

    // A bearer client named like an internal workload is still not one.
    let at = access_token(
        "alice",
        "spiffe://td.example/agent-a",
        "tickets.read",
        TICKETS,
        NOW + 300,
    );
    let gate_tickets = Gate::new(config(), authenticator(TICKETS), ScopePdp);
    let bearer = gate_tickets
        .check(
            &input(
                "/tickets",
                &[
                    ("authorization", &format!("Bearer {at}")),
                    ("txn-token", &token),
                ],
            ),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&bearer), (403, "txn.untrusted_hop"));

    // An internal workload with a token that does not verify.
    let forged = format!("{token}x");
    let pop = pop_key(1);
    let w = wit("agent-a", &pop);
    let p = wpt(&w, &pop, TICKETS, "f2", Some(&forged), None);
    let bad = gate
        .check(
            &input(
                "/tickets",
                &[
                    ("workload-identity-token", &w),
                    ("authorization", &format!("WPT {p}")),
                    ("txn-token", &forged),
                ],
            ),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&bad).0, 403);
    assert!(denied(&bad).1.starts_with("txn."));
}

#[tokio::test]
async fn request_target_is_checked_first() {
    let gate = gate(ScopePdp);
    let mut other_host = wimse_call("agent-a", 1, "/tickets", "t1", None, None);
    other_host.authority = "evil.example".into();
    assert_eq!(
        denied(&gate.check(&other_host, NOW, "t").await),
        (403, "request.unknown_authority")
    );

    for path in [
        "/tickets/../admin/roles",
        "/tickets/%2e%2e/admin",
        "/a//b",
        "/a/%2F/b",
        "/a/./b",
        // Path parameters: Tomcat and Jetty read `..;` as `..` and drop
        // `;jsessionid=x`.
        "/public/..;/admin",
        "/public/.;/admin",
        "/admin;jsessionid=x",
        "/admin%3bx",
        // Double encoding, encoded unreserved characters, overlong UTF-8.
        "/public/%252e%252e/admin",
        "/%61dmin",
        "/a%2Db",
        "/public/%c0%ae%c0%ae/admin",
        "/caf%C3",
        "/a%zz",
        "/a%2",
        // Encoded and literal backslashes, NUL and control characters.
        "/public/..%5cadmin",
        "/public\\..\\admin",
        "/a%00b",
        "/a%0d%0ab",
        "/a\u{0}b",
        "/a\tb",
        "/a b",
        "/caf\u{e9}",
        // A fragment reaches the PDP as the part before it.
        "/public#/../admin",
        "/public?x=1#frag",
        "relative",
    ] {
        assert_eq!(
            denied(&gate.check(&input(path, &[]), NOW, "t").await),
            (400, "request.unnormalized_path"),
            "{path}"
        );
    }
    // Ordinary paths get past the target check to authentication.
    for path in [
        "/tickets",
        "/tickets/",
        "/a/b%20c",
        "/files/caf%C3%A9",
        "/a:b@c/!$&'()*+,=",
        "/q?x=..;/%2e%25",
    ] {
        assert_eq!(
            denied(&gate.check(&input(path, &[]), NOW, "t").await),
            (401, "credential.missing"),
            "{path}"
        );
    }
    // The target is checked before any credential, so no consumer of the
    // path (the resource id, the WPT `aud`, a DPoP `htu`, an HTTP signature
    // `@path`, the bodiless AAT tool name) sees one that was refused.
    let signed = wimse_call("agent-a", 1, "/public/..;/admin/roles", "t2", None, None);
    assert_eq!(
        denied(&gate.check(&signed, NOW, "t").await),
        (400, "request.unnormalized_path")
    );

    let mut no_scheme = input("/tickets", &[]);
    no_scheme.scheme = String::new();
    assert_eq!(
        denied(&gate.check(&no_scheme, NOW, "t").await),
        (400, "request.no_scheme")
    );
}

#[tokio::test]
async fn rejections() {
    let gate = gate(ScopePdp);
    assert_eq!(
        denied(&gate.check(&input("/tickets", &[]), NOW, "t").await),
        (401, "credential.missing")
    );

    // A user token without a scope grants nothing, even with a default scope.
    let no_scope = signed_access_token(&serde_json::json!({
        "iss": OAUTH_ISSUER, "sub": "alice", "aud": ADMIN, "client_id": "c1", "exp": NOW + 300,
    }));
    let outcome = gate
        .check(
            &input(
                "/tickets",
                &[("authorization", &format!("Bearer {no_scope}"))],
            ),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&outcome), (403, "token.no_scope"));

    // A PDP outage denies.
    let down = self::gate(DownPdp);
    let at = access_token("alice", "client-1", "tickets.read", ADMIN, NOW + 300);
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
async fn bearer_clients_are_marked_in_req_wl() {
    let gate = gate(ScopePdp);
    let at = access_token("alice", "mcp-client", "tickets.read", ADMIN, NOW + 300);
    let outcome = gate
        .check(
            &input("/tickets", &[("authorization", &format!("Bearer {at}"))]),
            NOW,
            "t",
        )
        .await;
    let (_, claims) = minted(&outcome);
    assert_eq!(claims.req_wl, "oauth-client:mcp-client");
    assert_eq!(claims.sub, "alice");
}

fn check_request(headers: HashMap<String, String>) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(Request {
                http: Some(HttpRequest {
                    method: "POST".into(),
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
    }
}

#[tokio::test]
async fn grpc_service_maps_outcomes() {
    let service = ExtAuthz::new(Gate::new(config(), authenticator(TICKETS), ScopePdp));

    let rejected = service
        .check(tonic::Request::new(check_request(HashMap::from([(
            "authorization".to_owned(),
            "Bearer nope".to_owned(),
        )]))))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        rejected.status.unwrap().code,
        tonic::Code::PermissionDenied as i32
    );
    let Some(HttpResponse::DeniedResponse(body)) = rejected.http_response else {
        panic!()
    };
    assert_eq!(body.status.unwrap().code, 401);
    assert!(body.body.contains("token.invalid"));

    // The service reads the real clock, so this token expires far in the future.
    let at = access_token("alice", "client-1", "tickets.read", TICKETS, 4_000_000_000);
    let allowed = service
        .check(tonic::Request::new(check_request(HashMap::from([(
            "authorization".to_owned(),
            format!("Bearer {at}"),
        )]))))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(allowed.status.unwrap().code, tonic::Code::Ok as i32);
    assert!(allowed.dynamic_metadata.unwrap().fields.contains_key("txn"));
    let Some(HttpResponse::OkResponse(ok)) = allowed.http_response else {
        panic!()
    };
    let txn = ok
        .headers
        .iter()
        .find(|h| h.header.as_ref().unwrap().key == "txn-token")
        .unwrap();
    assert_eq!(
        txn.append_action,
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32
    );
    assert!(ok.headers_to_remove.contains(&"authorization".to_owned()));

    let empty = service
        .check(tonic::Request::new(CheckRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert!(
        matches!(empty.http_response, Some(HttpResponse::DeniedResponse(_))),
        "malformed requests are denied, not returned as gRPC errors"
    );
}
