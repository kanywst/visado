//! The gate and the gRPC service with server-provided DPoP nonces
//! (RFC 9449 §8, §8.2, §9): a 401 `use_dpop_nonce` with a `DPoP-Nonce`
//! header, then a retry with that nonce.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::{BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use envoy_types::ext_authz::v3::pb::{Authorization, CheckRequest, HeaderAppendAction};
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request};
use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_asor::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, Nonces, OAuthIssuer, WitIssuer};
use visado_extauthz::{CheckInput, DPOP_NONCE_HEADER, ExtAuthz, Gate, GateConfig, Outcome};
use visado_testkit::{
    ASOR_ISSUER, NOW, OAUTH_ISSUER, TRUST_DOMAIN, access_token, asor_anchor_key, asor_child_claims,
    asor_root_claims, asor_sign, dpop_access_token, dpop_claims, dpop_jwk, oauth_jwks, pop_key,
    sign_dpop_proof, wit, wit_issuer_verifying_key, wpt,
};
use visado_txn_token::Scope;
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const AUDIENCE: &str = "https://tools.td.example";
const URI: &str = "https://tools.td.example/mcp";
const NOW_I: i64 = 1_800_000_000;
const ALGS: &str = r#"algs="ES256 EdDSA Ed25519""#;

/// Allows everything except the `deny-me` client.
struct Pdp1;

impl Pdp for Pdp1 {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Ok(Decision {
            allowed: request.subject.id != "deny-me",
            context: None,
        })
    }
}

fn nonces() -> Nonces {
    Nonces::new(&[0x6e; 32], 120).unwrap()
}

fn config() -> GateConfig {
    GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: SigningKey::from_ed25519_seed(&[0x51; 32]).into(),
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

fn authenticator() -> Authenticator {
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_oauth_issuer(OAuthIssuer::new(
            OAUTH_ISSUER,
            AUDIENCE,
            serde_json::from_value(oauth_jwks()).unwrap(),
        ))
}

fn gate() -> Gate<Pdp1> {
    Gate::new(config(), authenticator().with_dpop_nonces(nonces()), Pdp1)
}

fn gate_without_nonces() -> Gate<Pdp1> {
    Gate::new(config(), authenticator(), Pdp1)
}

fn holder() -> SigningKey {
    pop_key(7)
}

fn token_for(client: &str, exp: u64) -> String {
    dpop_access_token("alice", client, "files.read", AUDIENCE, exp, &holder())
}

fn token() -> String {
    token_for("mcp-client", NOW + 300)
}

/// A proof for `token` at `iat` with `jti`, carrying `nonce` if given.
fn proof(token: &str, jti: &str, nonce: Option<&str>, iat: u64) -> String {
    let key = holder();
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(&key) });
    let mut claims = dpop_claims("POST", URI, token, jti, iat);
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    sign_dpop_proof(&header, &claims, &key)
}

fn input(headers: Vec<(&str, String)>, body: Option<String>) -> CheckInput {
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers: headers
            .into_iter()
            .map(|(n, v)| (n.to_owned(), v))
            .collect(),
        body: body.map(String::into_bytes),
        peer_certificate: None,
    }
}

fn dpop_call(token: &str, proof: String) -> CheckInput {
    input(
        vec![("authorization", format!("DPoP {token}")), ("dpop", proof)],
        None,
    )
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// The status, code, challenge and headers of a denial.
fn denied(outcome: &Outcome) -> (u16, &str, Option<&str>, &[(String, String)]) {
    match outcome {
        Outcome::Deny {
            status,
            code,
            challenge,
            headers,
        } => (*status, code.as_str(), challenge.as_deref(), headers),
        Outcome::Allow { .. } => panic!("expected deny, got {outcome:?}"),
    }
}

fn allowed(outcome: &Outcome) -> &[(String, String)] {
    match outcome {
        Outcome::Allow {
            response_headers, ..
        } => response_headers,
        Outcome::Deny { .. } => panic!("expected allow, got {outcome:?}"),
    }
}

fn use_nonce() -> String {
    format!(r#"DPoP error="use_dpop_nonce", {ALGS}"#)
}

/// The `DPoP-Nonce` of a 401 or an allow, checked to be a nonce this gate
/// accepts right now.
fn nonce_of(headers: &[(String, String)]) -> String {
    let nonce = header(headers, DPOP_NONCE_HEADER).expect("a DPoP-Nonce header");
    assert_eq!(nonces().check(nonce, NOW_I), Ok(NOW_I));
    nonce.to_owned()
}

#[tokio::test]
async fn a_first_proof_without_a_nonce_gets_one_and_the_retry_passes() {
    let gate = gate();
    let at = token();
    let first = gate
        .check(&dpop_call(&at, proof(&at, "p-1", None, NOW)), NOW, "t")
        .await;
    let (status, code, challenge, headers) = denied(&first);
    assert_eq!((status, code), (401, "dpop.nonce_missing"));
    assert_eq!(challenge, Some(use_nonce().as_str()));
    assert_eq!(header(headers, "cache-control"), Some("no-store"));
    assert_eq!(
        headers
            .iter()
            .filter(|(n, _)| n == DPOP_NONCE_HEADER)
            .count(),
        1,
        "never more than one DPoP-Nonce (RFC 9449 §8)"
    );
    let nonce = nonce_of(headers);

    let retry = gate
        .check(
            &dpop_call(&at, proof(&at, "p-2", Some(&nonce), NOW)),
            NOW,
            "t",
        )
        .await;
    // The next nonce comes with the success (§8.2).
    nonce_of(allowed(&retry));
}

#[tokio::test]
async fn each_bad_nonce_is_a_401_with_a_fresh_one() {
    let gate = gate();
    let at = token();
    let n = nonces();
    let other = Nonces::new(&[0x6f; 32], 120).unwrap();
    for (i, (nonce, code)) in [
        ("x".to_owned(), "dpop.nonce_invalid"),
        (other.issue(NOW_I), "dpop.nonce_invalid"),
        (n.issue(NOW_I + 30), "dpop.nonce_invalid"),
        (n.issue(NOW_I - 120), "dpop.nonce_expired"),
    ]
    .into_iter()
    .enumerate()
    {
        let outcome = gate
            .check(
                &dpop_call(&at, proof(&at, &format!("b-{i}"), Some(&nonce), NOW)),
                NOW,
                "t",
            )
            .await;
        let (status, got, challenge, headers) = denied(&outcome);
        assert_eq!((status, got), (401, code), "case {i}");
        assert_eq!(challenge, Some(use_nonce().as_str()), "case {i}");
        nonce_of(headers);
    }
}

#[tokio::test]
async fn a_replayed_proof_with_a_good_nonce_is_still_refused() {
    let gate = gate();
    let at = token();
    let nonce = nonces().issue(NOW_I);
    let call = dpop_call(&at, proof(&at, "r-1", Some(&nonce), NOW));
    allowed(&gate.check(&call, NOW, "t").await);
    let again = gate.check(&call, NOW, "t").await;
    let (status, code, challenge, headers) = denied(&again);
    assert_eq!((status, code), (401, "dpop.replay"));
    assert_eq!(
        challenge,
        Some(format!(r#"DPoP error="invalid_dpop_proof", {ALGS}"#).as_str())
    );
    nonce_of(headers);
}

#[tokio::test]
async fn every_401_carries_a_nonce_and_nothing_else_does() {
    let gate = gate();
    // No credentials at all.
    let bare = gate.check(&input(Vec::new(), None), NOW, "t").await;
    let (status, code, _, headers) = denied(&bare);
    assert_eq!((status, code), (401, "credential.missing"));
    nonce_of(headers);
    // A broken bearer token.
    let bearer = gate
        .check(
            &input(vec![("authorization", "Bearer nope".into())], None),
            NOW,
            "t",
        )
        .await;
    nonce_of(denied(&bearer).3);
    // A 403 from the PDP: no nonce, no Cache-Control.
    let at = token_for("deny-me", NOW + 300);
    let nonce = nonces().issue(NOW_I);
    let forbidden = gate
        .check(
            &dpop_call(&at, proof(&at, "f-1", Some(&nonce), NOW)),
            NOW,
            "t",
        )
        .await;
    let (status, code, _, headers) = denied(&forbidden);
    assert_eq!((status, code), (403, "pdp.deny"));
    assert_eq!(headers, []);
    // A bearer caller that is allowed made no DPoP proof: no nonce.
    let plain = access_token("alice", "bearer-client", "files.read", AUDIENCE, NOW + 300);
    let ok = gate
        .check(
            &input(vec![("authorization", format!("Bearer {plain}"))], None),
            NOW,
            "t",
        )
        .await;
    assert_eq!(allowed(&ok), []);
}

#[tokio::test]
async fn without_nonces_nothing_changes() {
    let gate = gate_without_nonces();
    let at = token();
    let ok = gate
        .check(&dpop_call(&at, proof(&at, "w-1", None, NOW)), NOW, "t")
        .await;
    assert_eq!(allowed(&ok), []);
    let bare = gate.check(&input(Vec::new(), None), NOW, "t").await;
    assert_eq!(denied(&bare).3, []);
}

/// Root held by agent A (key 1), leaf held by agent B (key 2).
fn asor_chain() -> Vec<String> {
    let root = asor_sign(&asor_root_claims(
        "root-1",
        "spiffe://td.example/agent-a",
        &pop_key(1),
        &json!(["crm.*"]),
        &json!([]),
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
        &json!(["crm.read"]),
        &json!([]),
        AUDIENCE,
        NOW,
    ));
    vec![root, child]
}

/// Agent B calls `crm.read` with its WIT and WPT, the chain, and a leaf
/// proof carrying `nonce` if given.
fn asor_call(nonce: Option<&str>, n: u32) -> CheckInput {
    let chain = asor_chain();
    let key = pop_key(2);
    let w = wit("agent-b", &key);
    let p = wpt(&w, &key, URI, &format!("w{n}"), None, None);
    let header = json!({ "alg": "Ed25519", "typ": "dpop+jwt", "jwk": dpop_jwk(&key) });
    let mut claims = dpop_claims("POST", URI, chain.last().unwrap(), &format!("d{n}"), NOW);
    if let Some(nonce) = nonce {
        claims["nonce"] = Value::from(nonce);
    }
    let body = json!({ "jsonrpc": "2.0", "id": n, "method": "tools/call",
                       "params": { "name": "crm.read", "arguments": {} } });
    input(
        vec![
            ("agent-delegation-chain", chain.join(",")),
            ("authorization", format!("WPT {p}")),
            ("workload-identity-token", w),
            ("dpop", sign_dpop_proof(&header, &claims, &key)),
        ],
        Some(body.to_string()),
    )
}

#[tokio::test]
async fn an_asor_leaf_proof_needs_the_nonce_too() {
    let gate = gate();
    let first = gate.check(&asor_call(None, 1), NOW, "t").await;
    let (status, code, challenge, headers) = denied(&first);
    assert_eq!((status, code), (401, "dpop.nonce_missing"));
    // The leaf proof accepts Ed25519 and ES256 only, and says so.
    assert_eq!(challenge, Some(leaf_use_nonce()));
    let nonce = nonce_of(headers);

    let retry = gate.check(&asor_call(Some(&nonce), 2), NOW, "t").await;
    nonce_of(allowed(&retry));

    let forged = Nonces::new(&[1; 32], 120).unwrap().issue(NOW_I);
    let bad = gate.check(&asor_call(Some(&forged), 3), NOW, "t").await;
    assert_eq!(denied(&bad).1, "dpop.nonce_invalid");
}

#[tokio::test]
async fn an_asor_verifier_keeps_its_own_nonces() {
    // Nonces on the asor verifier only: the authenticator's absence does
    // not turn the leaf check off, and the gate hands out the verifier's.
    let mut cfg = config();
    cfg.asor = cfg.asor.map(|v| v.with_dpop_nonces(Some(nonces())));
    let gate = Gate::new(cfg, authenticator(), Pdp1);
    let first = gate.check(&asor_call(None, 1), NOW, "t").await;
    let (status, code, challenge, headers) = denied(&first);
    assert_eq!((status, code), (401, "dpop.nonce_missing"));
    assert_eq!(challenge, Some(leaf_use_nonce()));
    let nonce = nonce_of(headers);
    let retry = gate.check(&asor_call(Some(&nonce), 2), NOW, "t").await;
    nonce_of(allowed(&retry));

    // A DPoP-bound access token needs no nonce there, and gets none.
    let at = token();
    let ok = gate
        .check(&dpop_call(&at, proof(&at, "o-1", None, NOW)), NOW, "t")
        .await;
    assert_eq!(allowed(&ok), []);
}

fn leaf_use_nonce() -> &'static str {
    r#"DPoP error="use_dpop_nonce", algs="Ed25519 ES256""#
}

fn check_request(headers: HashMap<String, String>) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(Request {
                http: Some(HttpRequest {
                    method: "POST".into(),
                    host: HOST.into(),
                    path: "/mcp".into(),
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
async fn the_grpc_service_returns_the_nonce_headers() {
    let service = ExtAuthz::new(gate());
    // The service reads the real clock.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let at = token_for("mcp-client", 4_000_000_000);
    let send = |proof: String| {
        check_request(HashMap::from([
            ("authorization".to_owned(), format!("DPoP {at}")),
            ("dpop".to_owned(), proof),
        ]))
    };

    let first = service
        .check(tonic::Request::new(send(proof(&at, "g-1", None, now))))
        .await
        .unwrap()
        .into_inner();
    let Some(HttpResponse::DeniedResponse(denied)) = first.http_response else {
        panic!("denied")
    };
    assert_eq!(denied.status.unwrap().code, 401);
    assert!(denied.body.contains("dpop.nonce_missing"));
    let value = |name: &str| {
        denied
            .headers
            .iter()
            .filter_map(|h| h.header.as_ref())
            .find(|h| h.key == name)
            .map(|h| h.value.clone())
    };
    assert_eq!(value("www-authenticate"), Some(use_nonce()));
    assert_eq!(value("cache-control").as_deref(), Some("no-store"));
    let nonce = value(DPOP_NONCE_HEADER).expect("DPoP-Nonce on the 401");
    let now_i = i64::try_from(now).unwrap();
    assert!(nonces().check(&nonce, now_i + 2).is_ok());

    let retry = service
        .check(tonic::Request::new(send(proof(
            &at,
            "g-2",
            Some(&nonce),
            now,
        ))))
        .await
        .unwrap()
        .into_inner();
    let Some(HttpResponse::OkResponse(ok)) = retry.http_response else {
        panic!("allowed")
    };
    let next = ok
        .response_headers_to_add
        .iter()
        .find(|h| h.header.as_ref().unwrap().key == DPOP_NONCE_HEADER)
        .expect("DPoP-Nonce on the success");
    assert_eq!(
        next.append_action,
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32
    );
    assert!(
        nonces()
            .check(&next.header.as_ref().unwrap().value, now_i + 2)
            .is_ok()
    );
    // The nonce goes to the client, never upstream.
    assert!(
        ok.headers
            .iter()
            .all(|h| h.header.as_ref().unwrap().key != DPOP_NONCE_HEADER)
    );
}
