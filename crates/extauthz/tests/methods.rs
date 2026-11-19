//! The gate with callers that authenticate by other methods than a WPT or a
//! bearer access token.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_aat::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, WitIssuer, X509Bundle};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{
    AAT_ISSUER, NOW, SignatureSpec, TRUST_DOMAIN, aat_anchor_key, aat_pop, aat_root,
    certificate_pem, content_digest, envoy_peer_certificate, http_signature, pop_key, wic, wit,
    wit_issuer_verifying_key, workload_ca,
};
use visado_txn_token::{KeySet, Scope, TxnTokenClaims, Validation, verify};
use wimsey_jose::SigningKey;

const HOST: &str = "tools.td.example";
const AAT_AUDIENCE: &str = "https://tools.td.example";

type Seen = Arc<Mutex<Option<EvaluationRequest>>>;

/// Allows everything and remembers the last request.
struct RecordingPdp(Seen);

impl Pdp for RecordingPdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        if let Ok(mut last) = self.0.lock() {
            *last = Some(request.clone());
        }
        Ok(Decision {
            allowed: true,
            context: None,
        })
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
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::from(["spiffe://td.example/agent-a".to_owned()]),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: Some(Verifier::new(
            vec![TrustAnchor::new(
                AAT_ISSUER,
                aat_anchor_key().verifying_key(),
            )],
            vec![AAT_AUDIENCE.to_owned()],
        )),
        require_chain: false,
    }
}

fn authenticator() -> Authenticator {
    let ca = certificate_pem(workload_ca().certificate_der());
    Authenticator::new()
        .with_wit_issuer(WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()))
        .with_x509_bundle(X509Bundle::from_pem(TRUST_DOMAIN, &ca).unwrap())
}

fn gate() -> Gate<RecordingPdp> {
    gate_with(authenticator()).0
}

fn gate_with(authenticator: Authenticator) -> (Gate<RecordingPdp>, Seen) {
    let seen = Seen::default();
    let gate = Gate::new(config(), authenticator, RecordingPdp(seen.clone()));
    (gate, seen)
}

fn input(path: &str, headers: Vec<(String, String)>, body: Option<Vec<u8>>) -> CheckInput {
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: path.into(),
        headers,
        body,
        peer_certificate: None,
    }
}

/// A request from `workload` (key `seed`) signed over `headers`, `body` bound
/// by a covered `Content-Digest` when present.
fn signed_call(
    workload: &str,
    seed: u8,
    nonce: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> CheckInput {
    let pop = pop_key(seed);
    let w = wit(workload, &pop);
    let digest = body.map(content_digest);
    let mut all: Vec<(&str, &str)> = headers.to_vec();
    all.push(("workload-identity-token", &w));
    if let Some(digest) = &digest {
        all.push(("content-digest", digest));
    }
    let spec = SignatureSpec {
        nonce,
        created: NOW,
        audience: &format!("https://{HOST}/mcp"),
        cover: &[],
    };
    let (signature_input, signature) = http_signature("POST", HOST, "/mcp", &all, &pop, &spec);
    let mut headers: Vec<(String, String)> = all
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    headers.push(("signature-input".into(), signature_input));
    headers.push(("signature".into(), signature));
    input("/mcp", headers, body.map(<[u8]>::to_vec))
}

fn minted(outcome: &Outcome) -> TxnTokenClaims {
    let Outcome::Allow { set, .. } = outcome else {
        panic!("expected allow, got {outcome:?}")
    };
    let token = &set.iter().find(|(n, _)| n == "txn-token").unwrap().1;
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    verify(token, &keys, &Validation::new(TRUST_DOMAIN, NOW + 1))
        .unwrap()
        .claims
}

fn denied(outcome: &Outcome) -> (u16, &str, Option<&str>) {
    match outcome {
        Outcome::Deny {
            status,
            code,
            challenge,
        } => (*status, code.as_str(), challenge.as_deref()),
        Outcome::Allow { .. } => panic!("expected deny"),
    }
}

/// `auth_method` as the PDP saw it and as the token records it, and `req_wl`.
fn auth_method(seen: &Seen, outcome: &Outcome) -> (Value, Value, String) {
    let claims = minted(outcome);
    let tctx = claims.tctx.unwrap_or_default();
    let pdp = seen
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|r| r.context.as_ref())
        .map_or(Value::Null, |c| c["auth_method"].clone());
    (
        pdp,
        tctx.get("auth_method").cloned().unwrap_or(Value::Null),
        claims.req_wl,
    )
}

#[tokio::test]
async fn a_signed_request_gets_a_transaction_token() {
    let (gate, seen) = gate_with(authenticator());
    let outcome = gate
        .check(&signed_call("agent-b", 2, "n1", &[], None), NOW, "t1")
        .await;
    let (pdp, token, req_wl) = auth_method(&seen, &outcome);
    assert_eq!(pdp, json!("wit-httpsig"));
    assert_eq!(token, json!("wit-httpsig"));
    assert_eq!(req_wl, "spiffe://td.example/agent-b");
    let Outcome::Allow { remove, .. } = &outcome else {
        unreachable!()
    };
    for header in ["signature", "signature-input", "workload-identity-token"] {
        assert!(remove.contains(&header.to_owned()), "{header} is removed");
    }
}

#[tokio::test]
async fn a_failed_signature_is_a_400_without_a_challenge() {
    let gate = gate();
    let mut call = signed_call("agent-b", 2, "n2", &[], None);
    call.path = "/mcp?changed=1".into();
    let outcome = gate.check(&call, NOW, "t").await;
    assert_eq!(denied(&outcome), (400, "httpsig.invalid", None));
}

#[tokio::test]
async fn an_internal_caller_may_forward_a_covered_transaction_token() {
    let gate = gate();
    let first = gate
        .check(&signed_call("agent-b", 2, "n3", &[], None), NOW, "t-fwd")
        .await;
    let Outcome::Allow { set, .. } = &first else {
        panic!("{first:?}")
    };
    let token = set[0].1.clone();

    let forwarded = gate
        .check(
            &signed_call("agent-a", 1, "n4", &[("txn-token", &token)], None),
            NOW,
            "t-new",
        )
        .await;
    assert_eq!(minted(&forwarded).txn, "t-fwd");

    // Not an internal caller.
    let outsider = gate
        .check(
            &signed_call("agent-b", 2, "n5", &[("txn-token", &token)], None),
            NOW,
            "t",
        )
        .await;
    assert_eq!(denied(&outsider).1, "txn.untrusted_hop");
}

#[tokio::test]
async fn a_signed_caller_holds_an_aat_chain_with_its_wit_key() {
    let gate = gate();
    let tools = json!({ "read_file": { "path": { "constraint_type": "wildcard" } } });
    let args = json!({ "path": "/data/report.pdf" });
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": { "name": "read_file", "arguments": args } })
    .to_string();

    let call = |seed: u8, holder: u8, n: &str| {
        let root = aat_root(
            &format!("root-{n}"),
            &pop_key(holder),
            &tools,
            NOW,
            1,
            AAT_AUDIENCE,
        );
        let pop = aat_pop(
            &format!("pop-{n}"),
            &root,
            &format!("root-{n}"),
            &pop_key(holder),
            "read_file",
            &args,
            AAT_AUDIENCE,
            NOW,
        );
        signed_call(
            "agent-b",
            seed,
            n,
            &[("aat-chain", &root), ("aat-pop", &pop)],
            Some(body.as_bytes()),
        )
    };

    let outcome = gate.check(&call(2, 2, "c1"), NOW, "t").await;
    assert!(minted(&outcome).tctx.unwrap().contains_key("chain"));

    // A chain held by another key.
    let outcome = gate.check(&call(2, 3, "c2"), NOW, "t").await;
    assert_eq!(denied(&outcome).1, "chain.holder_mismatch");
}

/// A request over mTLS from `workload` with key `seed`.
fn mtls_call(workload: &str, seed: u8, headers: &[(&str, &str)], body: Option<&str>) -> CheckInput {
    let id = format!("spiffe://{TRUST_DOMAIN}/{workload}");
    let cert = envoy_peer_certificate(&wic(&id, &pop_key(seed).verifying_key()));
    let headers = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let mut call = input("/mcp", headers, body.map(|b| b.as_bytes().to_vec()));
    call.peer_certificate = Some(cert);
    call
}

#[tokio::test]
async fn an_mtls_caller_gets_a_transaction_token() {
    let (gate, seen) = gate_with(authenticator());
    let outcome = gate
        .check(&mtls_call("agent-b", 2, &[], None), NOW, "m1")
        .await;
    let (pdp, token, req_wl) = auth_method(&seen, &outcome);
    assert_eq!(pdp, json!("mtls"));
    assert_eq!(token, json!("mtls"));
    assert_eq!(req_wl, "spiffe://td.example/agent-b");

    // An internal caller over mTLS may forward the token.
    let Outcome::Allow { set, .. } = &outcome else {
        unreachable!()
    };
    let forwarded = gate
        .check(
            &mtls_call("agent-a", 1, &[("txn-token", &set[0].1)], None),
            NOW,
            "m2",
        )
        .await;
    assert_eq!(minted(&forwarded).txn, "m1");

    // A certificate from another CA is a 401 without a challenge.
    let mut forged = mtls_call("agent-b", 2, &[], None);
    let other = wimsey_mtls::WorkloadCa::from_ed25519(&pop_key(0x99), NOW - 60, NOW + 60).unwrap();
    let der = other
        .issue(
            &wimsey_identifier::WorkloadIdentifier::parse("spiffe://td.example/agent-b").unwrap(),
            &pop_key(2).verifying_key(),
            NOW - 60,
            NOW + 60,
        )
        .unwrap();
    forged.peer_certificate = Some(envoy_peer_certificate(&der));
    let outcome = gate.check(&forged, NOW, "t").await;
    assert_eq!(denied(&outcome), (401, "mtls.invalid", None));
}

#[tokio::test]
async fn an_mtls_caller_holds_an_aat_chain_with_its_certificate_key() {
    let gate = gate();
    let tools = json!({ "read_file": { "path": { "constraint_type": "wildcard" } } });
    let args = json!({ "path": "/data/report.pdf" });
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": { "name": "read_file", "arguments": args } })
    .to_string();
    let call = |holder: u8, n: &str| {
        let root = aat_root(
            &format!("root-{n}"),
            &pop_key(holder),
            &tools,
            NOW,
            1,
            AAT_AUDIENCE,
        );
        let pop = aat_pop(
            &format!("pop-{n}"),
            &root,
            &format!("root-{n}"),
            &pop_key(holder),
            "read_file",
            &args,
            AAT_AUDIENCE,
            NOW,
        );
        mtls_call(
            "agent-b",
            2,
            &[("aat-chain", &root), ("aat-pop", &pop)],
            Some(&body),
        )
    };
    let outcome = gate.check(&call(2, "m1"), NOW, "t").await;
    assert!(minted(&outcome).tctx.unwrap().contains_key("chain"));
    let outcome = gate.check(&call(3, "m2"), NOW, "t").await;
    assert_eq!(denied(&outcome).1, "chain.holder_mismatch");
}
