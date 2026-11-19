//! AAT chains through the gate, using vector J.1 from the published suite.
//! The orchestrator key in that suite is `pop_key(2)` in the testkit, so a
//! WIT can be bound to the chain's holder.

#![allow(clippy::unused_async_trait_impl)]

use std::collections::BTreeSet;

use serde_json::Value;
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_chain_aat::{TrustAnchor, Verifier};
use visado_credentials::{Authenticator, WitIssuer};
use visado_extauthz::{CheckInput, Gate, GateConfig, Outcome};
use visado_testkit::{TRUST_DOMAIN, pop_key, wit_at, wit_issuer_verifying_key, wpt_at};
use visado_txn_token::{KeySet, Scope, Validation, verify};
use wimsey_jose::{Jwk, SigningKey};

const HOST: &str = "tools.example.com";

/// Allows everything, and checks that the chain reached the PDP.
struct ChainPdp;

impl Pdp for ChainPdp {
    async fn evaluate(&self, request: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        let chain = &request.context.as_ref().unwrap()["chain"];
        assert_eq!(chain["profile"], "aat-02");
        Ok(Decision {
            allowed: true,
            context: None,
        })
    }
}

struct Vector {
    chain: Vec<String>,
    pop: String,
    tool: String,
    args: String,
    now: u64,
    anchors: Vec<TrustAnchor>,
    audience: String,
}

fn j1() -> Vector {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/aat/aat-jws-vectors.json"
    ))
    .unwrap();
    let suite: Value = serde_json::from_str(&text).unwrap();
    let vector = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "J.1")
        .unwrap();
    let anchors = suite["trust_anchors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let mut jwk = a["jwk"].clone();
            jwk["alg"] = "Ed25519".into();
            let jwk: Jwk = serde_json::from_value(jwk).unwrap();
            TrustAnchor::new(a["iss"].as_str().unwrap(), jwk.to_verifying_key().unwrap())
        })
        .collect();
    Vector {
        chain: vector["presentation"]["aat_chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect(),
        pop: vector["presentation"]["aat_pop"]
            .as_str()
            .unwrap()
            .to_owned(),
        tool: vector["tool"].as_str().unwrap().to_owned(),
        args: vector["args_json"].as_str().unwrap().to_owned(),
        now: vector["now"].as_u64().unwrap(),
        anchors,
        audience: suite["params"]["audience"].as_str().unwrap().to_owned(),
    }
}

fn txn_key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0x51; 32])
}

fn gate(v: &Vector) -> Gate<ChainPdp> {
    let config = GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: txn_key(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::new(),
        allowed_authorities: BTreeSet::from([HOST.to_owned()]),
        aat: Some(Verifier::new(v.anchors.clone(), vec![v.audience.clone()])),
        require_chain: false,
    };
    let authenticator = Authenticator::new().with_wit_issuer(
        WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
    );
    Gate::new(config, authenticator, ChainPdp)
}

/// An MCP `tools/call` from `workload` holding `seed`'s key, carrying the chain.
fn call(v: &Vector, seed: u8, jti: &str, tool: &str, args: &str) -> CheckInput {
    let pop = pop_key(seed);
    let wit = wit_at("spiffe://td.example/orchestrator", &pop, v.now);
    let wpt = wpt_at(
        &wit,
        &pop,
        &format!("https://{HOST}/mcp"),
        jti,
        None,
        None,
        v.now,
    );
    CheckInput {
        method: "POST".into(),
        scheme: "https".into(),
        authority: HOST.into(),
        path: "/mcp".into(),
        headers: vec![
            ("aat-chain".into(), v.chain.join(",")),
            ("aat-pop".into(), v.pop.clone()),
            ("authorization".into(), format!("WPT {wpt}")),
            ("workload-identity-token".into(), wit),
        ],
        body: Some(
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
            )
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
async fn a_valid_chain_from_its_holder_is_allowed() {
    let v = j1();
    let gate = gate(&v);
    let outcome = gate
        .check(&call(&v, 2, "w1", &v.tool, &v.args), v.now, "txn-aat")
        .await;
    let Outcome::Allow { set, remove, .. } = &outcome else {
        panic!("{outcome:?}")
    };
    let keys = KeySet::new().with_key("txn-1", txn_key().verifying_key());
    let claims = verify(&set[0].1, &keys, &Validation::new(TRUST_DOMAIN, v.now))
        .unwrap()
        .claims;
    assert_eq!(claims.tctx.unwrap()["chain"]["profile"], "aat-02");
    assert!(remove.contains(&"aat-chain".to_owned()));
    assert!(remove.contains(&"aat-pop".to_owned()));
}

#[tokio::test]
async fn rejections() {
    let v = j1();

    // The same chain and proof from a workload holding a different key.
    let gate = gate(&v);
    let other = gate
        .check(&call(&v, 9, "w2", &v.tool, &v.args), v.now, "t")
        .await;
    assert_eq!(code(&other), "chain.holder_mismatch");

    // Arguments other than the ones the proof covers.
    let gate = self::gate(&v);
    let changed = gate
        .check(
            &call(&v, 2, "w3", &v.tool, r#"{"path":"/etc/passwd"}"#),
            v.now,
            "t",
        )
        .await;
    assert!(code(&changed).starts_with("aat."), "{}", code(&changed));

    // The proof is single-use per gate.
    let gate = self::gate(&v);
    assert_eq!(
        code(
            &gate
                .check(&call(&v, 2, "w4", &v.tool, &v.args), v.now, "t")
                .await
        ),
        "allow"
    );
    let again = gate
        .check(&call(&v, 2, "w5", &v.tool, &v.args), v.now, "t")
        .await;
    assert!(code(&again).starts_with("aat."), "{}", code(&again));

    // A chain where AAT is not configured.
    let pop = pop_key(2);
    let wit = wit_at("spiffe://td.example/orchestrator", &pop, v.now);
    let mut config = GateConfig {
        trust_domain: TRUST_DOMAIN.into(),
        signing_key: txn_key(),
        kid: "txn-1".into(),
        txn_lifetime: 60,
        default_scope: Scope::parse("tools.call"),
        internal_callers: BTreeSet::new(),
        allowed_authorities: BTreeSet::new(),
        aat: None,
        require_chain: false,
    };
    config.allowed_authorities.insert(HOST.to_owned());
    let plain = Gate::new(
        config,
        Authenticator::new().with_wit_issuer(
            WitIssuer::new(TRUST_DOMAIN).with_key("wit-1", wit_issuer_verifying_key()),
        ),
        ChainPdp,
    );
    let mut request = call(&v, 2, "w6", &v.tool, &v.args);
    let wpt = wpt_at(
        &wit,
        &pop,
        &format!("https://{HOST}/mcp"),
        "w6b",
        None,
        None,
        v.now,
    );
    request
        .headers
        .retain(|(n, _)| n != "authorization" && n != "workload-identity-token");
    request
        .headers
        .push(("authorization".into(), format!("WPT {wpt}")));
    request
        .headers
        .push(("workload-identity-token".into(), wit));
    assert_eq!(
        code(&plain.check(&request, v.now, "t").await),
        "chain.unsupported"
    );
}
