//! The invariant engine's own vectors: generates
//! `conformance/chain-invariants/vectors.json`, checks that the committed
//! file is current, and runs every case from the file with the algebras of
//! all three chain formats. Set `VISADO_REGENERATE=1` to rewrite the file
//! after an intended change.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use visado_chain::algebra::{Action, Algebras};
use visado_chain::invariants::Engine;
use visado_chain::{
    ActorId, Assurance, Authority, Cnf, Hop, KeyThumbprint, Link, NormalizedChain, Principal,
    Profile, SignerBinding, StatusCheck, TrustRef, Validity,
};

const ISSUER: &str = "https://as.example";
const AUD: &str = "https://tools.example";

// ---- the chains, as JSON ----

fn hop(i: usize, actor: &Value, authority: (&str, &str), max_depth: Option<u32>) -> Value {
    json!({
        "id": format!("jti-{i}"),
        "depth": i,
        "max_depth": max_depth,
        "actor": actor,
        "principal": { "issuer": ISSUER, "subject": "alice" },
        "delegator": null,
        "signer": "anchor",
        "signer_binding": "root_anchor",
        "link": "root",
        "authority": { "type": authority.0, "json": authority.1 },
        "validity": { "issued_at": 1000, "expires_at": 2000 - i64::try_from(i).unwrap() },
        "audience": [AUD],
        "cnf": format!("holder-{i}"),
        "status": null,
        "assurance": "verified",
    })
}

/// Links each hop after the first to its parent, the way `binding` says.
fn link(hops: &mut [Value], binding: &str) {
    for i in 1..hops.len() {
        let parent = hops[i - 1].clone();
        let hop = &mut hops[i];
        hop["delegator"] = parent["actor"].clone();
        hop["signer_binding"] = json!(binding);
        hop["link"] = json!({ "par_hash": format!("hash-{i}") });
        if binding == "parent_cnf" {
            hop["signer"] = parent["cnf"].clone();
        }
    }
}

fn chain(profile: &str, hops: Vec<Value>) -> Value {
    let mut chain = json!({
        "profile": profile,
        "principal": { "issuer": ISSUER, "subject": "alice" },
        "root": { "issuer": ISSUER, "key": "anchor" },
        "holder_proof": true,
    });
    chain["hops"] = Value::Array(hops);
    chain
}

const AAT_TOOLS: [&str; 3] = [
    r#"{"read":{"path":{"constraint_type":"one_of","values":["/a","/b"]}},"write":{}}"#,
    r#"{"read":{"path":{"constraint_type":"one_of","values":["/a","/b"]}}}"#,
    r#"{"read":{"path":{"constraint_type":"exact","value":"/a"}}}"#,
];

/// Three AAT hops, each signed by its parent's `cnf`, caps 4, 3, 3.
fn aat() -> Value {
    let mut hops: Vec<Value> = (0..3)
        .map(|i| {
            let actor = json!({ "key": format!("holder-{i}") });
            let cap = [4, 3, 3][i];
            hop(
                i,
                &actor,
                ("attenuating_agent_token", AAT_TOOLS[i]),
                Some(cap),
            )
        })
        .collect();
    link(&mut hops, "parent_cnf");
    chain("aat-02", hops)
}

const ASOR_DETAILS: [&str; 3] = [
    r#"{"constraints":[{"key":"rows","max":1000}],"scopes":["crm.*"],"type":"agent_delegation"}"#,
    r#"{"constraints":[{"key":"rows","max":100}],"scopes":["crm.read"],"type":"agent_delegation"}"#,
    r#"{"constraints":[{"key":"rows","max":100}],"scopes":["crm.read"],"type":"agent_delegation"}"#,
];

/// Three asor hops, all signed by the anchor, bounded by the first hop.
fn asor() -> Value {
    let mut hops: Vec<Value> = (0..3)
        .map(|i| {
            let name = ["orchestrator", "summarizer", "formatter"][i];
            let actor = json!({ "name": name });
            hop(i, &actor, ("agent_delegation", ASOR_DETAILS[i]), Some(2))
        })
        .collect();
    link(&mut hops, "root_anchor");
    chain("asor-03", hops)
}

/// An `act` claim: a declared prior actor and the verified current one,
/// nested in one token signed by the issuer.
fn act() -> Value {
    let mut hops: Vec<Value> = (0..2)
        .map(|i| {
            let actor = json!({ "issuer": ISSUER, "subject": format!("agent-{i}") });
            let mut h = hop(i, &actor, ("rfc8693-act", "{}"), None);
            h["id"] = json!("at-1");
            h["audience"] = Value::Null;
            h["cnf"] = Value::Null;
            h
        })
        .collect();
    link(&mut hops, "root_anchor");
    hops[1]["link"] = json!("nested");
    hops[0]["assurance"] = json!("declared");
    chain("rfc8693-act", hops)
}

// ---- the cases ----

fn action(name: &str, params: &Value) -> Value {
    json!({ "name": name, "params_json": params.to_string() })
}

fn aat_action() -> Value {
    action("read", &json!({ "path": "/a" }))
}

fn asor_action() -> Value {
    action("crm.read", &json!({ "rows": 50 }))
}

/// `base()` with each `(JSON pointer, value)` edit applied.
fn edited(base: fn() -> Value, edits: &[(&str, Value)]) -> Value {
    let mut chain = base();
    for (pointer, value) in edits {
        *chain.pointer_mut(pointer).expect(pointer) = value.clone();
    }
    chain
}

/// A case that must deny with `code` at `hop`, or that must be accepted
/// with the depth semantics named in `code` (and no hop).
fn case(
    name: &str,
    description: &str,
    chain: Value,
    action: Value,
    code: &str,
    hop: Option<usize>,
) -> Value {
    let mut case = json!({
        "name": name,
        "description": description,
        "check": "full",
        "expect": code,
        "hop": hop,
    });
    case["chain"] = chain;
    case["action"] = action;
    case
}

const UNCHECKED: &str = "unchecked";

fn accepted() -> Vec<Value> {
    let mut chain_only = case(
        "asor-without-a-request",
        "What needs no request: a decoded asor chain without holder proof, with a status reference not yet looked up.",
        edited(
            asor,
            &[
                ("/holder_proof", json!(false)),
                ("/hops/1/status", json!(UNCHECKED)),
            ],
        ),
        Value::Null,
        "asor-strict",
        None,
    );
    chain_only["check"] = json!("chain");
    vec![
        case(
            "aat-valid",
            "Three AAT hops narrowing read to one path.",
            aat(),
            aat_action(),
            "aat-holder-cap",
            None,
        ),
        case(
            "asor-valid",
            "Three asor hops narrowing crm.* to crm.read.",
            asor(),
            asor_action(),
            "asor-strict",
            None,
        ),
        case(
            "act-valid",
            "An act claim: a declared prior actor, the verified current one, no action.",
            act(),
            Value::Null,
            "uncapped",
            None,
        ),
        case(
            "aat-holder-repeats",
            "The leaf holder is the root holder again (AAT-02 §6.2 allows a holder to repeat).",
            edited(aat, &[("/hops/2/actor", json!({ "key": "holder-0" }))]),
            aat_action(),
            "aat-holder-cap",
            None,
        ),
        case(
            "aat-audience-inherited",
            "Hops without aud inherit their parent's restriction.",
            edited(
                aat,
                &[
                    ("/hops/1/audience", Value::Null),
                    ("/hops/2/audience", Value::Null),
                ],
            ),
            aat_action(),
            "aat-holder-cap",
            None,
        ),
        case(
            "asor-later-bound-ignored",
            "Under asor only the first hop's bound counts, so a later hop's smaller bound does not deny.",
            edited(asor, &[("/hops/1/max_depth", json!(1))]),
            asor_action(),
            "asor-strict",
            None,
        ),
        chain_only,
    ]
}

/// One denial: name, description, base chain, edits, action, code, hop.
type Denial = (
    &'static str,
    &'static str,
    fn() -> Value,
    Vec<(&'static str, Value)>,
    Value,
    &'static str,
    Option<usize>,
);

fn denials(list: Vec<Denial>) -> Vec<Value> {
    list.into_iter()
        .map(|(name, description, base, edits, action, code, hop)| {
            case(name, description, edited(base, &edits), action, code, hop)
        })
        .collect()
}

fn links_and_principal() -> Vec<Value> {
    denials(vec![
        (
            "empty",
            "No hops.",
            aat,
            vec![("/hops", json!([]))],
            aat_action(),
            "chain.malformed",
            None,
        ),
        (
            "depth-out-of-order",
            "The second hop says depth 2.",
            aat,
            vec![("/hops/1/depth", json!(2))],
            aat_action(),
            "chain.malformed",
            Some(1),
        ),
        (
            "root-not-anchor-signed",
            "The first hop's signer is not the trust anchor.",
            asor,
            vec![("/hops/0/signer", json!("other"))],
            asor_action(),
            "chain.link_mismatch",
            Some(0),
        ),
        (
            "signer-not-parent-cnf",
            "An AAT hop is signed by a key other than its parent's cnf.",
            aat,
            vec![("/hops/2/signer", json!("holder-0"))],
            aat_action(),
            "chain.link_mismatch",
            Some(2),
        ),
        (
            "delegator-not-parent",
            "A hop names the root's actor, not its parent's, as delegator.",
            asor,
            vec![("/hops/2/delegator", json!({ "name": "orchestrator" }))],
            asor_action(),
            "chain.link_mismatch",
            Some(2),
        ),
        (
            "nested-in-another-token",
            "A nested act hop has another token's identifier.",
            act,
            vec![("/hops/1/id", json!("at-2"))],
            Value::Null,
            "chain.link_mismatch",
            Some(1),
        ),
        (
            "principal-altered",
            "The leaf acts for another subject.",
            asor,
            vec![("/hops/2/principal/subject", json!("mallory"))],
            asor_action(),
            "chain.principal_altered",
            Some(2),
        ),
        (
            "exp-extended",
            "The leaf expires after its parent.",
            aat,
            vec![("/hops/2/validity/expires_at", json!(2001))],
            aat_action(),
            "chain.exp_extended",
            Some(2),
        ),
    ])
}

fn depth_audience_and_repeats() -> Vec<Value> {
    let all = |v: Value| {
        vec![
            ("/hops/0/max_depth", v.clone()),
            ("/hops/1/max_depth", v.clone()),
            ("/hops/2/max_depth", v),
        ]
    };
    denials(vec![
        (
            "aat-cap-raised",
            "An AAT hop raises its parent's cap.",
            aat,
            vec![("/hops/2/max_depth", json!(4))],
            aat_action(),
            "chain.depth_exceeded",
            Some(2),
        ),
        (
            "aat-beyond-own-cap",
            "An AAT hop is deeper than its own cap.",
            aat,
            vec![("/hops/2/max_depth", json!(1))],
            aat_action(),
            "chain.depth_exceeded",
            Some(2),
        ),
        (
            "asor-beyond-root-bound",
            "The asor leaf is deeper than the first hop's bound.",
            asor,
            all(json!(1)),
            asor_action(),
            "chain.depth_exceeded",
            Some(2),
        ),
        (
            "asor-no-root-bound",
            "The first asor hop has no bound.",
            asor,
            vec![("/hops/0/max_depth", Value::Null)],
            asor_action(),
            "chain.depth_exceeded",
            Some(0),
        ),
        (
            "audience-widened",
            "The leaf adds an audience its parent does not have.",
            asor,
            vec![("/hops/2/audience", json!([AUD, "https://other.example"]))],
            asor_action(),
            "chain.audience_widened",
            Some(2),
        ),
        (
            "audience-empty",
            "A hop restricts its audience to nothing.",
            aat,
            vec![("/hops/1/audience", json!([]))],
            aat_action(),
            "chain.audience_widened",
            Some(1),
        ),
        (
            "token-repeated",
            "The leaf token is the root token again.",
            asor,
            vec![("/hops/2/id", json!("jti-0"))],
            asor_action(),
            "chain.token_repeated",
            Some(2),
        ),
        (
            "declared-leaf",
            "The current act actor was never bound to the caller.",
            act,
            vec![("/hops/1/assurance", json!("declared"))],
            Value::Null,
            "chain.unverified",
            Some(1),
        ),
    ])
}

fn attenuation() -> Vec<Value> {
    let leaf = "/hops/2/authority/json";
    denials(vec![
        (
            "unknown-authority-type",
            "A verified hop's authority type has no algebra.",
            aat,
            vec![("/hops/1/authority/type", json!("payments"))],
            aat_action(),
            "chain.unknown_authority",
            Some(1),
        ),
        (
            "authority-type-changes",
            "An AAT hop carries an asor authority.",
            aat,
            vec![(
                "/hops/1/authority",
                json!({ "type": "agent_delegation", "json": ASOR_DETAILS[1] }),
            )],
            aat_action(),
            "chain.scope_escalation",
            Some(1),
        ),
        (
            "aat-tool-added",
            "An AAT hop grants a tool its parent does not.",
            aat,
            vec![(leaf, json!(r#"{"delete":{},"read":{}}"#))],
            aat_action(),
            "chain.scope_escalation",
            Some(2),
        ),
        (
            "aat-constraint-widened",
            "An AAT hop allows a path its parent does not.",
            aat,
            vec![(
                leaf,
                json!(r#"{"read":{"path":{"constraint_type":"exact","value":"/c"}}}"#),
            )],
            aat_action(),
            "chain.scope_escalation",
            Some(2),
        ),
        (
            "asor-scope-widened",
            "An asor hop adds a scope its parent does not cover.",
            asor,
            vec![(
                leaf,
                json!(
                    r#"{"constraints":[{"key":"rows","max":100}],"scopes":["crm.read","mail.send"],"type":"agent_delegation"}"#
                ),
            )],
            asor_action(),
            "chain.scope_escalation",
            Some(2),
        ),
        (
            "asor-constraint-dropped",
            "An asor hop drops its parent's row cap.",
            asor,
            vec![(
                leaf,
                json!(r#"{"scopes":["crm.read"],"type":"agent_delegation"}"#),
            )],
            asor_action(),
            "chain.scope_escalation",
            Some(2),
        ),
        (
            "asor-ceiling-raised",
            "An asor hop raises its parent's row cap.",
            asor,
            vec![(
                leaf,
                json!(
                    r#"{"constraints":[{"key":"rows","max":500}],"scopes":["crm.read"],"type":"agent_delegation"}"#
                ),
            )],
            asor_action(),
            "chain.scope_escalation",
            Some(2),
        ),
        (
            "act-authority-invented",
            "An act hop carries an authority RFC 8693 does not define.",
            act,
            vec![("/hops/1/authority/json", json!(r#"{"scope":"admin"}"#))],
            Value::Null,
            "chain.action_denied",
            Some(1),
        ),
    ])
}

fn request() -> Vec<Value> {
    denials(vec![
        (
            "status-unchecked",
            "A status reference was never looked up.",
            asor,
            vec![("/hops/1/status", json!(UNCHECKED))],
            asor_action(),
            "chain.status_unchecked",
            Some(1),
        ),
        (
            "no-holder-proof",
            "The presenter did not prove the leaf key.",
            aat,
            vec![("/holder_proof", json!(false))],
            aat_action(),
            "chain.no_holder_proof",
            None,
        ),
        (
            "aat-tool-not-granted",
            "The call is to a tool the leaf does not grant.",
            aat,
            vec![],
            action("write", &json!({})),
            "chain.action_denied",
            Some(2),
        ),
        (
            "aat-argument-outside",
            "The call's path is outside the leaf's constraint.",
            aat,
            vec![],
            action("read", &json!({ "path": "/b" })),
            "chain.action_denied",
            Some(2),
        ),
        (
            "aat-no-action",
            "An AAT chain is asked to authorize no action.",
            aat,
            vec![],
            Value::Null,
            "chain.action_denied",
            Some(2),
        ),
        (
            "asor-scope-not-granted",
            "The call's scope is not covered by the leaf.",
            asor,
            vec![],
            action("crm.write", &json!({ "rows": 1 })),
            "chain.action_denied",
            Some(2),
        ),
        (
            "asor-over-ceiling",
            "The call asks for more rows than the leaf allows.",
            asor,
            vec![],
            action("crm.read", &json!({ "rows": 101 })),
            "chain.action_denied",
            Some(2),
        ),
        (
            "act-asked-an-action",
            "An act chain is asked to authorize a tool call.",
            act,
            vec![],
            action("read", &json!({})),
            "chain.action_denied",
            Some(1),
        ),
    ])
}

fn build() -> Value {
    let cases: Vec<Value> = [
        accepted(),
        links_and_principal(),
        depth_audience_and_repeats(),
        attenuation(),
        request(),
    ]
    .concat();
    json!({
        "format": "visado-chain-invariants/v1",
        "suite": "chain-invariants",
        "spec": "visado docs/design.md, Delegation chain: the invariant engine and the authority algebras",
        "algebras": ["attenuating_agent_token", "agent_delegation", "rfc8693-act"],
        "cases": cases,
    })
}

// ---- reading the chains back ----

fn text(v: &Value) -> String {
    v.as_str().expect("string").to_owned()
}

fn principal(v: &Value) -> Principal {
    if v.is_null() {
        return Principal::Unspecified;
    }
    Principal::Subject {
        issuer: text(&v["issuer"]),
        subject: text(&v["subject"]),
    }
}

fn actor(v: &Value) -> ActorId {
    if let Some(key) = v.get("key") {
        ActorId::Key(KeyThumbprint(text(key)))
    } else if let Some(name) = v.get("name") {
        ActorId::Name(text(name))
    } else {
        ActorId::Subject {
            issuer: text(&v["issuer"]),
            subject: text(&v["subject"]),
        }
    }
}

fn read_hop(v: &Value) -> Hop {
    let max_depth = v["max_depth"].as_u64().map(|d| u32::try_from(d).unwrap());
    Hop {
        id: text(&v["id"]),
        depth: u32::try_from(v["depth"].as_u64().unwrap()).unwrap(),
        max_depth,
        actor: actor(&v["actor"]),
        principal: principal(&v["principal"]),
        delegator: (!v["delegator"].is_null()).then(|| actor(&v["delegator"])),
        signer: KeyThumbprint(text(&v["signer"])),
        signer_binding: match v["signer_binding"].as_str().unwrap() {
            "root_anchor" => SignerBinding::RootAnchor,
            _ => SignerBinding::ParentCnf,
        },
        link: match &v["link"] {
            Value::String(s) if s == "root" => Link::Root,
            Value::String(_) => Link::Nested,
            other => Link::ParHash(text(&other["par_hash"])),
        },
        authority: Authority {
            detail_type: text(&v["authority"]["type"]),
            json: text(&v["authority"]["json"]),
        },
        validity: Validity {
            issued_at: v["validity"]["issued_at"].as_i64().unwrap(),
            expires_at: v["validity"]["expires_at"].as_i64().unwrap(),
        },
        audience: v["audience"]
            .as_array()
            .map(|a| a.iter().map(text).collect()),
        cnf: v["cnf"].as_str().map(|t| Cnf {
            thumbprint: KeyThumbprint(t.to_owned()),
        }),
        status: v["status"].as_str().map(|s| match s {
            "valid" => StatusCheck::Valid,
            _ => StatusCheck::Unchecked,
        }),
        assurance: match v["assurance"].as_str().unwrap() {
            "verified" => Assurance::Verified,
            _ => Assurance::Declared,
        },
    }
}

fn read_chain(v: &Value) -> NormalizedChain {
    NormalizedChain {
        profile: match v["profile"].as_str().unwrap() {
            "aat-02" => Profile::Aat02,
            "asor-03" => Profile::Asor03,
            _ => Profile::Rfc8693Act,
        },
        principal: principal(&v["principal"]),
        root: TrustRef {
            issuer: text(&v["root"]["issuer"]),
            key: KeyThumbprint(text(&v["root"]["key"])),
        },
        hops: v["hops"].as_array().unwrap().iter().map(read_hop).collect(),
        holder_proof: v["holder_proof"].as_bool().unwrap(),
    }
}

/// Runs one case and returns what the engine said: a depth semantics name
/// on acceptance, the deny code otherwise, and the hop that failed.
fn run(engine: &Engine, case: &Value) -> (String, Value) {
    let chain = read_chain(&case["chain"]);
    let action = case["action"].as_object().map(|a| {
        (
            a["name"].as_str().unwrap().to_owned(),
            a["params_json"].as_str().unwrap().to_owned(),
        )
    });
    let action = action
        .as_ref()
        .map(|(name, params_json)| Action { name, params_json });
    let result = match case["check"].as_str().unwrap() {
        "chain" => engine.check_chain(&chain),
        _ => engine.check(&chain, action.as_ref()),
    };
    match result {
        Ok(checked) => (checked.depth_semantics.as_str().to_owned(), Value::Null),
        Err(e) => (e.invariant.code().to_owned(), json!(e.hop)),
    }
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/chain-invariants/vectors.json")
}

#[test]
fn vectors_are_fresh_and_pass() {
    let rendered = serde_json::to_string_pretty(&build()).unwrap() + "\n";
    if std::env::var_os("VISADO_REGENERATE").is_some() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), &rendered).unwrap();
    }
    let on_disk = std::fs::read_to_string(path()).expect("run with VISADO_REGENERATE=1 once");
    assert_eq!(
        on_disk, rendered,
        "vectors are stale; rerun with VISADO_REGENERATE=1"
    );
    let suite: Value = serde_json::from_str(&on_disk).unwrap();
    let engine = Engine::new(
        Algebras::new()
            .with(Arc::new(visado_chain_aat::Algebra::default()))
            .with(Arc::new(visado_chain_asor::Algebra::default()))
            .with(Arc::new(visado_chain_act::Algebra)),
    );
    let cases = suite["cases"].as_array().unwrap();
    let mut accepted = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let got = run(&engine, case);
        assert_eq!(got, (text(&case["expect"]), case["hop"].clone()), "{name}");
        accepted +=
            usize::from(case["hop"].is_null() && !text(&case["expect"]).starts_with("chain."));
    }
    assert_eq!((cases.len(), accepted), (39, 7));
}
