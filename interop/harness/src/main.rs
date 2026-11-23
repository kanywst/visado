//! Command-line harness for interop runs against other implementations.
//!
//! Each subcommand reads JSON on standard input or from a file and writes
//! JSON to standard output, so a script in another language can drive it.
//! See `interop/README.md`.
//!
//! - `aat-suite <file>`: runs the AAT JWS vector suite and prints the verdicts
//!   in the format of the suite's `compare_results.py`.
//! - `aat-mint`: prints AAT chains minted by visado's test fixtures, with
//!   visado's own verdict for each.
//! - `asor-mint`: the same for asor Delegation Chains.
//! - `asor-verify`: verifies asor chains given on standard input.

use std::collections::BTreeSet;
use std::io::Read;
use std::process::ExitCode;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use visado_chain::{jose, json};
use visado_chain_aat as aat;
use visado_chain_asor as asor;
use visado_testkit as kit;
use wimsey_jose::{Algorithm, Jwk, SigningKey, VerifyingKey};

/// The time every minted chain is issued at and checked at.
const NOW: u64 = 1_800_000_000;
/// The enforcement point the minted chains name.
const AUDIENCE: &str = "https://tools.example.com";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.first().map(String::as_str) {
        Some("aat-suite") => match args.get(1) {
            Some(path) => read_file(path).map(|s| aat_suite(&s)),
            None => Err("usage: visado-interop aat-suite <suite.json>".to_owned()),
        },
        Some("aat-mint") => Ok(aat_mint()),
        Some("asor-mint") => Ok(asor_mint()),
        Some("asor-verify") => stdin().map(|input| asor_verify(&input)),
        _ => Err(
            "usage: visado-interop <aat-suite FILE | aat-mint | asor-mint | asor-verify>"
                .to_owned(),
        ),
    };
    match out {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).expect("json"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("visado-interop: {e}");
            ExitCode::from(2)
        }
    }
}

fn read_file(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn stdin() -> Result<Value, String> {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn now() -> i64 {
    i64::try_from(NOW).expect("time")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn ed25519(x: &str) -> Result<VerifyingKey, String> {
    let raw = URL_SAFE_NO_PAD.decode(x).map_err(|e| e.to_string())?;
    VerifyingKey::from_raw_bytes(Algorithm::Ed25519, &raw).map_err(|e| e.to_string())
}

/// The public JWK of `key`, without `alg`.
fn public_jwk(key: &SigningKey) -> Value {
    let mut jwk = serde_json::to_value(Jwk::from_verifying_key(&key.verifying_key())).expect("jwk");
    if let Some(o) = jwk.as_object_mut() {
        o.remove("alg");
    }
    jwk
}

// ---------------------------------------------------------------------------
// AAT
// ---------------------------------------------------------------------------

/// Runs every vector of the suite at `suite` and returns
/// `{"<id>": {"verdict": "PERMIT"|"DENY", "step": ...}}`.
fn aat_suite(suite: &Value) -> Value {
    let anchors: Vec<aat::TrustAnchor> = suite["trust_anchors"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let key = ed25519(a["jwk"]["x"].as_str().unwrap_or_default()).expect("anchor key");
            aat::TrustAnchor::new(a["iss"].as_str().unwrap_or_default(), key)
        })
        .collect();
    let audience = suite["params"]["audience"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let mut results = Map::new();
    for vector in suite["vectors"].as_array().into_iter().flatten() {
        let param = |name: &str| {
            vector["params"]
                .get(name)
                .or_else(|| suite["params"].get(name))
                .and_then(Value::as_i64)
                .unwrap_or_default()
        };
        let size = |name: &str| usize::try_from(param(name)).unwrap_or_default();
        let limits = aat::Limits {
            max_iat_skew: param("max_iat_skew"),
            max_token_lifetime: param("max_token_lifetime"),
            max_delegation_depth: u32::try_from(param("max_delegation_depth")).unwrap_or_default(),
            max_constraint_depth: size("max_constraint_depth"),
            max_constraint_nodes: aat::Limits::default().max_constraint_nodes,
            max_token_size: size("max_token_size"),
            max_chain_size: size("max_chain_size"),
            pop_window: param("pop_window"),
            // visado's own default is stricter about the future; the vectors
            // test the draft, as in crates/chain-aat/tests/vectors.rs.
            pop_max_future: param("pop_window"),
        };
        let p = &vector["policy"];
        let policy = aat::Policy {
            require_chain_aud: p["require_chain_aud"].as_bool().unwrap_or(false),
            require_pop_aud: p["require_pop_aud"].as_bool().unwrap_or(false),
            nonces: p["nonce"].as_str().map(|n| BTreeSet::from([n.to_owned()])),
        };
        let verifier = aat::Verifier::new(anchors.clone(), vec![audience.clone()])
            .with_limits(limits)
            .with_policy(policy);
        let now = vector["now"].as_i64().unwrap_or_default();
        let cache = aat::MemoryReplayCache::new(1024);
        let seen = strings(&vector["replay_state"]["before"]);
        if let Some(holder) = leaf_holder(&strings(&vector["presentation"]["aat_chain"])) {
            for jti in seen {
                let recorded =
                    aat::ReplayCache::check_and_record(&cache, &holder, &jti, now + 60, now);
                assert!(recorded.is_fresh(), "pre-seeded jti {jti} was not fresh");
            }
        }
        let tracked = p["track_pop_jti"].as_bool().unwrap_or(false);
        let replay: Option<&dyn aat::ReplayCache> = if tracked { Some(&cache) } else { None };
        let chain = strings(&vector["presentation"]["aat_chain"]);
        let result = verifier.verify(
            &aat::Presentation {
                chain: &chain,
                pop: vector["presentation"]["aat_pop"]
                    .as_str()
                    .unwrap_or_default(),
            },
            &aat::Invocation {
                tool: vector["tool"].as_str().unwrap_or_default(),
                args_json: vector["args_json"].as_str().unwrap_or_default(),
            },
            now,
            replay,
        );
        let id = vector["id"].as_str().unwrap_or_default().to_owned();
        let verdict = match result {
            Ok(_) => json!("PERMIT"),
            Err(e) => json!({ "verdict": "DENY", "step": e.step().as_str() }),
        };
        results.insert(id, verdict);
    }
    Value::Object(results)
}

/// One minted AAT case: the chain, the proof and the call.
struct AatCase {
    id: &'static str,
    note: &'static str,
    chain: Vec<String>,
    pop: String,
    tool: &'static str,
    args: Value,
}

// A flat list of cases reads better than one split across helpers.
#[allow(clippy::too_many_lines)]
fn aat_cases() -> Vec<AatCase> {
    let a = kit::pop_key(11);
    let b = kit::pop_key(12);
    let c = kit::pop_key(13);
    let other = kit::pop_key(14);
    let root_tools = json!({
        "read_file": { "path": { "constraint_type": "wildcard" } },
        "delete_file": { "path": { "constraint_type": "wildcard" } },
    });
    let child_tools = json!({
        "read_file": { "path": { "constraint_type": "one_of", "values": ["/data/report.pdf", "/data/q3.csv"] } },
    });
    let root = kit::aat_root("v-root", &a, &root_tools, NOW, 3, AUDIENCE);
    let child = kit::aat_child("v-child", &root, &a, &b, &child_tools, 1, 3, NOW);
    let read = |path: &str| json!({ "path": path });
    let pop =
        |jti: &str, leaf: &str, leaf_jti: &str, key: &SigningKey, tool: &str, args: &Value| {
            kit::aat_pop(jti, leaf, leaf_jti, key, tool, args, AUDIENCE, NOW)
        };

    let grandchild_tools = json!({
        "read_file": { "path": { "constraint_type": "exact", "value": "/data/q3.csv" } },
    });
    let grandchild = kit::aat_child("v-grand", &child, &b, &c, &grandchild_tools, 2, 3, NOW);
    let widened = kit::aat_child(
        "v-wide",
        &root,
        &a,
        &b,
        &json!({ "write_file": { "path": { "constraint_type": "wildcard" } } }),
        1,
        3,
        NOW,
    );
    let other_root = kit::aat_root("v-root-2", &a, &root_tools, NOW, 3, AUDIENCE);
    let spliced = kit::aat_child("v-splice", &other_root, &a, &b, &child_tools, 1, 3, NOW);
    let shallow_root = kit::aat_root("v-root-3", &a, &root_tools, NOW, 1, AUDIENCE);
    let shallow_child = kit::aat_child("v-sc", &shallow_root, &a, &b, &child_tools, 1, 1, NOW);
    let too_deep = kit::aat_child(
        "v-deep",
        &shallow_child,
        &b,
        &c,
        &grandchild_tools,
        2,
        1,
        NOW,
    );

    vec![
        AatCase {
            id: "V.1",
            note: "two hops, call within the child's one_of",
            pop: pop(
                "p1",
                &child,
                "v-child",
                &b,
                "read_file",
                &read("/data/report.pdf"),
            ),
            chain: vec![root.clone(), child.clone()],
            tool: "read_file",
            args: read("/data/report.pdf"),
        },
        AatCase {
            id: "V.2",
            note: "three hops, exact narrows one_of",
            pop: pop(
                "p2",
                &grandchild,
                "v-grand",
                &c,
                "read_file",
                &read("/data/q3.csv"),
            ),
            chain: vec![root.clone(), child.clone(), grandchild.clone()],
            tool: "read_file",
            args: read("/data/q3.csv"),
        },
        AatCase {
            id: "V.3",
            note: "argument outside the child's one_of",
            pop: pop(
                "p3",
                &child,
                "v-child",
                &b,
                "read_file",
                &read("/etc/passwd"),
            ),
            chain: vec![root.clone(), child.clone()],
            tool: "read_file",
            args: read("/etc/passwd"),
        },
        AatCase {
            id: "V.4",
            note: "tool granted by the root but not by the leaf",
            pop: pop(
                "p4",
                &child,
                "v-child",
                &b,
                "delete_file",
                &read("/data/report.pdf"),
            ),
            chain: vec![root.clone(), child.clone()],
            tool: "delete_file",
            args: read("/data/report.pdf"),
        },
        AatCase {
            id: "V.5",
            note: "child adds a tool its parent does not grant",
            pop: pop("p5", &widened, "v-wide", &b, "write_file", &read("/x")),
            chain: vec![root.clone(), widened],
            tool: "write_file",
            args: read("/x"),
        },
        AatCase {
            id: "V.6",
            note: "PoP signed by a key that is not the leaf cnf",
            pop: pop(
                "p6",
                &child,
                "v-child",
                &other,
                "read_file",
                &read("/data/report.pdf"),
            ),
            chain: vec![root.clone(), child.clone()],
            tool: "read_file",
            args: read("/data/report.pdf"),
        },
        AatCase {
            id: "V.7",
            note: "child's par_hash commits to another root",
            pop: pop(
                "p7",
                &spliced,
                "v-splice",
                &b,
                "read_file",
                &read("/data/report.pdf"),
            ),
            chain: vec![root.clone(), spliced],
            tool: "read_file",
            args: read("/data/report.pdf"),
        },
        AatCase {
            id: "V.8",
            note: "chain deeper than the root's del_max_depth",
            pop: pop(
                "p8",
                &too_deep,
                "v-deep",
                &c,
                "read_file",
                &read("/data/q3.csv"),
            ),
            chain: vec![shallow_root, shallow_child, too_deep],
            tool: "read_file",
            args: read("/data/q3.csv"),
        },
        AatCase {
            id: "V.9",
            note: "PoP hta differs from the call's arguments",
            pop: pop(
                "p9",
                &child,
                "v-child",
                &b,
                "read_file",
                &read("/data/q3.csv"),
            ),
            chain: vec![root, child],
            tool: "read_file",
            args: read("/data/report.pdf"),
        },
    ]
}

/// AAT chains minted by visado's fixtures, with visado's own verdict.
fn aat_mint() -> Value {
    let anchor = aat::TrustAnchor::new(kit::AAT_ISSUER, kit::aat_anchor_key().verifying_key());
    let verifier = aat::Verifier::new(vec![anchor], vec![AUDIENCE.to_owned()]);
    let cases: Vec<Value> = aat_cases()
        .into_iter()
        .map(|case| {
            let args_json = serde_json::to_string(&case.args).expect("json");
            let result = verifier.verify(
                &aat::Presentation {
                    chain: &case.chain,
                    pop: &case.pop,
                },
                &aat::Invocation {
                    tool: case.tool,
                    args_json: &args_json,
                },
                now(),
                None,
            );
            let visado = match result {
                Ok(_) => json!({ "verdict": "PERMIT" }),
                Err(e) => json!({ "verdict": "DENY", "step": e.step().as_str() }),
            };
            json!({
                "id": case.id, "note": case.note, "chain": case.chain, "pop": case.pop,
                "tool": case.tool, "args_json": args_json, "visado": visado,
            })
        })
        .collect();
    json!({
        "minted_by": format!("visado-testkit {}", env!("CARGO_PKG_VERSION")),
        "now": NOW,
        "audience": AUDIENCE,
        "trust_anchors": [{ "iss": kit::AAT_ISSUER, "jwk": public_jwk(&kit::aat_anchor_key()) }],
        "cases": cases,
    })
}

// ---------------------------------------------------------------------------
// asor
// ---------------------------------------------------------------------------

fn asor_outcome(result: Result<(), asor::AsorError>) -> Value {
    match result {
        Ok(()) => json!({ "verdict": "accept" }),
        Err(e) => json!({ "verdict": "reject", "reason": e.outcome().as_str() }),
    }
}

/// Verifies the asor chains on standard input:
///
/// ```json
/// {"anchor": {"iss": "...", "kid": "...", "x": "<Ed25519 public key>"},
///  "audience": "...",
///  "cases": [{"id": "...", "tokens": ["..."], "now": 0,
///             "request": {"dpop": "...", "method": "POST", "uri": "...",
///                         "scope": "...", "params": {}}}]}
/// ```
///
/// A case without `request` runs [`asor::Verifier::check`]; one with it runs
/// [`asor::Verifier::verify`], DPoP included.
fn asor_verify(input: &Value) -> Value {
    let anchor = &input["anchor"];
    let key = match ed25519(anchor["x"].as_str().unwrap_or_default()) {
        Ok(key) => key,
        Err(e) => return json!({ "error": e }),
    };
    let mut trust = asor::TrustAnchor::new(anchor["iss"].as_str().unwrap_or_default(), key);
    if let Some(kid) = anchor["kid"].as_str() {
        trust = trust.with_kid(kid);
    }
    let audience = input["audience"].as_str().unwrap_or_default().to_owned();
    let verifier = asor::Verifier::new(vec![trust], vec![audience]);
    let results: Vec<Value> = input["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|case| {
            let tokens = strings(&case["tokens"]);
            let now = case["now"].as_i64().unwrap_or_default();
            let request = &case["request"];
            let result = if request.is_object() {
                let params = serde_json::to_string(&request["params"]).expect("json");
                verifier
                    .verify(
                        &asor::Presentation {
                            chain: &tokens,
                            dpop: request["dpop"].as_str().unwrap_or_default(),
                        },
                        &asor::HttpRequest {
                            method: request["method"].as_str().unwrap_or_default(),
                            uri: request["uri"].as_str().unwrap_or_default(),
                        },
                        &asor::Action {
                            scope: request["scope"].as_str().unwrap_or_default(),
                            params_json: &params,
                            totals: None,
                        },
                        now,
                        None,
                    )
                    .map(|_| ())
            } else {
                verifier.check(&tokens, now).map(|_| ())
            };
            let mut out = asor_outcome(result);
            out["id"] = case["id"].clone();
            out
        })
        .collect();
    json!({ "results": results })
}

/// asor chains minted by visado's fixtures, with visado's own verdict from
/// [`asor::Verifier::check`] (the vectors' profile: no request).
#[allow(clippy::too_many_lines)]
fn asor_mint() -> Value {
    let holder = [kit::pop_key(21), kit::pop_key(22), kit::pop_key(23)];
    let root = |max_depth: u32, scopes: &Value, constraints: &Value| {
        kit::asor_root_claims(
            "v-root",
            "orchestrator",
            &holder[0],
            scopes,
            constraints,
            AUDIENCE,
            NOW,
            max_depth,
        )
    };
    let child = |jti: &str, parent: &str, depth: u32, scopes: &Value, constraints: &Value| {
        kit::asor_child_claims(
            jti,
            "reader",
            parent,
            &holder[usize::try_from(depth).expect("depth")],
            depth,
            scopes,
            constraints,
            AUDIENCE,
            NOW,
        )
    };
    let rows = |max: u32| json!([{ "key": "rows", "max": max }]);
    let r = kit::asor_sign(&root(5, &json!(["crm.*"]), &rows(1000)));
    let c = kit::asor_sign(&child("v-child", &r, 1, &json!(["crm.read"]), &rows(100)));
    let g = kit::asor_sign(&child("v-grand", &c, 2, &json!(["crm.read"]), &rows(10)));
    let wider_scope = kit::asor_sign(&child(
        "v-w1",
        &r,
        1,
        &json!(["crm.*", "mail.send"]),
        &rows(100),
    ));
    let wider_ceiling = kit::asor_sign(&child("v-w2", &r, 1, &json!(["crm.read"]), &rows(5000)));
    let mut altered = child("v-alt", &r, 1, &json!(["crm.read"]), &rows(100));
    altered["sub"] = json!("user:mallory");
    let altered = kit::asor_sign(&altered);
    let mut spliced = child("v-spl", &r, 1, &json!(["crm.read"]), &rows(100));
    spliced["par_hash"] = json!(URL_SAFE_NO_PAD.encode([0u8; 32]));
    let spliced = kit::asor_sign(&spliced);
    let shallow = kit::asor_sign(&root(2, &json!(["crm.*"]), &rows(1000)));
    let s1 = kit::asor_sign(&child(
        "v-s1",
        &shallow,
        1,
        &json!(["crm.read"]),
        &rows(100),
    ));
    let s2 = kit::asor_sign(&child("v-s2", &s1, 2, &json!(["crm.read"]), &rows(10)));
    let mut forged = c.clone();
    forged.replace_range(forged.len() - 4.., "AAAA");

    let cases = [
        (
            "V.1",
            "two hops, scope and ceiling narrowed",
            vec![r.clone(), c.clone()],
            NOW,
        ),
        ("V.2", "three hops", vec![r.clone(), c.clone(), g], NOW),
        (
            "V.3",
            "child adds a scope",
            vec![r.clone(), wider_scope],
            NOW,
        ),
        (
            "V.4",
            "child raises a ceiling",
            vec![r.clone(), wider_ceiling],
            NOW,
        ),
        ("V.5", "child changes sub", vec![r.clone(), altered], NOW),
        (
            "V.6",
            "child's par_hash does not match its parent",
            vec![r.clone(), spliced],
            NOW,
        ),
        (
            "V.7",
            "three tokens under del_max_depth 2",
            vec![shallow, s1, s2],
            NOW,
        ),
        (
            "V.8",
            "child signature altered",
            vec![r.clone(), forged],
            NOW,
        ),
        (
            "V.9",
            "checked after the child's exp",
            vec![r, c],
            NOW + 301,
        ),
    ];
    let verifier = asor::Verifier::new(
        vec![asor::TrustAnchor::new(
            kit::ASOR_ISSUER,
            kit::asor_anchor_key().verifying_key(),
        )],
        vec![AUDIENCE.to_owned()],
    );
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(id, note, tokens, at)| {
            let at = i64::try_from(at).expect("time");
            let visado = asor_outcome(verifier.check(&tokens, at).map(|_| ()));
            json!({ "id": id, "note": note, "tokens": tokens, "now": at, "visado": visado })
        })
        .collect();
    let x = URL_SAFE_NO_PAD.encode(kit::asor_anchor_key().verifying_key().to_raw_bytes());
    json!({
        "minted_by": format!("visado-testkit {}", env!("CARGO_PKG_VERSION")),
        "anchor": { "iss": kit::ASOR_ISSUER, "alg": "Ed25519", "x": x },
        "audience": AUDIENCE,
        "cases": cases,
    })
}

/// The leaf's holder key thumbprint, which the verifier records a PoP `jti`
/// under.
fn leaf_holder(chain: &[String]) -> Option<String> {
    let claims = jose::split(chain.last()?)
        .and_then(|jws| jose::b64(jws.payload))
        .and_then(|payload| json::parse(&payload).ok())?;
    jose::holder_key(claims.get("cnf")).map(|key| key.thumbprint)
}
