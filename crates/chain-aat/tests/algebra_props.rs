//! Property tests for the AAT authority algebra: subsumption is reflexive
//! and transitive, and attenuation never widens what the leaf permits.
//!
//! Authorities and calls are drawn from a small universe of tools, argument
//! names and values, so that random pairs often relate.

use proptest::prelude::*;
use proptest::sample::subsequence;
use serde_json::{Map, Value, json};
use visado_chain::Authority;
use visado_chain::algebra::{Action, AuthorityAlgebra};
use visado_chain_aat::Algebra;

const TOOLS: [&str; 2] = ["read", "write"];
const KEYS: [&str; 2] = ["x", "y"];

fn scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!("a")),
        Just(json!("b")),
        Just(json!(1)),
        Just(json!(2)),
        Just(json!(3)),
    ]
}

fn scalars() -> impl Strategy<Value = Vec<Value>> {
    subsequence(
        vec![json!("a"), json!("b"), json!(1), json!(2), json!(3)],
        0..=3,
    )
}

/// `one_of` must list at least one value.
fn nonempty() -> impl Strategy<Value = Vec<Value>> {
    subsequence(
        vec![json!("a"), json!("b"), json!(1), json!(2), json!(3)],
        1..=3,
    )
}

fn range() -> impl Strategy<Value = Value> {
    (
        prop::option::of(0..4i64),
        prop::option::of(0..4i64),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(min, max, min_inclusive, max_inclusive)| {
            // A range whose min is above its max is malformed.
            let (min, max) = match (min, max) {
                (Some(lo), Some(hi)) if lo > hi => (Some(hi), Some(lo)),
                other => other,
            };
            let mut c = json!({ "constraint_type": "range" });
            if let Some(min) = min {
                c["min"] = json!(min);
                c["min_inclusive"] = json!(min_inclusive);
            }
            if let Some(max) = max {
                c["max"] = json!(max);
                c["max_inclusive"] = json!(max_inclusive);
            }
            c
        })
}

fn constraint() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(json!({ "constraint_type": "wildcard" })),
        scalar().prop_map(|v| json!({ "constraint_type": "exact", "value": v })),
        nonempty().prop_map(|v| json!({ "constraint_type": "one_of", "values": v })),
        scalars().prop_map(|v| json!({ "constraint_type": "not_one_of", "excluded": v })),
        scalars().prop_map(|v| json!({ "constraint_type": "contains", "required": v })),
        scalars().prop_map(|v| json!({ "constraint_type": "subset", "allowed": v })),
        range(),
    ];
    leaf.prop_recursive(2, 6, 2, |inner| {
        (any::<bool>(), prop::collection::vec(inner, 1..=2)).prop_map(|(all, clauses)| {
            let kind = if all { "all" } else { "any" };
            json!({ "constraint_type": kind, "constraints": clauses })
        })
    })
}

/// A tool's constraint map: some named arguments, each optional or not,
/// and sometimes `"*"`.
fn tool_map() -> impl Strategy<Value = Value> {
    (
        prop::collection::vec((constraint(), any::<bool>()), KEYS.len()),
        subsequence(KEYS.to_vec(), 0..=KEYS.len()),
        any::<bool>(),
    )
        .prop_map(|(entries, keys, star)| {
            let mut map = Map::new();
            for (key, (mut constraint, optional)) in KEYS.iter().zip(entries) {
                if keys.contains(key) {
                    if optional {
                        constraint["optional"] = json!(true);
                    }
                    map.insert((*key).to_owned(), constraint);
                }
            }
            if star {
                map.insert("*".into(), json!({ "constraint_type": "wildcard" }));
            }
            Value::Object(map)
        })
}

fn authority() -> impl Strategy<Value = Authority> {
    (
        prop::collection::vec(tool_map(), TOOLS.len()),
        subsequence(TOOLS.to_vec(), 0..=TOOLS.len()),
    )
        .prop_map(|(maps, tools)| {
            let mut object = Map::new();
            for (tool, map) in TOOLS.iter().zip(maps) {
                if tools.contains(tool) {
                    object.insert((*tool).to_owned(), map);
                }
            }
            Authority {
                detail_type: "attenuating_agent_token".into(),
                json: Value::Object(object).to_string(),
            }
        })
}

fn argument() -> impl Strategy<Value = Value> {
    prop_oneof![scalar(), scalars().prop_map(Value::Array)]
}

/// A call to one of the tools with some of `x`, `y` and `z`.
fn call() -> impl Strategy<Value = (String, String)> {
    (
        prop::sample::select(TOOLS.to_vec()),
        prop::collection::vec(argument(), 3),
        subsequence(vec!["x", "y", "z"], 0..=3),
    )
        .prop_map(|(tool, values, keys)| {
            let mut args = Map::new();
            for (key, value) in ["x", "y", "z"].iter().zip(values) {
                if keys.contains(key) {
                    args.insert((*key).to_owned(), value);
                }
            }
            (tool.to_owned(), Value::Object(args).to_string())
        })
}

fn permits(a: &Authority, (tool, args): &(String, String)) -> bool {
    Algebra::default().permits(
        a,
        Some(&Action {
            name: tool,
            params_json: args,
        }),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn subsumption_is_reflexive(a in authority()) {
        prop_assert!(Algebra::default().subsumes(&a, &a), "{}", a.json);
    }

    #[test]
    fn subsumption_is_transitive(a in authority(), b in authority(), c in authority()) {
        let alg = Algebra::default();
        if alg.subsumes(&a, &b) && alg.subsumes(&b, &c) {
            prop_assert!(alg.subsumes(&a, &c), "{}\n{}\n{}", a.json, b.json, c.json);
        }
    }

    #[test]
    fn attenuation_never_widens(parent in authority(), child in authority(), calls in prop::collection::vec(call(), 8)) {
        if Algebra::default().subsumes(&parent, &child) {
            for call in &calls {
                prop_assert!(
                    !permits(&child, call) || permits(&parent, call),
                    "parent {}\nchild {}\ncall {call:?}", parent.json, child.json
                );
            }
        }
    }
}
