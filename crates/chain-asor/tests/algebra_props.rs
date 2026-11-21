//! Property tests for the asor authority algebra: subsumption is reflexive
//! and transitive, and attenuation never widens what the leaf permits.
//!
//! Details and actions are drawn from a small universe of scopes,
//! constraint keys and values, so that random pairs often relate.

use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use serde_json::{Map, Value, json};
use visado_chain::Authority;
use visado_chain::algebra::{Action, AuthorityAlgebra};
use visado_chain_asor::Algebra;

const SCOPES: [&str; 6] = [
    "crm.*",
    "crm.read",
    "crm.write",
    "crm.read.*",
    "mail.send",
    "openid",
];

fn member() -> impl Strategy<Value = Value> {
    select(vec![json!("eu"), json!("us"), json!(1), json!(2)])
}

/// One constraint on `rows` (numbers), `region` (members), `path`
/// (prefixes) or `tier` (ranks), or of a type the verifier does not know.
fn constraint() -> impl Strategy<Value = Value> {
    prop_oneof![
        (0..4i64).prop_map(|n| json!({ "key": "rows", "max": n })),
        (0..4i64).prop_map(|n| json!({ "key": "rows", "min": n })),
        prop::collection::vec(member(), 0..=3)
            .prop_map(|v| json!({ "key": "region", "one_of": v })),
        prop::collection::vec(member(), 0..=3)
            .prop_map(|v| json!({ "key": "region", "not_one_of": v })),
        select(vec!["/a", "/a/b", "/b", ""]).prop_map(|p| json!({ "key": "path", "prefix": p })),
        select(vec!["low", "mid", "high"])
            .prop_map(|r| json!({ "key": "tier", "rank": r, "order": ["low", "mid", "high"] })),
        (0..3i64).prop_map(|n| json!({ "key": "rows", "units": n })),
    ]
}

fn authority() -> impl Strategy<Value = Authority> {
    (
        subsequence(SCOPES.to_vec(), 1..=3),
        prop::collection::vec(constraint(), 0..=2),
    )
        .prop_map(|(scopes, constraints)| {
            // A (key, type) pair may appear once.
            let mut unique: Vec<Value> = Vec::new();
            for c in constraints {
                let kind = |c: &Value| {
                    let object = c.as_object().unwrap();
                    let mut kinds: Vec<&String> = object
                        .keys()
                        .filter(|k| *k != "key" && *k != "order")
                        .collect();
                    kinds.sort();
                    (c["key"].clone(), kinds.first().map(|k| (*k).clone()))
                };
                if !unique.iter().any(|u| kind(u) == kind(&c)) {
                    unique.push(c);
                }
            }
            let detail = json!({
                "type": "agent_delegation",
                "scopes": scopes,
                "constraints": unique,
            });
            Authority {
                detail_type: "agent_delegation".into(),
                json: detail.to_string(),
            }
        })
}

/// An action: a scope and some of the constrained parameters.
fn action() -> impl Strategy<Value = (String, String)> {
    (
        select(vec![
            "crm.read",
            "crm.write",
            "crm.read.x",
            "mail.send",
            "openid",
            "crm",
        ]),
        0..5i64,
        member(),
        select(vec!["/a", "/a/b/c", "/b", "/c"]),
        select(vec!["low", "mid", "high", "none"]),
        subsequence(vec!["rows", "region", "path", "tier"], 3..=4),
    )
        .prop_map(|(scope, rows, region, path, tier, keys)| {
            let values = [json!(rows), region, json!(path), json!(tier)];
            let mut params = Map::new();
            for (key, value) in ["rows", "region", "path", "tier"].iter().zip(values) {
                if keys.contains(key) {
                    params.insert((*key).to_owned(), value);
                }
            }
            (scope.to_owned(), Value::Object(params).to_string())
        })
}

fn permits(a: &Authority, (scope, params): &(String, String)) -> bool {
    Algebra::default().permits(
        a,
        Some(&Action {
            name: scope,
            params_json: params,
        }),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5000,
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
    fn attenuation_never_widens(parent in authority(), child in authority(), actions in prop::collection::vec(action(), 16)) {
        if Algebra::default().subsumes(&parent, &child) {
            for action in &actions {
                prop_assert!(
                    !permits(&child, action) || permits(&parent, action),
                    "parent {}\nchild {}\naction {action:?}", parent.json, child.json
                );
            }
        }
    }
}
