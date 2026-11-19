//! The `agent_delegation` authorization detail: parsing (§4), subsumption
//! (§4.3) and the action check of step 8.

use visado_chain::json::Value;

use crate::error::Outcome;
use crate::scope;

/// The `authorization_details` type of a Delegation Token (§4).
pub const DETAIL_TYPE: &str = "agent_delegation";

/// What a constraint bounds, by type (§4.2).
#[derive(Debug, Clone, PartialEq)]
enum Bound {
    Max(f64),
    Min(f64),
    MaxLifetime(f64),
    MaxSubtree(f64),
    /// Members as their JCS serializations.
    OneOf(Vec<String>),
    NotOneOf(Vec<String>),
    Prefix(String),
    Rank {
        rank: String,
        order: Vec<String>,
    },
    /// A type this verifier does not implement: the whole constraint object
    /// as JCS. It subsumes only an identical constraint and denies every
    /// action.
    Unknown(String),
}

/// One constraint, identified by (key, type).
#[derive(Debug, Clone, PartialEq)]
struct Constraint {
    key: String,
    kind: String,
    bound: Bound,
}

/// A running total of a cumulative constraint, held outside the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cumulative {
    /// `max_lifetime`: summed over every action under the token's `jti`.
    Lifetime,
    /// `max_subtree`: summed over the token and its descendants.
    Subtree,
}

/// Supplies the running totals that `max_lifetime` and `max_subtree` are
/// measured over (§6 step 8). The total reaches the check through this
/// channel, never from the request.
pub trait RunningTotals {
    /// The total for `key`, including the action being authorized, for the
    /// token `jti`. `None` if this component does not hold it, which denies.
    fn total(&self, jti: &str, key: &str, kind: Cumulative) -> Option<f64>;
}

/// The Authority of one Delegation Token.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Authority {
    scopes: Vec<String>,
    constraints: Vec<Constraint>,
    /// The detail object as JCS.
    pub(crate) jcs: String,
}

const DETAIL_MEMBERS: &[&str] = &["type", "scopes", "constraints"];
const NUMERIC_TYPES: &[&str] = &["max", "min", "max_lifetime", "max_subtree"];
const KNOWN_TYPES: &[&str] = &[
    "max",
    "min",
    "max_lifetime",
    "max_subtree",
    "one_of",
    "not_one_of",
    "prefix",
    "rank",
];

impl Authority {
    /// Reads `authorization_details`: exactly one detail, of type
    /// `agent_delegation`, with no members but `type`, `scopes` and
    /// `constraints` (§4, §4.4). Every failure is `malformed`.
    pub(crate) fn parse(details: Option<&Value>) -> Option<Self> {
        let [detail] = details?.as_array()? else {
            return None;
        };
        let members = detail.as_object()?;
        if detail.get("type")?.as_str()? != DETAIL_TYPE {
            return None;
        }
        if members
            .iter()
            .any(|(k, _)| !DETAIL_MEMBERS.contains(&k.as_str()))
        {
            return None;
        }
        let scopes = detail
            .get("scopes")?
            .as_array()?
            .iter()
            .map(|s| {
                s.as_str()
                    .filter(|s| scope::classify(s).is_some())
                    .map(ToOwned::to_owned)
            })
            .collect::<Option<Vec<_>>>()?;
        let constraints = match detail.get("constraints") {
            None => Vec::new(),
            Some(list) => list
                .as_array()?
                .iter()
                .map(constraint)
                .collect::<Option<Vec<_>>>()?,
        };
        for (i, c) in constraints.iter().enumerate() {
            if constraints[..i]
                .iter()
                .any(|d| d.key == c.key && d.kind == c.kind)
            {
                return None;
            }
        }
        Some(Self {
            scopes,
            constraints,
            jcs: detail.jcs(),
        })
    }

    /// Rules 1, 2 and 3 of §4.3: `self` (the child) is subsumed by `parent`.
    pub(crate) fn subsumed_by(&self, parent: &Self) -> bool {
        let scopes = self
            .scopes
            .iter()
            .all(|c| parent.scopes.iter().any(|p| scope::covers(p, c)));
        scopes
            && parent.constraints.iter().all(|p| {
                self.constraints
                    .iter()
                    .find(|c| c.key == p.key && c.kind == p.kind)
                    .is_some_and(|c| narrows(&c.bound, &p.bound))
            })
    }

    /// Step 8 after the audience check: the scope, then every constraint in
    /// order. `params` is the action's parameters (a JSON object).
    pub(crate) fn permits(
        &self,
        jti: &str,
        action_scope: &str,
        params: &Value,
        totals: Option<&dyn RunningTotals>,
    ) -> Result<(), (Outcome, &'static str)> {
        if !self.scopes.iter().any(|s| scope::covers(s, action_scope)) {
            return Err((Outcome::ScopeNotGranted, "scope not covered by the leaf"));
        }
        for c in &self.constraints {
            let param = params.get(&c.key);
            let total = |kind| totals.and_then(|t| t.total(jti, &c.key, kind));
            let ok = match &c.bound {
                Bound::Unknown(_) => {
                    return Err((
                        Outcome::UnknownConstraint,
                        "constraint type not implemented",
                    ));
                }
                Bound::Max(max) => param.is_none_or(|p| number(p).is_some_and(|n| n <= *max)),
                Bound::Min(min) => param.is_none_or(|p| number(p).is_some_and(|n| n >= *min)),
                Bound::MaxLifetime(max) => total(Cumulative::Lifetime).is_some_and(|t| t <= *max),
                Bound::MaxSubtree(max) => total(Cumulative::Subtree).is_some_and(|t| t <= *max),
                Bound::OneOf(members) => {
                    param.is_none_or(|p| member(p).is_some_and(|m| members.contains(&m)))
                }
                Bound::NotOneOf(members) => {
                    param.is_none_or(|p| member(p).is_some_and(|m| !members.contains(&m)))
                }
                Bound::Prefix(prefix) => {
                    param.is_none_or(|p| p.as_str().is_some_and(|s| s.starts_with(prefix.as_str())))
                }
                Bound::Rank { rank, order } => param.is_none_or(|p| {
                    let at = |v: &str| order.iter().position(|o| o == v);
                    p.as_str()
                        .and_then(at)
                        .zip(at(rank))
                        .is_some_and(|(v, r)| v <= r)
                }),
            };
            if !ok {
                return Err((Outcome::CeilingExceeded, "action exceeds a leaf constraint"));
            }
        }
        Ok(())
    }
}

/// One constraint object: `key`, exactly one type member, and the members
/// that type adds (`order` for `rank`). A single member of an unknown type
/// is kept whole; anything else is malformed (§4.2).
fn constraint(value: &Value) -> Option<Constraint> {
    let members = value.as_object()?;
    let key = value.get("key")?.as_str()?.to_owned();
    let others: Vec<&(String, Value)> = members.iter().filter(|(k, _)| k != "key").collect();
    let known: Vec<&str> = others
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| KNOWN_TYPES.contains(k))
        .collect();
    let kind = match known.as_slice() {
        [] => {
            let [(kind, _)] = others.as_slice() else {
                return None;
            };
            return Some(Constraint {
                key,
                kind: kind.clone(),
                bound: Bound::Unknown(value.jcs()),
            });
        }
        [kind] => *kind,
        _ => return None,
    };
    let allowed = |k: &str| k == "key" || k == kind || (kind == "rank" && k == "order");
    if members.iter().any(|(k, _)| !allowed(k)) {
        return None;
    }
    let v = value.get(kind)?;
    let bound = match kind {
        k if NUMERIC_TYPES.contains(&k) => {
            let n = number(v)?;
            match k {
                "max" => Bound::Max(n),
                "min" => Bound::Min(n),
                "max_lifetime" => Bound::MaxLifetime(n),
                _ => Bound::MaxSubtree(n),
            }
        }
        "one_of" | "not_one_of" => {
            let items = v
                .as_array()?
                .iter()
                .map(member)
                .collect::<Option<Vec<_>>>()?;
            if kind == "one_of" {
                Bound::OneOf(items)
            } else {
                Bound::NotOneOf(items)
            }
        }
        "prefix" => Bound::Prefix(v.as_str()?.to_owned()),
        _ => {
            let rank = v.as_str()?.to_owned();
            let order = value
                .get("order")?
                .as_array()?
                .iter()
                .map(|o| o.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>()?;
            let distinct = order
                .iter()
                .enumerate()
                .all(|(i, o)| !order[..i].contains(o));
            if order.len() < 2 || !distinct || !order.contains(&rank) {
                return None;
            }
            Bound::Rank { rank, order }
        }
    };
    Some(Constraint {
        key,
        kind: kind.to_owned(),
        bound,
    })
}

/// Rule 2 of §4.3 for one (key, type) pair: the child's admissible set is a
/// subset of the parent's.
fn narrows(child: &Bound, parent: &Bound) -> bool {
    match (child, parent) {
        (Bound::Max(c), Bound::Max(p))
        | (Bound::MaxLifetime(c), Bound::MaxLifetime(p))
        | (Bound::MaxSubtree(c), Bound::MaxSubtree(p)) => c <= p,
        (Bound::Min(c), Bound::Min(p)) => c >= p,
        (Bound::OneOf(c), Bound::OneOf(p)) => c.iter().all(|m| p.contains(m)),
        (Bound::NotOneOf(c), Bound::NotOneOf(p)) => p.iter().all(|m| c.contains(m)),
        (Bound::Prefix(c), Bound::Prefix(p)) => c.starts_with(p.as_str()),
        (
            Bound::Rank {
                rank: c_rank,
                order: c_order,
            },
            Bound::Rank {
                rank: p_rank,
                order: p_order,
            },
        ) => {
            let at = |v: &String| c_order.iter().position(|o| o == v);
            c_order == p_order && at(c_rank).zip(at(p_rank)).is_some_and(|(c, p)| c <= p)
        }
        (Bound::Unknown(c), Bound::Unknown(p)) => c == p,
        _ => false,
    }
}

/// A number whose JCS form denotes the value as written, as a double.
fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) if n.is_admissible() => Some(n.to_f64()),
        _ => None,
    }
}

/// A `one_of` / `not_one_of` member or an action value compared with one:
/// a JSON scalar, as its JCS serialization, so `1` and `1.0` are the same
/// member and `1` and `"1"` are not.
fn member(value: &Value) -> Option<String> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Some(value.jcs()),
        Value::Number(n) if n.is_admissible() => Some(value.jcs()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use visado_chain::json::{Value, parse};

    use super::Authority;
    use crate::error::Outcome;

    fn authority(json: &str) -> Option<Authority> {
        let details = parse(json.as_bytes()).unwrap();
        Authority::parse(Some(&details))
    }

    fn detail(scopes: &str, constraints: &str) -> Authority {
        authority(&format!(
            r#"[{{"type":"agent_delegation","scopes":{scopes},"constraints":{constraints}}}]"#
        ))
        .unwrap()
    }

    #[test]
    fn closed_objects() {
        assert!(authority(r#"[{"type":"agent_delegation","scopes":[]}]"#).is_some());
        assert!(authority(r#"[{"type":"agent_delegation","scopes":[],"actions":[]}]"#).is_none());
        assert!(authority(r#"[{"type":"other","scopes":[]}]"#).is_none());
        assert!(authority("[]").is_none());
        let c = |c: &str| {
            authority(&format!(
                r#"[{{"type":"agent_delegation","scopes":[],"constraints":[{c}]}}]"#
            ))
        };
        assert!(c(r#"{"key":"a","max":1}"#).is_some());
        assert!(c(r#"{"key":"a","max":1,"note":"x"}"#).is_none());
        assert!(c(r#"{"key":"a","max":1,"min":0}"#).is_none());
        assert!(c(r#"{"key":"a","units":1}"#).is_some());
        assert!(c(r#"{"key":"a","units":1,"more":2}"#).is_none());
        assert!(c(r#"{"key":"a","rank":"x","order":["x","y"]}"#).is_some());
        assert!(c(r#"{"key":"a","rank":"x"}"#).is_none());
        assert!(c(r#"{"key":"a","rank":"z","order":["x","y"]}"#).is_none());
        assert!(c(r#"{"key":"a","rank":"x","order":["x","x"]}"#).is_none());
        assert!(c(r#"{"key":"a","one_of":[[1]]}"#).is_none());
        assert!(c(r#"{"key":"a","max":1},{"key":"a","max":2}"#).is_none());
        assert!(c(r#"{"key":"a","max":1},{"key":"a","min":0}"#).is_some());
    }

    #[test]
    fn subsumption() {
        let parent = detail(
            r#"["crm.*"]"#,
            r#"[{"key":"n","max":10},{"key":"e","one_of":["a","b",1]},{"key":"d","not_one_of":["x"]},{"key":"p","prefix":"/a"}]"#,
        );
        let child = detail(
            r#"["crm.read"]"#,
            r#"[{"key":"n","max":5},{"key":"e","one_of":[1.0]},{"key":"d","not_one_of":["x","y"]},{"key":"p","prefix":"/a/b"}]"#,
        );
        assert!(child.subsumed_by(&parent));
        assert!(!parent.subsumed_by(&child));
        let dropped = detail(r#"["crm.read"]"#, "[]");
        assert!(!dropped.subsumed_by(&parent));
    }

    #[test]
    fn permits() {
        let leaf = detail(
            r#"["crm.read"]"#,
            r#"[{"key":"rows","max":100},{"key":"egress","rank":"internal","order":["none","internal","any"]}]"#,
        );
        let params = |p: &str| parse(p.as_bytes()).unwrap();
        let check = |scope: &str, p: &str| leaf.permits("j", scope, &params(p), None);
        assert_eq!(check("crm.read", r#"{"rows":100}"#), Ok(()));
        assert_eq!(
            check("crm.read", r#"{"rows":"100"}"#).unwrap_err().0,
            Outcome::CeilingExceeded
        );
        assert_eq!(
            check("crm.read", r#"{"rows":101}"#).unwrap_err().0,
            Outcome::CeilingExceeded
        );
        assert_eq!(
            check("crm.read", r#"{"egress":"any"}"#).unwrap_err().0,
            Outcome::CeilingExceeded
        );
        assert_eq!(check("crm.read", r#"{"egress":"none"}"#), Ok(()));
        assert_eq!(
            check("crm.write", "{}").unwrap_err().0,
            Outcome::ScopeNotGranted
        );
        let cumulative = detail(r#"["crm.read"]"#, r#"[{"key":"calls","max_lifetime":2}]"#);
        assert_eq!(
            cumulative
                .permits("j", "crm.read", &Value::Object(Vec::new()), None)
                .unwrap_err()
                .0,
            Outcome::CeilingExceeded
        );
        let unknown = detail(r#"["crm.read"]"#, r#"[{"key":"u","units":2}]"#);
        assert_eq!(
            unknown
                .permits("j", "crm.read", &Value::Object(Vec::new()), None)
                .unwrap_err()
                .0,
            Outcome::UnknownConstraint
        );
    }
}
