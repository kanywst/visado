//! Argument constraints (§3.3, §3.4) and their subsumption rules (§4.5).

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};

use crate::error::Step;
use visado_chain::json::Value;

/// The reserved constraint-map key for unnamed arguments (§3.3).
const STAR: &str = "*";

/// A constraint value in JCS form, with its double when it is a number.
#[derive(Debug, Clone)]
struct Canon {
    jcs: String,
    number: Option<f64>,
}

impl Canon {
    fn of(value: &Value) -> Self {
        let number = match value {
            Value::Number(n) => Some(n.to_f64()),
            _ => None,
        };
        Self {
            jcs: value.jcs(),
            number,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bound {
    value: f64,
    inclusive: bool,
}

#[derive(Debug, Clone, Copy)]
struct Range {
    min: Option<Bound>,
    max: Option<Bound>,
}

impl Range {
    fn accepts(self, x: f64) -> bool {
        let above = self.min.is_none_or(|b| {
            if b.inclusive {
                x >= b.value
            } else {
                x > b.value
            }
        });
        let below = self.max.is_none_or(|b| {
            if b.inclusive {
                x <= b.value
            } else {
                x < b.value
            }
        });
        above && below
    }

    /// §4.5: `self` (the derived range) is at least as tight as `parent`.
    fn within(self, parent: Self) -> bool {
        bound_within(self.min, parent.min, |d, p| d > p)
            && bound_within(self.max, parent.max, |d, p| d < p)
    }
}

/// One side of a range: the derived bound must exist where the parent's does,
/// lie inside it, and not be inclusive where an equal parent bound is
/// exclusive.
fn bound_within(
    derived: Option<Bound>,
    parent: Option<Bound>,
    inside: fn(f64, f64) -> bool,
) -> bool {
    match (derived, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(d), Some(p)) => {
            #[allow(clippy::float_cmp)]
            let equal = d.value == p.value;
            inside(d.value, p.value) || (equal && (p.inclusive || !d.inclusive))
        }
    }
}

/// The JCS forms of a constraint's value list, built once at parse time.
type JcsSet = BTreeSet<String>;

/// A well-formed core constraint.
#[derive(Debug, Clone)]
enum Constraint {
    Exact(Canon),
    Range(Range),
    OneOf(JcsSet),
    NotOneOf(JcsSet),
    Contains(JcsSet),
    Subset(JcsSet),
    Wildcard,
    All(Vec<Constraint>),
    Any(Vec<Constraint>),
}

#[derive(Debug, Clone)]
struct Entry {
    constraint: Constraint,
    optional: bool,
}

/// A tool's constraint map, normalized: an empty map, or a `"*"` entry, sets
/// `star` (§3.3).
#[derive(Debug, Clone)]
pub(crate) struct ToolMap {
    named: BTreeMap<String, Entry>,
    star: bool,
}

impl ToolMap {
    /// Parses a constraint map and checks that every constraint in it is
    /// well-formed and at most `max_depth` deep (§3.4; §8 steps 3n and 4o).
    /// Each constraint node takes one from `nodes`; the map is rejected when
    /// it runs out.
    pub(crate) fn parse(
        members: &[(String, Value)],
        max_depth: usize,
        nodes: &mut usize,
    ) -> Option<Self> {
        let mut named = BTreeMap::new();
        let mut star = members.is_empty();
        for (key, value) in members {
            let entry = parse_entry(value, max_depth, nodes)?;
            if key == STAR {
                if entry.optional || !matches!(entry.constraint, Constraint::Wildcard) {
                    return None;
                }
                // `optional: false` is not allowed on `"*"` either.
                if value.get("optional").is_some() {
                    return None;
                }
                star = true;
            } else {
                named.insert(key.clone(), entry);
            }
        }
        Some(Self { named, star })
    }

    /// §8 step 4p2 to 4p4: `self` (the derived map) attenuates `parent`.
    pub(crate) fn attenuates(&self, parent: &Self) -> Result<(), Step> {
        // 4p2: the key rules.
        if self
            .named
            .keys()
            .any(|k| !parent.star && !parent.named.contains_key(k))
        {
            return Err(Step::S4p2);
        }
        for (key, entry) in &parent.named {
            if !self.named.contains_key(key) && (!entry.optional || self.star) {
                return Err(Step::S4p2);
            }
        }
        if self.star && !parent.star {
            return Err(Step::S4p2);
        }
        // 4p3: a required argument stays required.
        for (key, entry) in &self.named {
            if let Some(p) = parent.named.get(key)
                && !p.optional
                && entry.optional
            {
                return Err(Step::S4p3);
            }
        }
        // 4p4: each named constraint narrows the parent's, or the parent's `"*"`.
        for (key, entry) in &self.named {
            let ok = match parent.named.get(key) {
                Some(p) => subsumes(&p.constraint, &entry.constraint),
                None => true, // parent `"*"`: a wildcard subsumes everything
            };
            if !ok {
                return Err(Step::S4p4);
            }
        }
        Ok(())
    }

    /// §8 step 6b in closed-world mode: every argument is named or admitted
    /// by `"*"` and satisfies its constraint, and no required argument is
    /// missing.
    pub(crate) fn permits(&self, args: &[(String, Value)]) -> bool {
        for (key, value) in args {
            match self.named.get(key) {
                Some(entry) => {
                    if !check(&entry.constraint, &Arg::new(value)) {
                        return false;
                    }
                }
                None if self.star => {}
                None => return false,
            }
        }
        self.named
            .iter()
            .all(|(key, entry)| entry.optional || args.iter().any(|(k, _)| k == key))
    }
}

fn parse_entry(value: &Value, max_depth: usize, nodes: &mut usize) -> Option<Entry> {
    let optional = match value.get("optional") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    let constraint = parse_constraint(value, 1, max_depth, true, nodes)?;
    Some(Entry {
        constraint,
        optional,
    })
}

fn parse_constraint(
    value: &Value,
    level: usize,
    max_depth: usize,
    top: bool,
    nodes: &mut usize,
) -> Option<Constraint> {
    if level > max_depth {
        return None;
    }
    *nodes = nodes.checked_sub(1)?;
    let members = value.as_object()?;
    let kind = value.get("constraint_type")?.as_str()?;
    let allowed: &[&str] = match kind {
        "exact" => &["value"],
        "range" => &["min", "max", "min_inclusive", "max_inclusive"],
        "one_of" => &["values"],
        "not_one_of" => &["excluded"],
        "contains" => &["required"],
        "subset" => &["allowed"],
        "wildcard" => &[],
        "all" | "any" => &["constraints"],
        _ => return None,
    };
    for (key, _) in members {
        let known = key == "constraint_type"
            || (top && key == "optional")
            || allowed.contains(&key.as_str());
        if !known {
            return None;
        }
    }
    if !value.numbers_admissible() {
        return None;
    }
    let constraint = match kind {
        "exact" => {
            let v = value.get("value")?;
            if matches!(v, Value::Array(_) | Value::Object(_)) {
                return None;
            }
            Constraint::Exact(Canon::of(v))
        }
        "range" => Constraint::Range(parse_range(value)?),
        "one_of" => {
            let values = jcs_set(value.get("values")?)?;
            if values.is_empty() {
                return None;
            }
            Constraint::OneOf(values)
        }
        "not_one_of" => Constraint::NotOneOf(jcs_set(value.get("excluded")?)?),
        "contains" => Constraint::Contains(jcs_set(value.get("required")?)?),
        "subset" => Constraint::Subset(jcs_set(value.get("allowed")?)?),
        "wildcard" => Constraint::Wildcard,
        _ => {
            let clauses = value.get("constraints")?.as_array()?;
            if clauses.is_empty() {
                return None;
            }
            let parsed = clauses
                .iter()
                .map(|c| parse_constraint(c, level + 1, max_depth, false, nodes))
                .collect::<Option<Vec<_>>>()?;
            if kind == "all" {
                Constraint::All(parsed)
            } else {
                Constraint::Any(parsed)
            }
        }
    };
    Some(constraint)
}

fn parse_range(value: &Value) -> Option<Range> {
    let bound = |name: &str, flag: &str| -> Option<Option<Bound>> {
        let inclusive = match value.get(flag) {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        match value.get(name) {
            None if value.get(flag).is_some() => None,
            None => Some(None),
            Some(Value::Number(n)) => Some(Some(Bound {
                value: n.to_f64(),
                inclusive,
            })),
            Some(_) => None,
        }
    };
    let min = bound("min", "min_inclusive")?;
    let max = bound("max", "max_inclusive")?;
    if let (Some(lo), Some(hi)) = (min, max)
        && lo.value > hi.value
    {
        return None;
    }
    Some(Range { min, max })
}

fn jcs_set(value: &Value) -> Option<JcsSet> {
    Some(value.as_array()?.iter().map(Value::jcs).collect())
}

/// An argument value with its JCS forms, each computed at most once however
/// many constraint nodes look at it.
struct Arg<'a> {
    value: &'a Value,
    jcs: OnceCell<String>,
    items: OnceCell<Option<JcsSet>>,
}

impl<'a> Arg<'a> {
    fn new(value: &'a Value) -> Self {
        Self {
            value,
            jcs: OnceCell::new(),
            items: OnceCell::new(),
        }
    }

    fn jcs(&self) -> &str {
        self.jcs.get_or_init(|| self.value.jcs())
    }

    /// The distinct JCS forms of the elements, if the value is an array.
    fn items(&self) -> Option<&JcsSet> {
        self.items
            .get_or_init(|| {
                self.value
                    .as_array()
                    .map(|items| items.iter().map(Value::jcs).collect())
            })
            .as_ref()
    }
}

/// The runtime `check` predicate (§3.4).
fn check(constraint: &Constraint, arg: &Arg<'_>) -> bool {
    match constraint {
        Constraint::Wildcard => true,
        Constraint::Exact(c) => arg.jcs() == c.jcs,
        Constraint::Range(r) => match arg.value {
            Value::Number(n) => r.accepts(n.to_f64()),
            _ => false,
        },
        Constraint::OneOf(values) => values.contains(arg.jcs()),
        Constraint::NotOneOf(excluded) => !excluded.contains(arg.jcs()),
        Constraint::Contains(required) => arg
            .items()
            .is_some_and(|have| required.iter().all(|r| have.contains(r))),
        // `is_subset` stops at once when there are more distinct items than
        // allowed values, so the cost is bounded by the constraint's size.
        Constraint::Subset(allowed) => arg.items().is_some_and(|have| have.is_subset(allowed)),
        Constraint::All(clauses) => clauses.iter().all(|c| check(c, arg)),
        Constraint::Any(clauses) => clauses.iter().any(|c| check(c, arg)),
    }
}

/// `child ⊑ parent` per the §4.5 table. Pairs the table does not list are
/// rejected.
fn subsumes(parent: &Constraint, child: &Constraint) -> bool {
    use Constraint as C;
    match (parent, child) {
        (C::Wildcard, _) => true,
        (C::Exact(p), C::Exact(c)) => p.jcs == c.jcs,
        (C::Range(p), C::Range(c)) => c.within(*p),
        (C::Range(p), C::Exact(c)) => c.number.is_some_and(|x| p.accepts(x)),
        (C::OneOf(p), C::OneOf(c)) => !c.is_empty() && c.is_subset(p),
        (C::OneOf(p), C::Exact(c)) => p.contains(&c.jcs),
        (C::NotOneOf(p), C::NotOneOf(c)) | (C::Contains(p), C::Contains(c)) => p.is_subset(c),
        (C::Subset(p), C::Subset(c)) => c.is_subset(p),
        (C::All(p), C::All(c)) => p.iter().all(|cp| c.iter().any(|cd| subsumes(cp, cd))),
        (C::Any(p), C::Any(c)) => c.iter().all(|cd| p.iter().any(|cp| subsumes(cp, cd))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::ToolMap;
    use crate::error::Step;
    use visado_chain::json::parse;

    fn map(json: &str) -> ToolMap {
        let v = parse(json.as_bytes()).unwrap();
        ToolMap::parse(v.as_object().unwrap(), 32, &mut 1024).unwrap()
    }

    #[test]
    fn range_bounds() {
        let parent =
            map(r#"{"n":{"constraint_type":"range","min":0,"min_inclusive":false,"max":10}}"#);
        let tighter = map(
            r#"{"n":{"constraint_type":"range","min":0,"min_inclusive":false,"max":10,"max_inclusive":false}}"#,
        );
        let wider = map(r#"{"n":{"constraint_type":"range","min":0,"max":10}}"#);
        let open = map(r#"{"n":{"constraint_type":"range","max":10}}"#);
        assert_eq!(tighter.attenuates(&parent), Ok(()));
        assert_eq!(wider.attenuates(&parent), Err(Step::S4p4));
        assert_eq!(open.attenuates(&parent), Err(Step::S4p4));
    }

    #[test]
    fn malformed_constraints() {
        for bad in [
            r#"{"a":{"constraint_type":"range","min":2,"max":1}}"#,
            r#"{"a":{"constraint_type":"range","min_inclusive":true}}"#,
            r#"{"a":{"constraint_type":"one_of","values":[]}}"#,
            r#"{"a":{"constraint_type":"exact","value":[1]}}"#,
            r#"{"a":{"constraint_type":"all","constraints":[]}}"#,
            r#"{"a":{"constraint_type":"all","constraints":[{"constraint_type":"wildcard","optional":true}]}}"#,
            r#"{"*":{"constraint_type":"exact","value":1}}"#,
            r#"{"a":{"constraint_type":"regex","pattern":"x"}}"#,
            r#"{"a":{"constraint_type":"exact","value":9007199254740993}}"#,
        ] {
            let v = parse(bad.as_bytes()).unwrap();
            assert!(
                ToolMap::parse(v.as_object().unwrap(), 32, &mut 1024).is_none(),
                "{bad}"
            );
        }
    }

    #[test]
    fn closed_world() {
        let m = map(
            r#"{"path":{"constraint_type":"exact","value":"/a"},"head":{"constraint_type":"range","max":5,"optional":true}}"#,
        );
        let args = |s: &str| parse(s.as_bytes()).unwrap();
        assert!(m.permits(args(r#"{"path":"/a"}"#).as_object().unwrap()));
        assert!(m.permits(args(r#"{"path":"/a","head":5}"#).as_object().unwrap()));
        assert!(!m.permits(args(r#"{"path":"/a","head":6}"#).as_object().unwrap()));
        assert!(!m.permits(args(r#"{"path":"/a","x":1}"#).as_object().unwrap()));
        assert!(!m.permits(args(r#"{"head":1}"#).as_object().unwrap()));
    }

    #[test]
    fn node_budget() {
        let clauses = [r#"{"constraint_type":"one_of","values":[1,2]}"#; 9].join(",");
        let json = format!(r#"{{"a":{{"constraint_type":"any","constraints":[{clauses}]}}}}"#);
        let v = parse(json.as_bytes()).unwrap();
        let members = v.as_object().unwrap();
        let mut nodes = 10;
        assert!(ToolMap::parse(members, 32, &mut nodes).is_some());
        assert_eq!(nodes, 0);
        assert!(ToolMap::parse(members, 32, &mut 9).is_none());
    }

    #[test]
    fn set_constraints() {
        let m = map(
            r#"{"tags":{"constraint_type":"all","constraints":[{"constraint_type":"contains","required":["a"]},{"constraint_type":"subset","allowed":["a","b",1.0]}]},"mode":{"constraint_type":"not_one_of","excluded":["x"]}}"#,
        );
        let ok = |s: &str| m.permits(parse(s.as_bytes()).unwrap().as_object().unwrap());
        assert!(ok(r#"{"tags":["a","b","a",1],"mode":"y"}"#));
        assert!(!ok(r#"{"tags":["b"],"mode":"y"}"#));
        assert!(!ok(r#"{"tags":["a","c"],"mode":"y"}"#));
        assert!(!ok(r#"{"tags":["a"],"mode":"x"}"#));
        assert!(!ok(r#"{"tags":"a","mode":"y"}"#));
    }
}
