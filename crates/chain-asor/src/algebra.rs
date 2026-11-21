//! The authority algebra of the `agent_delegation` type.

use visado_chain::algebra::{Action, AuthorityAlgebra};
use visado_chain::json::{self, Value};

use crate::authority::{Authority, DETAIL_TYPE};

/// Subsumption and the action check for asor Authorities.
///
/// A normalized asor [`Authority`](visado_chain::Authority) is the
/// `agent_delegation` detail object. `subsumes` is rules 1 to 3 of §4.3
/// (scopes are covered, and every parent constraint is present in the child
/// and narrowed); `permits` is step 8 after the audience check: the action's
/// scope is covered by a leaf scope and its parameters satisfy every leaf
/// constraint.
///
/// The algebra holds no running totals, so a leaf with a `max_lifetime` or
/// `max_subtree` constraint permits nothing, as in a verifier given none.
#[derive(Debug, Clone, Copy)]
pub struct Algebra {
    max_params_size: usize,
}

impl Default for Algebra {
    fn default() -> Self {
        Self::new(crate::Limits::default().max_params_size)
    }
}

impl Algebra {
    /// An algebra that refuses action parameters larger than
    /// `max_params_size` bytes.
    #[must_use]
    pub const fn new(max_params_size: usize) -> Self {
        Self { max_params_size }
    }

    fn authority(authority: &visado_chain::Authority) -> Option<Authority> {
        if authority.detail_type != DETAIL_TYPE {
            return None;
        }
        let detail = json::parse(authority.json.as_bytes()).ok()?;
        Authority::parse(Some(&Value::Array(vec![detail])))
    }
}

impl AuthorityAlgebra for Algebra {
    fn detail_type(&self) -> &'static str {
        DETAIL_TYPE
    }

    fn subsumes(&self, parent: &visado_chain::Authority, child: &visado_chain::Authority) -> bool {
        match (Self::authority(parent), Self::authority(child)) {
            (Some(parent), Some(child)) => child.subsumed_by(&parent),
            _ => false,
        }
    }

    fn permits(&self, leaf: &visado_chain::Authority, action: Option<&Action<'_>>) -> bool {
        let (Some(leaf), Some(action)) = (Self::authority(leaf), action) else {
            return false;
        };
        if action.params_json.len() > self.max_params_size {
            return false;
        }
        let Some(params) = json::parse(action.params_json.as_bytes())
            .ok()
            .filter(|p| p.as_object().is_some())
        else {
            return false;
        };
        leaf.permits("", action.name, &params, None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use visado_chain::Authority;
    use visado_chain::algebra::{Action, AuthorityAlgebra};

    use super::Algebra;

    fn detail(json: &str) -> Authority {
        Authority {
            detail_type: "agent_delegation".into(),
            json: json.into(),
        }
    }

    fn act<'a>(name: &'a str, params_json: &'a str) -> Action<'a> {
        Action { name, params_json }
    }

    #[test]
    fn subsumption_follows_section_4_3() {
        let a = Algebra::default();
        let parent = detail(
            r#"{"constraints":[{"key":"n","max":10}],"scopes":["crm.*"],"type":"agent_delegation"}"#,
        );
        let child = detail(
            r#"{"constraints":[{"key":"n","max":5}],"scopes":["crm.read"],"type":"agent_delegation"}"#,
        );
        assert!(a.subsumes(&parent, &child));
        assert!(!a.subsumes(&child, &parent));
        let dropped = detail(r#"{"scopes":["crm.read"],"type":"agent_delegation"}"#);
        assert!(
            !a.subsumes(&parent, &dropped),
            "a parent constraint was dropped"
        );
    }

    #[test]
    fn permits_checks_scope_and_constraints() {
        let a = Algebra::default();
        let leaf = detail(
            r#"{"constraints":[{"key":"n","max":5}],"scopes":["crm.read"],"type":"agent_delegation"}"#,
        );
        assert!(a.permits(&leaf, Some(&act("crm.read", r#"{"n":5}"#))));
        assert!(!a.permits(&leaf, Some(&act("crm.read", r#"{"n":6}"#))));
        assert!(!a.permits(&leaf, Some(&act("crm.read", "{}"))));
        assert!(!a.permits(&leaf, Some(&act("crm.write", r#"{"n":1}"#))));
        assert!(!a.permits(&leaf, Some(&act("crm.read", "[]"))));
        assert!(!a.permits(&leaf, None));
        assert!(!Algebra::new(4).permits(&leaf, Some(&act("crm.read", r#"{"n":5}"#))));
        let cumulative = detail(
            r#"{"constraints":[{"key":"c","max_lifetime":5}],"scopes":["crm.read"],"type":"agent_delegation"}"#,
        );
        assert!(!a.permits(&cumulative, Some(&act("crm.read", "{}"))));
    }

    #[test]
    fn malformed_authorities_grant_nothing() {
        let a = Algebra::default();
        for bad in [
            "",
            "[]",
            r#"{"scopes":["crm.read"],"type":"other"}"#,
            r#"{"actions":[],"scopes":[],"type":"agent_delegation"}"#,
        ] {
            let bad = detail(bad);
            assert!(!a.subsumes(&bad, &bad), "{bad:?}");
            assert!(!a.permits(&bad, Some(&act("crm.read", "{}"))), "{bad:?}");
        }
    }
}
