//! The authority algebra of the `attenuating_agent_token` type.

use std::collections::BTreeMap;

use visado_chain::Authority;
use visado_chain::algebra::{Action, AuthorityAlgebra};
use visado_chain::json::{self, Value};

use crate::constraint::ToolMap;
use crate::verify::{DETAIL_TYPE, Invocation, Limits, attenuation, invocation_args, tool_maps};

/// Subsumption and the invocation check for AAT capabilities.
///
/// A normalized AAT [`Authority`] is the `tools` object of the token's AAT
/// entry. `subsumes` is §8 step 4p (every child tool is a parent tool, and
/// each constraint map attenuates the parent's per §4.5); `permits` is step
/// 6b in closed-world mode (§3.3): the tool is granted, and the arguments
/// are a JSON object of admissible numbers that satisfies its constraints.
#[derive(Debug, Clone, Copy, Default)]
pub struct Algebra {
    limits: Limits,
}

impl Algebra {
    /// An algebra that parses constraints and arguments within `limits`
    /// (constraint depth, constraint nodes, and token size for arguments).
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self { limits }
    }

    fn tools(&self, authority: &Authority) -> Option<BTreeMap<String, ToolMap>> {
        if authority.detail_type != DETAIL_TYPE {
            return None;
        }
        let value = json::parse(authority.json.as_bytes()).ok()?;
        let members = value.as_object()?;
        if !members.iter().all(|(_, v)| matches!(v, Value::Object(_))) {
            return None;
        }
        tool_maps(members, &self.limits)
    }
}

impl AuthorityAlgebra for Algebra {
    fn detail_type(&self) -> &'static str {
        DETAIL_TYPE
    }

    fn subsumes(&self, parent: &Authority, child: &Authority) -> bool {
        match (self.tools(parent), self.tools(child)) {
            (Some(parent), Some(child)) => attenuation(&child, &parent).is_ok(),
            _ => false,
        }
    }

    fn permits(&self, leaf: &Authority, action: Option<&Action<'_>>) -> bool {
        let (Some(tools), Some(action)) = (self.tools(leaf), action) else {
            return false;
        };
        let invocation = Invocation {
            tool: action.name,
            args_json: action.params_json,
        };
        invocation_args(&tools, &invocation, &self.limits).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use visado_chain::Authority;
    use visado_chain::algebra::{Action, AuthorityAlgebra};

    use super::Algebra;

    fn tools(json: &str) -> Authority {
        Authority {
            detail_type: "attenuating_agent_token".into(),
            json: json.into(),
        }
    }

    fn call<'a>(name: &'a str, params_json: &'a str) -> Action<'a> {
        Action { name, params_json }
    }

    #[test]
    fn subsumption_follows_step_4p() {
        let a = Algebra::default();
        let parent = tools(
            r#"{"read":{"path":{"constraint_type":"one_of","values":["/a","/b"]}},"write":{}}"#,
        );
        let child = tools(r#"{"read":{"path":{"constraint_type":"exact","value":"/a"}}}"#);
        assert!(a.subsumes(&parent, &child));
        assert!(!a.subsumes(&child, &parent), "a new tool widens");
        assert!(a.subsumes(&parent, &parent));
        let other = tools(r#"{"read":{"path":{"constraint_type":"exact","value":"/c"}}}"#);
        assert!(!a.subsumes(&parent, &other));
    }

    #[test]
    fn permits_is_closed_world() {
        let a = Algebra::default();
        let leaf = tools(r#"{"read":{"path":{"constraint_type":"exact","value":"/a"}}}"#);
        assert!(a.permits(&leaf, Some(&call("read", r#"{"path":"/a"}"#))));
        assert!(!a.permits(&leaf, Some(&call("read", r#"{"path":"/b"}"#))));
        assert!(!a.permits(&leaf, Some(&call("read", r#"{"path":"/a","x":1}"#))));
        assert!(!a.permits(&leaf, Some(&call("write", "{}"))));
        assert!(!a.permits(&leaf, Some(&call("read", "[]"))));
        assert!(!a.permits(&leaf, None));
    }

    #[test]
    fn malformed_authorities_grant_nothing() {
        let a = Algebra::default();
        for bad in [
            "",
            "[]",
            r#"{"read":1}"#,
            r#"{"read":{"x":{"constraint_type":"nope"}}}"#,
        ] {
            let bad = tools(bad);
            assert!(!a.subsumes(&bad, &bad), "{bad:?}");
            assert!(!a.permits(&bad, Some(&call("read", "{}"))), "{bad:?}");
        }
        let wrong_type = Authority {
            detail_type: "agent_delegation".into(),
            json: "{}".into(),
        };
        assert!(!a.subsumes(&wrong_type, &wrong_type));
    }
}
