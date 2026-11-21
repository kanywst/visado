//! Authority algebras: per authority type, whether one authority subsumes
//! another and whether an authority permits an action.
//!
//! Each [`Authority::detail_type`] a deployment accepts has one
//! [`AuthorityAlgebra`]. The format crates implement the types they decode
//! (`visado-chain-aat`, `visado-chain-asor`, `visado-chain-act`), and an
//! [`Algebras`] registry maps a type to its algebra. A type with no algebra
//! in the registry subsumes nothing and permits nothing.

use std::fmt;
use std::sync::Arc;

use crate::Authority;

/// What a request asks the leaf's authority to allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action<'a> {
    /// The action's name: an AAT tool, or an asor scope.
    pub name: &'a str,
    /// The action's parameters as the JSON object text that was received.
    pub params_json: &'a str,
}

/// The rules of one authority type.
///
/// Implementations must be conservative: an authority that does not parse
/// subsumes nothing, is subsumed by nothing, and permits nothing.
pub trait AuthorityAlgebra: fmt::Debug + Send + Sync {
    /// The [`Authority::detail_type`] this algebra handles.
    fn detail_type(&self) -> &str;

    /// Whether `parent` subsumes `child`: everything `child` allows,
    /// `parent` allows too. Both have this algebra's type.
    fn subsumes(&self, parent: &Authority, child: &Authority) -> bool;

    /// Whether the leaf's authority `leaf` allows `action`. `None` is a
    /// request with no action to check, which only a type that grants
    /// nothing per hop (the RFC 8693 `act` adapter's) permits.
    fn permits(&self, leaf: &Authority, action: Option<&Action<'_>>) -> bool;
}

/// The algebras a deployment accepts, one per authority type.
#[derive(Debug, Clone, Default)]
pub struct Algebras {
    algebras: Vec<Arc<dyn AuthorityAlgebra>>,
}

impl Algebras {
    /// An empty registry, which denies every authority.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `algebra`, replacing one already registered for its type.
    #[must_use]
    pub fn with(mut self, algebra: Arc<dyn AuthorityAlgebra>) -> Self {
        self.algebras
            .retain(|a| a.detail_type() != algebra.detail_type());
        self.algebras.push(algebra);
        self
    }

    /// The algebra for `detail_type`, if one is registered.
    #[must_use]
    pub fn get(&self, detail_type: &str) -> Option<&dyn AuthorityAlgebra> {
        self.algebras
            .iter()
            .find(|a| a.detail_type() == detail_type)
            .map(AsRef::as_ref)
    }

    /// Whether `parent` subsumes `child`. False when the two differ in type
    /// or the type has no algebra.
    #[must_use]
    pub fn subsumes(&self, parent: &Authority, child: &Authority) -> bool {
        parent.detail_type == child.detail_type
            && self
                .get(&parent.detail_type)
                .is_some_and(|a| a.subsumes(parent, child))
    }

    /// Whether `leaf` permits `action`. False when its type has no algebra.
    #[must_use]
    pub fn permits(&self, leaf: &Authority, action: Option<&Action<'_>>) -> bool {
        self.get(&leaf.detail_type)
            .is_some_and(|a| a.permits(leaf, action))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Action, Algebras, AuthorityAlgebra};
    use crate::Authority;

    /// Authorities are sets of names, written `a,b,c`.
    #[derive(Debug)]
    struct Names(&'static str);

    fn names(a: &Authority) -> Vec<&str> {
        a.json.split(',').filter(|s| !s.is_empty()).collect()
    }

    impl AuthorityAlgebra for Names {
        fn detail_type(&self) -> &str {
            self.0
        }
        fn subsumes(&self, parent: &Authority, child: &Authority) -> bool {
            names(child).iter().all(|c| names(parent).contains(c))
        }
        fn permits(&self, leaf: &Authority, action: Option<&Action<'_>>) -> bool {
            action.is_some_and(|a| names(leaf).contains(&a.name))
        }
    }

    fn authority(detail_type: &str, json: &str) -> Authority {
        Authority {
            detail_type: detail_type.into(),
            json: json.into(),
        }
    }

    #[test]
    fn unknown_types_are_denied() {
        let registry = Algebras::new().with(Arc::new(Names("names")));
        let known = authority("names", "a,b");
        let unknown = authority("other", "a,b");
        let action = Action {
            name: "a",
            params_json: "{}",
        };
        assert!(registry.subsumes(&known, &known));
        assert!(registry.permits(&known, Some(&action)));
        assert!(!registry.subsumes(&unknown, &unknown));
        assert!(!registry.permits(&unknown, Some(&action)));
        assert!(!registry.subsumes(&known, &authority("other", "a")));
        assert!(!Algebras::new().permits(&known, Some(&action)));
    }

    #[test]
    fn a_later_algebra_replaces_an_earlier_one() {
        #[derive(Debug)]
        struct Nothing;
        impl AuthorityAlgebra for Nothing {
            fn detail_type(&self) -> &'static str {
                "names"
            }
            fn subsumes(&self, _: &Authority, _: &Authority) -> bool {
                false
            }
            fn permits(&self, _: &Authority, _: Option<&Action<'_>>) -> bool {
                false
            }
        }
        let registry = Algebras::new()
            .with(Arc::new(Names("names")))
            .with(Arc::new(Nothing));
        let a = authority("names", "a");
        assert!(!registry.subsumes(&a, &a));
    }
}
