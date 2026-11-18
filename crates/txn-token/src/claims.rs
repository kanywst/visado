//! The Transaction Token claim set (draft-ietf-oauth-transaction-tokens-11 §9.2).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::error::TxnTokenError;

/// The claims of a Transaction Token.
///
/// Members the draft marks REQUIRED are plain fields; RECOMMENDED and OPTIONAL
/// ones are `Option`. Claims this crate does not know are ignored on parse, as
/// §9.2 requires of recipients.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxnTokenClaims {
    /// Issuer. OPTIONAL (§13.16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: u64,
    /// The trust domain the token is valid in.
    pub aud: String,
    /// Expiry, seconds since the Unix epoch.
    pub exp: u64,
    /// Transaction identifier, unique per call chain (RFC 8417 §2.2).
    pub txn: String,
    /// The subject, unique within the trust domain.
    pub sub: String,
    /// The authorized scope for the transaction.
    pub scope: Scope,
    /// The workload that requested the token.
    pub req_wl: String,
    /// Immutable authorization context. RECOMMENDED.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tctx: Option<Map<String, Value>>,
    /// Request environment context. RECOMMENDED.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rctx: Option<Map<String, Value>>,
}

impl TxnTokenClaims {
    /// Checks the claims a token must carry to be minted or accepted.
    ///
    /// # Errors
    ///
    /// [`TxnTokenError::InvalidClaim`] for an empty `aud`, `txn`, `sub`,
    /// `req_wl` or `scope`; [`TxnTokenError::InvalidLifetime`] if `exp` is not
    /// after `iat`.
    pub fn check(&self) -> Result<(), TxnTokenError> {
        for (claim, value) in [
            ("aud", &self.aud),
            ("txn", &self.txn),
            ("sub", &self.sub),
            ("req_wl", &self.req_wl),
        ] {
            if value.is_empty() {
                return Err(TxnTokenError::InvalidClaim { claim });
            }
        }
        if self.scope.is_empty() {
            return Err(TxnTokenError::InvalidClaim { claim: "scope" });
        }
        if self.exp <= self.iat {
            return Err(TxnTokenError::InvalidLifetime);
        }
        Ok(())
    }
}

/// A space-delimited scope, compared as a set of tokens.
///
/// The draft does not define how scopes compare (see `SPEC-MAP.md`). This crate
/// treats each space-separated value as an opaque string and a scope as narrower
/// when its values are a subset.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope(BTreeSet<String>);

impl Scope {
    /// Parses a space-delimited scope string. Repeated and surrounding
    /// whitespace is ignored.
    #[must_use]
    pub fn parse(scope: &str) -> Self {
        Self(scope.split_ascii_whitespace().map(str::to_owned).collect())
    }

    /// Whether the scope has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether every value in `self` is also in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }

    /// Whether `value` is in the scope.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.0.contains(value)
    }

    /// The values, in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for value in &self.0 {
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(value)?;
            first = false;
        }
        Ok(())
    }
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::parse(&raw))
    }
}

#[cfg(test)]
mod tests {
    use super::Scope;

    #[test]
    fn scope_parses_as_a_set() {
        let scope = Scope::parse("  write read  read ");
        assert_eq!(scope.to_string(), "read write");
        assert!(Scope::parse("read").is_subset_of(&scope));
        assert!(!Scope::parse("read admin").is_subset_of(&scope));
        assert!(Scope::parse("").is_empty());
    }
}
