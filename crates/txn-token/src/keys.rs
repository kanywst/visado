//! Trusted verification keys, selected by `kid`.

use std::collections::BTreeMap;

use wimsey_jose::VerifyingKey;

/// The keys a recipient trusts for Transaction Tokens of one trust domain.
///
/// Keys come from configuration, never from the token itself (§13.7).
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    by_kid: BTreeMap<String, VerifyingKey>,
    unnamed: Option<VerifyingKey>,
}

impl KeySet {
    /// An empty key set. Every token is rejected until a key is added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key that tokens select with `kid`.
    #[must_use]
    pub fn with_key(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.by_kid.insert(kid.into(), key);
        self
    }

    /// Sets the key used for tokens whose header has no `kid`.
    #[must_use]
    pub fn with_unnamed_key(mut self, key: VerifyingKey) -> Self {
        self.unnamed = Some(key);
        self
    }

    /// The key for `kid`. A token without `kid` only matches the unnamed key.
    #[must_use]
    pub fn get(&self, kid: Option<&str>) -> Option<&VerifyingKey> {
        match kid {
            Some(kid) => self.by_kid.get(kid),
            None => self.unnamed.as_ref(),
        }
    }
}
