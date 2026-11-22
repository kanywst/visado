//! Trusted verification keys, selected by `kid`.

use std::collections::BTreeMap;
use std::fmt;

use jsonwebtoken::DecodingKey;
use wimsey_jose::VerifyingKey;

use crate::error::TxnTokenError;

/// The smallest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;

/// An RSA public key for `RS256`.
#[derive(Clone)]
pub(crate) struct RsaKey {
    pub(crate) key: DecodingKey,
    /// The modulus length in bytes, which is also the signature length.
    pub(crate) len: usize,
}

impl fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKey")
            .field("bits", &(self.len * 8))
            .finish_non_exhaustive()
    }
}

/// A trusted key of either family.
#[derive(Debug, Clone)]
pub(crate) enum Key {
    Jose(VerifyingKey),
    Rsa(RsaKey),
}

/// The keys a recipient trusts for Transaction Tokens of one trust domain.
///
/// Keys come from configuration, never from the token itself (§13.7).
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    by_kid: BTreeMap<String, Key>,
    unnamed: Option<Key>,
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
        self.by_kid.insert(kid.into(), Key::Jose(key));
        self
    }

    /// Sets the key used for tokens whose header has no `kid`.
    #[must_use]
    pub fn with_unnamed_key(mut self, key: VerifyingKey) -> Self {
        self.unnamed = Some(Key::Jose(key));
        self
    }

    /// Adds an RSA key for `RS256` tokens that select it with `kid`, from the
    /// big-endian modulus `n` and exponent `e` (the JWK `n` and `e`, decoded).
    ///
    /// # Errors
    ///
    /// [`TxnTokenError::WeakKey`] if the modulus is shorter than
    /// [`MIN_RSA_BITS`] or the exponent is empty.
    pub fn with_rsa_key(
        mut self,
        kid: impl Into<String>,
        n: &[u8],
        e: &[u8],
    ) -> Result<Self, TxnTokenError> {
        self.by_kid.insert(kid.into(), Key::Rsa(rsa(n, e)?));
        Ok(self)
    }

    /// Sets an RSA key, as [`KeySet::with_rsa_key`], for tokens whose header
    /// has no `kid`.
    ///
    /// # Errors
    ///
    /// As [`KeySet::with_rsa_key`].
    pub fn with_unnamed_rsa_key(mut self, n: &[u8], e: &[u8]) -> Result<Self, TxnTokenError> {
        self.unnamed = Some(Key::Rsa(rsa(n, e)?));
        Ok(self)
    }

    /// The `Ed25519` or `ES256` key for `kid`. A token without `kid` only
    /// matches the unnamed key. RSA keys are not returned here.
    #[must_use]
    pub fn get(&self, kid: Option<&str>) -> Option<&VerifyingKey> {
        match self.find(kid)? {
            Key::Jose(key) => Some(key),
            Key::Rsa(_) => None,
        }
    }

    pub(crate) fn find(&self, kid: Option<&str>) -> Option<&Key> {
        match kid {
            Some(kid) => self.by_kid.get(kid),
            None => self.unnamed.as_ref(),
        }
    }
}

fn rsa(n: &[u8], e: &[u8]) -> Result<RsaKey, TxnTokenError> {
    let first = n.iter().position(|b| *b != 0).unwrap_or(n.len());
    let n = &n[first..];
    let bits = n.first().map_or(0, |top| {
        (n.len() - 1) * 8 + (8 - top.leading_zeros() as usize)
    });
    if bits < MIN_RSA_BITS || e.iter().all(|b| *b == 0) {
        return Err(TxnTokenError::WeakKey);
    }
    Ok(RsaKey {
        key: DecodingKey::from_rsa_raw_components(n, e),
        len: n.len(),
    })
}
