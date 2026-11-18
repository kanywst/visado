use std::collections::{BTreeSet, HashSet};

use sha2::{Digest, Sha256};

/// A fixed-size replay key for `jti` as used by `caller`.
pub(crate) fn key(caller: &str, jti: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(caller.as_bytes());
    hash.update([0]);
    hash.update(jti.as_bytes());
    hash.finalize().into()
}

/// Remembers proof keys until they expire.
#[derive(Debug)]
pub(crate) struct ReplayCache {
    seen: HashSet<[u8; 32]>,
    by_expiry: BTreeSet<(u64, [u8; 32])>,
    capacity: usize,
}

impl ReplayCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            by_expiry: BTreeSet::new(),
            capacity,
        }
    }

    /// Records `key` until `expires_at`.
    pub(crate) fn insert(&mut self, key: [u8; 32], expires_at: u64, now: u64) -> Insert {
        while let Some((exp, _)) = self.by_expiry.first() {
            if *exp > now {
                break;
            }
            if let Some((_, old)) = self.by_expiry.pop_first() {
                self.seen.remove(&old);
            }
        }
        if self.seen.contains(&key) {
            return Insert::Seen;
        }
        if self.seen.len() >= self.capacity {
            return Insert::Full;
        }
        self.seen.insert(key);
        self.by_expiry.insert((expires_at, key));
        Insert::Fresh
    }
}

/// The result of recording a proof.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Insert {
    /// Not seen before; now recorded.
    Fresh,
    /// Already used.
    Seen,
    /// The cache is full of live entries. The proof is rejected.
    Full,
}

#[cfg(test)]
mod tests {
    use super::{Insert, ReplayCache, key};

    #[test]
    fn rejects_reuse_until_expiry() {
        let mut cache = ReplayCache::new(2);
        assert_eq!(cache.insert(key("w", "a"), 10, 0), Insert::Fresh);
        assert_eq!(cache.insert(key("w", "a"), 10, 5), Insert::Seen);
        assert_eq!(cache.insert(key("other", "a"), 10, 5), Insert::Fresh);
        assert_eq!(cache.insert(key("w", "c"), 10, 5), Insert::Full);
        assert_eq!(cache.insert(key("w", "a"), 20, 10), Insert::Fresh);
    }
}
