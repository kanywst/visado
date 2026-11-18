use std::collections::{BTreeSet, HashSet};

/// Remembers proof `jti`s until they expire.
#[derive(Debug)]
pub(crate) struct ReplayCache {
    seen: HashSet<String>,
    by_expiry: BTreeSet<(u64, String)>,
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

    /// Records `jti` until `expires_at`. Returns false if it was already seen,
    /// or if the cache is full of live entries (fail closed).
    pub(crate) fn insert(&mut self, jti: &str, expires_at: u64, now: u64) -> bool {
        while let Some((exp, _)) = self.by_expiry.first() {
            if *exp > now {
                break;
            }
            if let Some((_, id)) = self.by_expiry.pop_first() {
                self.seen.remove(&id);
            }
        }
        if self.seen.contains(jti) || self.seen.len() >= self.capacity {
            return false;
        }
        self.seen.insert(jti.to_owned());
        self.by_expiry.insert((expires_at, jti.to_owned()));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayCache;

    #[test]
    fn rejects_reuse_until_expiry() {
        let mut cache = ReplayCache::new(2);
        assert!(cache.insert("a", 10, 0));
        assert!(!cache.insert("a", 10, 5));
        assert!(cache.insert("b", 10, 5));
        assert!(!cache.insert("c", 10, 5), "full cache fails closed");
        assert!(cache.insert("a", 20, 10), "expired entries are dropped");
    }
}
