//! Proof-of-possession `jti` tracking: AAT PoP JWTs (AAT §7.3) and DPoP
//! proofs (RFC 9449 §11.1).

use std::collections::HashMap;
use std::sync::Mutex;

/// Accepted proof `jti` values.
///
/// Replicas of one enforcement point must share this state, so a deployment
/// with several replicas implements it over shared storage.
pub trait ReplayCache {
    /// Records `jti` until `until` (seconds since the Unix epoch) and returns
    /// `true`, or returns `false` if it is already recorded and not expired.
    /// Must be atomic.
    fn check_and_record(&self, jti: &str, until: i64, now: i64) -> bool;
}

/// An in-process [`ReplayCache`] with a fixed capacity. When it is full of
/// unexpired entries, new proofs are refused.
#[derive(Debug)]
pub struct MemoryReplayCache {
    capacity: usize,
    seen: Mutex<HashMap<String, i64>>,
}

impl MemoryReplayCache {
    /// An empty cache holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `jti` is recorded and not expired at `now`.
    #[must_use]
    pub fn contains(&self, jti: &str, now: i64) -> bool {
        self.seen
            .lock()
            .is_ok_and(|seen| seen.get(jti).is_some_and(|until| *until >= now))
    }
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_record(&self, jti: &str, until: i64, now: i64) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if seen.get(jti).is_some_and(|t| *t >= now) {
            return false;
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, t| *t >= now);
            if seen.len() >= self.capacity {
                return false;
            }
        }
        seen.insert(jti.to_owned(), until);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryReplayCache, ReplayCache};

    #[test]
    fn records_once_and_expires() {
        let cache = MemoryReplayCache::new(1);
        assert!(cache.check_and_record("a", 130, 100));
        assert!(!cache.check_and_record("a", 130, 120));
        assert!(!cache.check_and_record("b", 150, 120), "full");
        assert!(cache.check_and_record("b", 170, 140), "a expired");
    }
}
