//! Proof-of-possession `jti` tracking: AAT PoP JWTs (AAT §7.3), DPoP proofs
//! (RFC 9449 §11.1), WPT `jti` values and HTTP signature nonces.
//!
//! A replay cache must remember every proof it accepted for as long as that
//! proof could be accepted again, and it must hold a bounded number of them.
//! Those two needs meet when the cache is full: new proofs are refused. To keep
//! one client from filling it for everyone else, [`MemoryReplayCache`] also
//! caps how many live entries one owner (a proof key, a workload) may hold.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// How far ahead of the clock, in seconds, a proof's issue time (DPoP and
/// AAT PoP `iat`, HTTP signature `created`) may be by default. A proof is
/// remembered for its acceptance window counted from that time, so a
/// proof issued far ahead would hold its cache entry that much longer.
pub const DEFAULT_PROOF_SKEW: i64 = 5;

/// Accepted proof `jti` values.
///
/// Replicas of one enforcement point must share this state, so a deployment
/// with several replicas implements it over shared storage.
pub trait ReplayCache {
    /// Records `jti` for `owner` until `until`, the last second (since the
    /// Unix epoch) at which the proof could still be accepted, and returns
    /// [`Recorded::Fresh`]; or refuses it without recording anything. `owner`
    /// is whoever made the proof, such as the proof key's thumbprint: a `jti`
    /// is unique per owner, and the per-owner quota counts by it. Must be
    /// atomic.
    fn check_and_record(&self, owner: &str, jti: &str, until: i64, now: i64) -> Recorded;
}

/// The result of [`ReplayCache::check_and_record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Recorded {
    /// Not seen before; now recorded.
    Fresh,
    /// Already recorded for this owner and not expired: a replay.
    Replayed,
    /// The proof's last acceptable second is before the latest time the
    /// cache has seen, so its entry may already have been recorded and
    /// dropped. It cannot be told apart from a replay and is refused like
    /// one.
    Stale,
    /// The owner already holds its quota of live entries. Only this owner's
    /// new proofs are refused until some of its entries expire.
    OverQuota,
    /// The cache is full of live entries, so the proof cannot be recorded.
    Full,
}

impl Recorded {
    /// Whether the proof was recorded.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// A fixed-size digest of a string, so an entry costs the same whatever the
/// length of the identifiers it was made from.
type Digest32 = [u8; 32];

/// An in-process [`ReplayCache`] with a fixed capacity and a per-owner quota.
///
/// Lookups are O(1) and expired entries are dropped in expiry order, so each
/// entry is removed once, in O(log n), however full the cache is. Each live
/// entry costs about 150 bytes.
#[derive(Debug)]
pub struct MemoryReplayCache {
    capacity: usize,
    owner_quota: usize,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// The latest `now` any call has passed. Time never runs backwards for
    /// the cache: a call with an older `now` (a request that waited, a clock
    /// stepped back) is handled at this time, so it cannot find an entry
    /// absent that a later call already dropped.
    high_water: i64,
    /// Live entries by key, with the expiry and the owner of each.
    live: HashMap<Digest32, (i64, Digest32)>,
    /// The same entries ordered by expiry, so the expired ones come first.
    by_expiry: BTreeSet<(i64, Digest32)>,
    /// How many live entries each owner holds.
    per_owner: HashMap<Digest32, usize>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            high_water: i64::MIN,
            live: HashMap::new(),
            by_expiry: BTreeSet::new(),
            per_owner: HashMap::new(),
        }
    }
}

impl State {
    /// Drops every entry whose last acceptable second is before `now`.
    fn expire(&mut self, now: i64) {
        while let Some(&(until, key)) = self.by_expiry.first() {
            if until >= now {
                break;
            }
            self.by_expiry.pop_first();
            if let Some((_, owner)) = self.live.remove(&key)
                && let Some(count) = self.per_owner.get_mut(&owner)
            {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.per_owner.remove(&owner);
                }
            }
        }
    }
}

impl MemoryReplayCache {
    /// An empty cache holding at most `capacity` entries, with no owner
    /// holding more than `capacity` of them (no quota beyond the capacity;
    /// see [`MemoryReplayCache::with_owner_quota`]).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            owner_quota: capacity,
            state: Mutex::new(State::default()),
        }
    }

    /// Caps the live entries one owner may hold at `quota`. A proof from an
    /// owner at its quota is [`Recorded::OverQuota`], while other owners
    /// still have room.
    #[must_use]
    pub const fn with_owner_quota(mut self, quota: usize) -> Self {
        self.owner_quota = quota;
        self
    }

    /// The most entries the cache holds.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The most live entries one owner may hold.
    #[must_use]
    pub const fn owner_quota(&self) -> usize {
        self.owner_quota
    }

    /// Whether `jti` is recorded for `owner` and not expired at `now`.
    #[must_use]
    pub fn contains(&self, owner: &str, jti: &str, now: i64) -> bool {
        let key = entry_key(owner, jti);
        self.state
            .lock()
            .is_ok_and(|state| state.live.get(&key).is_some_and(|(t, _)| *t >= now))
    }

    /// The number of entries held, expired ones included until the next
    /// insertion drops them.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.live.len())
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_record(&self, owner: &str, jti: &str, until: i64, now: i64) -> Recorded {
        // A poisoned lock fails closed: nothing is recorded, nothing accepted.
        let Ok(mut state) = self.state.lock() else {
            return Recorded::Full;
        };
        let now = now.max(state.high_water);
        state.high_water = now;
        state.expire(now);
        let key = entry_key(owner, jti);
        if state.live.contains_key(&key) {
            return Recorded::Replayed;
        }
        if until < now {
            return Recorded::Stale;
        }
        let owner = owner_key(owner);
        let held = state.per_owner.get(&owner).copied().unwrap_or(0);
        if held >= self.owner_quota {
            return Recorded::OverQuota;
        }
        if state.live.len() >= self.capacity {
            return Recorded::Full;
        }
        state.live.insert(key, (until, owner));
        state.by_expiry.insert((until, key));
        *state.per_owner.entry(owner).or_insert(0) += 1;
        Recorded::Fresh
    }
}

/// The key of `jti` for `owner`. Both are length-prefixed, so no two pairs
/// share an encoding.
fn entry_key(owner: &str, jti: &str) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"visado-replay-entry\0");
    hash.update((owner.len() as u64).to_be_bytes());
    hash.update(owner.as_bytes());
    hash.update((jti.len() as u64).to_be_bytes());
    hash.update(jti.as_bytes());
    hash.finalize().into()
}

fn owner_key(owner: &str) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"visado-replay-owner\0");
    hash.update(owner.as_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{MemoryReplayCache, Recorded, ReplayCache};

    #[test]
    fn records_once_and_expires() {
        let cache = MemoryReplayCache::new(1);
        assert_eq!(cache.check_and_record("k", "a", 130, 100), Recorded::Fresh);
        assert_eq!(
            cache.check_and_record("k", "a", 130, 120),
            Recorded::Replayed
        );
        assert_eq!(
            cache.check_and_record("k", "a", 130, 130),
            Recorded::Replayed,
            "live through its last second"
        );
        assert_eq!(cache.check_and_record("j", "b", 150, 120), Recorded::Full);
        assert_eq!(
            cache.check_and_record("j", "b", 170, 131),
            Recorded::Fresh,
            "a expired"
        );
    }

    /// A call with an older `now` than one already seen must not record a
    /// proof whose entry the later call dropped.
    #[test]
    fn an_older_now_cannot_record_a_dropped_entry_again() {
        let cache = MemoryReplayCache::new(4);
        assert_eq!(cache.check_and_record("k", "a", 160, 150), Recorded::Fresh);
        // A later request drops `a`, whose last second was 160.
        assert_eq!(cache.check_and_record("k", "b", 200, 161), Recorded::Fresh);
        // A request stamped 160, when `a` was still acceptable, replays it.
        assert_eq!(cache.check_and_record("k", "a", 160, 160), Recorded::Stale);
        // The same after the clock steps back.
        assert_eq!(cache.check_and_record("k", "c", 170, 165), Recorded::Fresh);
        assert_eq!(cache.check_and_record("k", "d", 200, 100), Recorded::Fresh);
        assert_eq!(
            cache.check_and_record("k", "c", 170, 100),
            Recorded::Replayed
        );
        assert_eq!(cache.check_and_record("k", "e", 164, 100), Recorded::Stale);
    }

    #[test]
    fn owners_do_not_share_identifiers() {
        let cache = MemoryReplayCache::new(4);
        assert!(cache.check_and_record("k1", "a", 130, 100).is_fresh());
        assert!(cache.check_and_record("k2", "a", 130, 100).is_fresh());
        // Length prefixes: ("k", "1a") is not ("k1", "a").
        assert!(cache.check_and_record("k", "1a", 130, 100).is_fresh());
        assert!(cache.contains("k1", "a", 100));
        assert!(!cache.contains("k1", "a", 131));
    }

    #[test]
    fn one_owner_cannot_take_more_than_its_quota() {
        let cache = MemoryReplayCache::new(10).with_owner_quota(3);
        for jti in ["a", "b", "c"] {
            assert!(cache.check_and_record("flood", jti, 200, 100).is_fresh());
        }
        assert_eq!(
            cache.check_and_record("flood", "d", 200, 100),
            Recorded::OverQuota
        );
        // A replay is still reported as one, not as the quota.
        assert_eq!(
            cache.check_and_record("flood", "a", 200, 100),
            Recorded::Replayed
        );
        // Others are unaffected, and the owner gets room back as its entries
        // expire.
        assert!(cache.check_and_record("other", "a", 300, 100).is_fresh());
        assert!(cache.check_and_record("flood", "d", 300, 201).is_fresh());
        assert_eq!(cache.len(), 2, "the expired entries were dropped");
    }

    #[test]
    fn the_quota_holds_off_a_flood_from_one_owner() {
        let cache = MemoryReplayCache::new(100).with_owner_quota(25);
        let refused = (0..1000)
            .filter(|i| {
                !cache
                    .check_and_record("flood", &i.to_string(), 1_000, 100)
                    .is_fresh()
            })
            .count();
        assert_eq!(refused, 975);
        for i in 0..75 {
            assert!(
                cache
                    .check_and_record(&format!("caller-{i}"), "x", 1_000, 100)
                    .is_fresh()
            );
        }
    }

    /// A cache of `size` live entries, and the time `REFUSALS` insertions into
    /// it take, the fastest of three runs.
    fn time_refusals(size: usize) -> (MemoryReplayCache, Duration) {
        const REFUSALS: usize = 10_000;
        let cache = MemoryReplayCache::new(size);
        for i in 0..size {
            assert!(
                cache
                    .check_and_record(&i.to_string(), "x", 1_000, 100)
                    .is_fresh()
            );
        }
        let fastest = (0..3)
            .map(|run| {
                let start = Instant::now();
                for i in 0..REFUSALS {
                    assert_eq!(
                        cache.check_and_record("late", &format!("{run}-{i}"), 1_000, 101),
                        Recorded::Full
                    );
                }
                start.elapsed()
            })
            .min()
            .unwrap_or_default();
        (cache, fastest)
    }

    /// Inserting into a full cache costs O(log n), not a scan of every entry:
    /// refusing a proof takes about as long with 50 000 live entries as with
    /// 1 000. A scan per insertion makes it 50 times slower (and 10 000
    /// refusals at 50 000 entries take most of a minute).
    #[test]
    fn a_full_cache_refuses_without_scanning() {
        let (_, small) = time_refusals(1_000);
        let (cache, large) = time_refusals(50_000);
        assert!(
            large < small * 10 + Duration::from_millis(50),
            "refusals took {large:?} at 50 000 entries and {small:?} at 1 000"
        );
        // Expiry frees all of it in one pass.
        assert!(cache.check_and_record("late", "x", 2_000, 1_001).is_fresh());
        assert_eq!(cache.len(), 1);
    }
}
