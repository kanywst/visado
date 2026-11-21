//! Server-provided DPoP nonces (RFC 9449 §8 and §9), kept without state.
//!
//! A nonce is `base64url(version || issued_at || tag)`: one version byte,
//! the issue time as eight big-endian bytes, and the first
//! [`TAG_LEN`] bytes of an HMAC-SHA256 over a context label, the version
//! and the issue time. Nothing is stored per client: a nonce is accepted
//! while its tag verifies under one of the configured keys and its issue
//! time is within the lifetime. Replicas that share a key accept each
//! other's nonces.
//!
//! Nonces are not single use (RFC 9449 §11.1 allows a nonce to be accepted
//! many times); replay of a whole proof is the `jti` cache's job.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The shortest nonce key accepted, in bytes.
pub const MIN_KEY_LEN: usize = 32;

/// How many bytes of the HMAC a nonce carries.
pub const TAG_LEN: usize = 16;

const VERSION: u8 = 1;
const RAW_LEN: usize = 1 + 8 + TAG_LEN;
/// The length of every nonce, in base64url characters.
const ENCODED_LEN: usize = (RAW_LEN * 8).div_ceil(6);
/// Keeps these tags apart from any other HMAC made with the same key.
const CONTEXT: &[u8] = b"visado DPoP nonce";

/// Why a proof's `nonce` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NonceError {
    /// The proof has no `nonce` claim although the server requires one.
    Missing,
    /// The `nonce` is not a string of the shape this server issues.
    Malformed,
    /// The tag does not verify under any configured key: the nonce was not
    /// issued by this server, or the key has changed.
    Invalid,
    /// The nonce is older than its lifetime.
    Expired,
    /// The nonce claims to be issued later than now, beyond the allowed
    /// skew between replicas. This server never issued it.
    Future,
}

impl NonceError {
    /// A short reason for logs and audit records.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Missing => "DPoP nonce missing",
            Self::Malformed => "DPoP nonce malformed",
            Self::Invalid => "DPoP nonce not issued by this server",
            Self::Expired => "DPoP nonce expired",
            Self::Future => "DPoP nonce issued in the future",
        }
    }

    /// The stable reason code: `dpop.nonce_missing`, `dpop.nonce_expired`,
    /// or `dpop.nonce_invalid` for every other case.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "dpop.nonce_missing",
            Self::Expired => "dpop.nonce_expired",
            Self::Malformed | Self::Invalid | Self::Future => "dpop.nonce_invalid",
        }
    }
}

/// Issues and checks nonces. The first key issues; every key verifies, so
/// a key can be rotated by putting the new one first and keeping the old
/// one until its nonces have expired.
#[derive(Clone)]
pub struct Nonces {
    keys: Vec<Vec<u8>>,
    lifetime: i64,
    max_skew: i64,
}

// The keys are secret.
impl std::fmt::Debug for Nonces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nonces")
            .field("keys", &self.keys.len())
            .field("lifetime", &self.lifetime)
            .field("max_skew", &self.max_skew)
            .finish()
    }
}

impl Nonces {
    /// Nonces made with `key`, accepted for `lifetime` seconds after they
    /// are issued. The default skew is 5 seconds.
    ///
    /// # Errors
    ///
    /// When `key` is shorter than [`MIN_KEY_LEN`] or `lifetime` is not
    /// positive.
    pub fn new(key: &[u8], lifetime: i64) -> Result<Self, &'static str> {
        if key.len() < MIN_KEY_LEN {
            return Err("DPoP nonce key shorter than 32 bytes");
        }
        if lifetime <= 0 {
            return Err("DPoP nonce lifetime must be positive");
        }
        Ok(Self {
            keys: vec![key.to_vec()],
            lifetime,
            max_skew: 5,
        })
    }

    /// Also accepts nonces made with `key`, which issues none.
    ///
    /// # Errors
    ///
    /// When `key` is shorter than [`MIN_KEY_LEN`].
    pub fn with_previous_key(mut self, key: &[u8]) -> Result<Self, &'static str> {
        if key.len() < MIN_KEY_LEN {
            return Err("DPoP nonce key shorter than 32 bytes");
        }
        self.keys.push(key.to_vec());
        Ok(self)
    }

    /// How many seconds a nonce's issue time may be ahead of now, for
    /// replicas whose clocks differ. Negative values count as 0.
    #[must_use]
    pub fn with_max_skew(mut self, seconds: i64) -> Self {
        self.max_skew = seconds.max(0);
        self
    }

    /// Seconds a nonce is accepted for after it is issued.
    #[must_use]
    pub const fn lifetime(&self) -> i64 {
        self.lifetime
    }

    /// A nonce issued at `now`. A time before 1970 is issued as 0, which
    /// is already expired.
    #[must_use]
    pub fn issue(&self, now: i64) -> String {
        let issued = u64::try_from(now).unwrap_or(0).to_be_bytes();
        let mut raw = Vec::with_capacity(RAW_LEN);
        raw.push(VERSION);
        raw.extend_from_slice(&issued);
        raw.extend_from_slice(&tag(&self.keys[0], issued)[..TAG_LEN]);
        URL_SAFE_NO_PAD.encode(raw)
    }

    /// Checks `nonce` at `now` and returns its issue time.
    ///
    /// # Errors
    ///
    /// [`NonceError::Malformed`] for anything this server does not issue,
    /// [`NonceError::Invalid`] when no key verifies the tag, then
    /// [`NonceError::Future`] or [`NonceError::Expired`] for the time.
    pub fn check(&self, nonce: &str, now: i64) -> Result<i64, NonceError> {
        if nonce.len() != ENCODED_LEN {
            return Err(NonceError::Malformed);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| NonceError::Malformed)?;
        let (Some(&VERSION), Some(issued), Some(presented)) =
            (raw.first(), raw.get(1..9), raw.get(9..RAW_LEN))
        else {
            return Err(NonceError::Malformed);
        };
        if raw.len() != RAW_LEN {
            return Err(NonceError::Malformed);
        }
        let issued: [u8; 8] = issued.try_into().map_err(|_| NonceError::Malformed)?;
        let verified = self.keys.iter().any(|key| {
            let mut mac = mac(key);
            mac.update(&message(issued));
            mac.verify_truncated_left(presented).is_ok()
        });
        if !verified {
            return Err(NonceError::Invalid);
        }
        let issued_at =
            i64::try_from(u64::from_be_bytes(issued)).map_err(|_| NonceError::Future)?;
        if issued_at > now.saturating_add(self.max_skew) {
            return Err(NonceError::Future);
        }
        if now.saturating_sub(issued_at) >= self.lifetime {
            return Err(NonceError::Expired);
        }
        Ok(issued_at)
    }
}

fn mac(key: &[u8]) -> Hmac<Sha256> {
    // HMAC takes a key of any length.
    <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap_or_else(|_| unreachable!())
}

fn message(issued: [u8; 8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CONTEXT.len() + 9);
    message.extend_from_slice(CONTEXT);
    message.push(VERSION);
    message.extend_from_slice(&issued);
    message
}

fn tag(key: &[u8], issued: [u8; 8]) -> Vec<u8> {
    let mut mac = mac(key);
    mac.update(&message(issued));
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{ENCODED_LEN, NonceError, Nonces};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    const NOW: i64 = 1_800_000_000;

    fn nonces() -> Nonces {
        Nonces::new(&[7; 32], 300).unwrap()
    }

    #[test]
    fn a_fresh_nonce_is_accepted_until_its_lifetime_ends() {
        let n = nonces();
        let nonce = n.issue(NOW);
        assert_eq!(nonce.len(), ENCODED_LEN);
        assert_eq!(n.check(&nonce, NOW), Ok(NOW));
        assert_eq!(n.check(&nonce, NOW + 299), Ok(NOW));
        assert_eq!(n.check(&nonce, NOW + 300), Err(NonceError::Expired));
        assert_eq!(n.check(&nonce, i64::MAX), Err(NonceError::Expired));
    }

    #[test]
    fn the_nonce_syntax_is_rfc_9449_nqchar() {
        // nonce = 1*NQCHAR, NQCHAR = %x21 / %x23-5B / %x5D-7E (§8.1).
        let nonce = nonces().issue(NOW);
        assert!(
            nonce
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        );
    }

    #[test]
    fn a_nonce_from_the_future_is_refused_beyond_the_skew() {
        let n = nonces();
        let later = n.issue(NOW + 5);
        assert_eq!(n.check(&later, NOW), Ok(NOW + 5));
        let later = n.issue(NOW + 6);
        assert_eq!(n.check(&later, NOW), Err(NonceError::Future));
        let strict = nonces().with_max_skew(-3);
        assert_eq!(
            strict.check(&strict.issue(NOW + 1), NOW),
            Err(NonceError::Future)
        );
        assert_eq!(strict.check(&strict.issue(NOW), NOW), Ok(NOW));
    }

    #[test]
    fn another_key_or_a_changed_byte_is_invalid() {
        let n = nonces();
        let other = Nonces::new(&[8; 32], 300).unwrap();
        assert_eq!(n.check(&other.issue(NOW), NOW), Err(NonceError::Invalid));

        let mut raw = URL_SAFE_NO_PAD.decode(n.issue(NOW)).unwrap();
        // A later issue time with the old tag.
        raw[8] ^= 1;
        assert_eq!(
            n.check(&URL_SAFE_NO_PAD.encode(&raw), NOW),
            Err(NonceError::Invalid)
        );
        raw[8] ^= 1;
        let last = raw.len() - 1;
        raw[last] ^= 0x80;
        assert_eq!(
            n.check(&URL_SAFE_NO_PAD.encode(&raw), NOW),
            Err(NonceError::Invalid)
        );
    }

    #[test]
    fn a_previous_key_still_verifies_but_does_not_issue() {
        let old = Nonces::new(&[8; 32], 300).unwrap();
        let rotated = Nonces::new(&[9; 32], 300)
            .unwrap()
            .with_previous_key(&[8; 32])
            .unwrap();
        assert_eq!(rotated.check(&old.issue(NOW), NOW), Ok(NOW));
        assert_eq!(
            old.check(&rotated.issue(NOW), NOW),
            Err(NonceError::Invalid)
        );
    }

    #[test]
    fn malformed_nonces() {
        let n = nonces();
        let good = n.issue(NOW);
        let mut raw = URL_SAFE_NO_PAD.decode(&good).unwrap();
        raw[0] = 2;
        let wrong_version = URL_SAFE_NO_PAD.encode(&raw);
        // Same length, but the last character carries bits past the end.
        let mut noncanonical = good[..ENCODED_LEN - 1].to_owned();
        let last = good.as_bytes()[ENCODED_LEN - 1];
        noncanonical.push(char::from(if last == b'A' { b'B' } else { b'A' }));
        for nonce in [
            "",
            "x",
            &good[1..],
            &format!("{good}A"),
            &good.replace(|_: char| true, "!"),
            &wrong_version,
            &format!("{}=", &good[..ENCODED_LEN - 1]),
        ] {
            assert_eq!(n.check(nonce, NOW), Err(NonceError::Malformed), "{nonce:?}");
        }
        // A changed final character is either non-canonical base64 or a
        // different tag; never accepted.
        assert!(n.check(&noncanonical, NOW).is_err());
    }

    #[test]
    fn keys_and_lifetimes_are_checked() {
        assert!(Nonces::new(&[1; 31], 300).is_err());
        assert!(Nonces::new(&[1; 32], 0).is_err());
        assert!(Nonces::new(&[1; 32], -1).is_err());
        assert!(nonces().with_previous_key(&[1; 31]).is_err());
        assert_eq!(nonces().lifetime(), 300);
        // The key never shows in Debug.
        assert!(!format!("{:?}", nonces()).contains('7'));
    }

    #[test]
    fn codes() {
        assert_eq!(NonceError::Missing.code(), "dpop.nonce_missing");
        assert_eq!(NonceError::Expired.code(), "dpop.nonce_expired");
        for e in [
            NonceError::Malformed,
            NonceError::Invalid,
            NonceError::Future,
        ] {
            assert_eq!(e.code(), "dpop.nonce_invalid");
        }
    }
}
