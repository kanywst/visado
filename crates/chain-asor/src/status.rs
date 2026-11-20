//! Step 7: Token Status Lists (draft-ietf-oauth-status-list-21).
//!
//! A Delegation Token may carry `status.status_list` with an index `idx` and
//! a `uri`. The verifier looks the index up in the Status List Token for that
//! `uri`, which a [`StatusLists`] source supplies already verified by a
//! [`StatusListVerifier`]. A list that cannot be obtained, has expired or has
//! outlived its time to live leaves the status unknown, which denies.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use miniz_oxide::inflate::{self, TINFLStatus};
use visado_chain::jose;
use visado_chain::json::{self, Value};

use crate::verify::{Alg, TrustAnchor};
use StatusListError::Malformed;

/// The JOSE `typ` values of a Status List Token (§5.1).
pub const STATUS_LIST_TYPS: [&str; 2] = ["statuslist+jwt", "application/statuslist+jwt"];

/// How long a cached Status List Token is trusted, in seconds, when it
/// carries no shorter `ttl` and no earlier `exp`.
pub const DEFAULT_STATUS_MAX_AGE: i64 = 300;

/// The Status Type values of §7.1.
const VALID: u8 = 0x00;
const INVALID: u8 = 0x01;
const SUSPENDED: u8 = 0x02;

/// What a Delegation Token's `status` claim refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StatusRef {
    /// `status.status_list`: an index into the list at `uri`.
    List { idx: u64, uri: String },
    /// A `status` object without `status_list`: a mechanism this verifier
    /// does not implement.
    Other,
}

/// Reads the `status` claim (§6.2 of the status list draft). An absent
/// claim is `None`; one of the wrong shape is an error, which the caller
/// reports as `malformed`.
pub(crate) fn reference(status: Option<&Value>) -> Result<Option<StatusRef>, &'static str> {
    let Some(status) = status else {
        return Ok(None);
    };
    if status.as_object().is_none_or(<[_]>::is_empty) {
        return Err("status is not a non-empty object");
    }
    let Some(list) = status.get("status_list") else {
        return Ok(Some(StatusRef::Other));
    };
    if list.as_object().is_none() {
        return Err("status_list is not an object");
    }
    let idx = list
        .get("idx")
        .and_then(Value::as_integer)
        .and_then(|i| u64::try_from(i).ok())
        .ok_or("status_list.idx is not a non-negative integer")?;
    let uri = list
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
        .ok_or("status_list.uri is not a non-empty string")?
        .to_owned();
    Ok(Some(StatusRef::List { idx, uri }))
}

/// Why a Status List Token could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusListError {
    /// No list is configured for the token's `uri`.
    UnknownList,
    /// The list could not be fetched.
    Unavailable,
    /// The token, or its decompressed list, exceeds the size limit.
    TooLarge,
    /// The token is not a JWT with the claims of §5.1, or `lst` is not
    /// base64url ZLIB data.
    Malformed(&'static str),
    /// The `typ` is not `statuslist+jwt`.
    WrongType,
    /// The signature does not verify under a trusted key, or the algorithm
    /// is not accepted.
    SignatureInvalid,
    /// The `sub` is not the `uri` the list was requested for.
    SubjectMismatch,
    /// The token is past its `exp` or before its `nbf`.
    Expired,
    /// The token was issued before the one already held.
    Rollback,
}

impl StatusListError {
    /// A short reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnknownList => "no status list is configured for this uri",
            Self::Unavailable => "status list could not be fetched",
            Self::TooLarge => "status list token too large",
            Self::Malformed(reason) => reason,
            Self::WrongType => "status list typ is not statuslist+jwt",
            Self::SignatureInvalid => "status list signature does not verify under a trusted key",
            Self::SubjectMismatch => "status list sub is not the uri",
            Self::Expired => "status list token expired or not yet valid",
            Self::Rollback => "status list was issued before the one held",
        }
    }
}

impl fmt::Display for StatusListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for StatusListError {}

/// A verified Status List Token, as fetched at one instant.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusList {
    uri: String,
    bits: u8,
    bytes: Vec<u8>,
    issued_at: i64,
    expires_at: Option<i64>,
    ttl: Option<i64>,
    fetched_at: i64,
}

impl fmt::Debug for StatusList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusList")
            .field("uri", &self.uri)
            .field("bits", &self.bits)
            .field("len", &self.bytes.len())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("ttl", &self.ttl)
            .field("fetched_at", &self.fetched_at)
            .finish()
    }
}

impl StatusList {
    /// The list's URI: the token's `sub`.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The token's `iat`.
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// The token's `exp`, if it has one.
    #[must_use]
    pub const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    /// When the token was fetched and verified.
    #[must_use]
    pub const fn fetched_at(&self) -> i64 {
        self.fetched_at
    }

    /// When this cached copy stops being trusted for want of a refresh: its
    /// fetch time plus the shorter of its `ttl` and `max_age`.
    #[must_use]
    pub fn stale_at(&self, max_age: i64) -> i64 {
        let age = self.ttl.map_or(max_age, |ttl| ttl.min(max_age));
        self.fetched_at.saturating_add(age)
    }

    /// The status value at `idx`, or `None` if `idx` is out of range (§4.1:
    /// bits are packed from the least significant bit of each byte).
    #[must_use]
    pub fn status(&self, idx: u64) -> Option<u8> {
        let per_byte = u64::from(8 / self.bits);
        let byte = usize::try_from(idx / per_byte).ok()?;
        let shift = u32::try_from(idx % per_byte).ok()? * u32::from(self.bits);
        let mask = (1u32 << self.bits) - 1;
        let value = (u32::from(*self.bytes.get(byte)?) >> shift) & mask;
        u8::try_from(value).ok()
    }
}

/// Verifies Status List Tokens (§5.1 and §8.3 of the status list draft)
/// against the keys trusted to sign them.
#[derive(Debug, Clone)]
pub struct StatusListVerifier {
    anchors: Vec<TrustAnchor>,
    algorithms: Vec<Alg>,
    max_token_size: usize,
    max_list_size: usize,
}

impl StatusListVerifier {
    /// A verifier trusting `anchors`, accepting `Ed25519` and `ES256`. A
    /// token with an `iss` must name the anchor's issuer. Tokens are at most
    /// 1 MiB, and lists at most 8 MiB once decompressed.
    #[must_use]
    pub fn new(anchors: Vec<TrustAnchor>) -> Self {
        Self {
            anchors,
            algorithms: vec![Alg::Ed25519, Alg::Es256],
            max_token_size: 1024 * 1024,
            max_list_size: 8 * 1024 * 1024,
        }
    }

    /// Replaces the list of accepted algorithms.
    #[must_use]
    pub fn with_algorithms(mut self, algorithms: Vec<Alg>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Replaces the size limits: the token in bytes, and the list in bytes
    /// once decompressed.
    #[must_use]
    pub fn with_max_sizes(mut self, token: usize, list: usize) -> Self {
        self.max_token_size = token;
        self.max_list_size = list;
        self
    }

    /// Verifies `token`, fetched at `now` for `uri`.
    ///
    /// # Errors
    ///
    /// The first check that failed.
    pub fn verify(&self, token: &str, uri: &str, now: i64) -> Result<StatusList, StatusListError> {
        if token.len() > self.max_token_size {
            return Err(StatusListError::TooLarge);
        }
        let jws = jose::split(token).ok_or(Malformed("status list is not a compact JWS"))?;
        let object = |part| {
            jose::b64(part)
                .and_then(|bytes| json::parse(&bytes).ok())
                .filter(|v| v.as_object().is_some())
                .ok_or(Malformed(
                    "status list header or claims are not a JSON object",
                ))
        };
        let header = object(jws.header)?;
        let claims = object(jws.payload)?;
        let typ = header.get("typ").and_then(Value::as_str);
        if !typ.is_some_and(|t| STATUS_LIST_TYPS.contains(&t)) {
            return Err(StatusListError::WrongType);
        }
        if header.get("crit").is_some() {
            return Err(Malformed("status list crit is not understood"));
        }
        self.signature(&header, &claims, jws)?;
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(Malformed("status list sub is not a string"))?;
        if sub != uri {
            return Err(StatusListError::SubjectMismatch);
        }
        let (issued_at, expires_at, ttl) = times(&claims, now)?;
        let (bits, bytes) = self.list(claims.get("status_list"))?;
        Ok(StatusList {
            uri: uri.to_owned(),
            bits,
            bytes,
            issued_at,
            expires_at,
            ttl,
            fetched_at: now,
        })
    }

    /// The signature, under an accepted algorithm and a trusted key: the
    /// anchor named by `kid` if one is, any anchor otherwise.
    fn signature(
        &self,
        header: &Value,
        claims: &Value,
        jws: jose::Compact<'_>,
    ) -> Result<(), StatusListError> {
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .and_then(Alg::from_name)
            .filter(|a| self.algorithms.contains(a))
            .ok_or(StatusListError::SignatureInvalid)?;
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| self.anchors.iter().any(|a| a.kid() == Some(*kid)));
        let iss = match claims.get("iss") {
            None => None,
            Some(iss) => Some(
                iss.as_str()
                    .ok_or(Malformed("status list iss is not a string"))?,
            ),
        };
        self.anchors
            .iter()
            .filter(|a| kid.is_none() || a.kid() == kid)
            .filter(|a| a.alg() == alg && iss.is_none_or(|iss| a.issuer() == iss))
            .any(|a| a.verifies(jws))
            .then_some(())
            .ok_or(StatusListError::SignatureInvalid)
    }

    /// `status_list`: `bits` and the decompressed `lst` (§4.2).
    fn list(&self, list: Option<&Value>) -> Result<(u8, Vec<u8>), StatusListError> {
        let list = list
            .filter(|l| l.as_object().is_some())
            .ok_or(Malformed("status_list is not an object"))?;
        let bits = list
            .get("bits")
            .and_then(Value::as_integer)
            .and_then(|b| u8::try_from(b).ok())
            .filter(|b| matches!(b, 1 | 2 | 4 | 8))
            .ok_or(Malformed("status_list.bits is not 1, 2, 4 or 8"))?;
        let compressed = list
            .get("lst")
            .and_then(Value::as_str)
            .and_then(jose::b64)
            .ok_or(Malformed("status_list.lst is not base64url"))?;
        let bytes = inflate::decompress_to_vec_zlib_with_limit(&compressed, self.max_list_size)
            .map_err(|e| match e.status {
                TINFLStatus::HasMoreOutput => StatusListError::TooLarge,
                _ => Malformed("status_list.lst is not ZLIB data"),
            })?;
        Ok((bits, bytes))
    }
}

/// `iat` (required), `exp` and `nbf` (checked against `now`) and `ttl` (a
/// positive integer), all integers.
fn times(claims: &Value, now: i64) -> Result<(i64, Option<i64>, Option<i64>), StatusListError> {
    let int = |name, reason| match claims.get(name) {
        None => Ok(None),
        Some(v) => v.as_integer().map(Some).ok_or(Malformed(reason)),
    };
    let issued_at = int("iat", "status list iat is not an integer")?
        .ok_or(Malformed("status list iat is not an integer"))?;
    let expires_at = int("exp", "status list exp is not an integer")?;
    let not_before = int("nbf", "status list nbf is not an integer")?;
    let ttl = int("ttl", "status list ttl is not a positive integer")?;
    if ttl.is_some_and(|t| t <= 0) {
        return Err(Malformed("status list ttl is not a positive integer"));
    }
    if expires_at.is_some_and(|exp| now >= exp) || not_before.is_some_and(|nbf| now < nbf) {
        return Err(StatusListError::Expired);
    }
    Ok((issued_at, expires_at, ttl))
}

/// Where step 7 gets Status List Tokens.
pub trait StatusLists: Send + Sync {
    /// The list most recently obtained for `uri`, or why there is none.
    ///
    /// # Errors
    ///
    /// Why no list is held for `uri`.
    fn get(&self, uri: &str) -> Result<Arc<StatusList>, StatusListError>;
}

/// Status lists held in memory, filled by whatever fetches them.
#[derive(Debug, Default)]
pub struct MemoryStatusLists {
    lists: RwLock<HashMap<String, Result<Arc<StatusList>, StatusListError>>>,
}

impl MemoryStatusLists {
    /// An empty set: every lookup is [`StatusListError::UnknownList`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the outcome of fetching `uri`. A list replaces the one held
    /// unless it was issued earlier. A failure, or an earlier list, keeps a
    /// list already held, which step 7 trusts until it goes stale; with no
    /// list held, the failure is what [`StatusLists::get`] returns.
    ///
    /// # Errors
    ///
    /// The failure, or [`StatusListError::Rollback`] for an earlier list, or
    /// [`StatusListError::SubjectMismatch`] for a list of another `uri`.
    pub fn update(
        &self,
        uri: &str,
        fetched: Result<StatusList, StatusListError>,
    ) -> Result<(), StatusListError> {
        let Ok(mut lists) = self.lists.write() else {
            return Err(StatusListError::Unavailable);
        };
        let held = lists
            .get(uri)
            .and_then(|held| held.as_ref().ok())
            .map(|h| h.issued_at);
        let error = match fetched {
            Ok(list) if list.uri != uri => StatusListError::SubjectMismatch,
            Ok(list) if held.is_some_and(|iat| list.issued_at < iat) => StatusListError::Rollback,
            Ok(list) => {
                lists.insert(uri.to_owned(), Ok(Arc::new(list)));
                return Ok(());
            }
            Err(e) => e,
        };
        if held.is_none() {
            lists.insert(uri.to_owned(), Err(error));
        }
        Err(error)
    }
}

impl StatusLists for MemoryStatusLists {
    fn get(&self, uri: &str) -> Result<Arc<StatusList>, StatusListError> {
        let lists = self
            .lists
            .read()
            .map_err(|_| StatusListError::Unavailable)?;
        lists
            .get(uri)
            .cloned()
            .unwrap_or(Err(StatusListError::UnknownList))
    }
}

/// The outcome of looking one token up: `Ok` if `VALID`, else the outcome
/// and reason.
pub(crate) fn check(
    reference: &StatusRef,
    lists: Option<&dyn StatusLists>,
    max_age: i64,
    now: i64,
) -> Result<(), (crate::Outcome, &'static str)> {
    use crate::Outcome::{Revoked, StatusUnknown};
    let StatusRef::List { idx, uri } = reference else {
        return Err((StatusUnknown, "status mechanism not supported"));
    };
    let lists = lists.ok_or((StatusUnknown, "no status lists are configured"))?;
    let list = lists.get(uri).map_err(|e| (StatusUnknown, e.reason()))?;
    if list.uri != *uri {
        return Err((StatusUnknown, StatusListError::SubjectMismatch.reason()));
    }
    if list.expires_at.is_some_and(|exp| now >= exp) {
        return Err((StatusUnknown, "status list expired"));
    }
    if now >= list.stale_at(max_age) {
        return Err((StatusUnknown, "status list outlived its time to live"));
    }
    match list.status(*idx) {
        None => Err((StatusUnknown, "status index out of range")),
        Some(VALID) => Ok(()),
        Some(INVALID) => Err((Revoked, "token is revoked")),
        Some(SUSPENDED) => Err((Revoked, "token is suspended")),
        Some(_) => Err((StatusUnknown, "status value not understood")),
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusList, StatusRef, reference};
    use visado_chain::json::parse;

    fn list(bits: u8, bytes: &[u8]) -> StatusList {
        StatusList {
            uri: "u".into(),
            bits,
            bytes: bytes.to_vec(),
            issued_at: 0,
            expires_at: None,
            ttl: None,
            fetched_at: 0,
        }
    }

    /// The byte arrays of §4.1.
    #[test]
    fn bit_packing() {
        let one = list(1, &[0xb9, 0xa3]);
        let expect = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        for (i, v) in expect.iter().enumerate() {
            assert_eq!(one.status(i as u64), Some(*v), "bits=1 idx {i}");
        }
        assert_eq!(one.status(16), None);
        let two = list(2, &[0xc9, 0x44, 0xf9]);
        let expect = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
        for (i, v) in expect.iter().enumerate() {
            assert_eq!(two.status(i as u64), Some(*v), "bits=2 idx {i}");
        }
        assert_eq!(two.status(12), None);
        assert_eq!(list(8, &[7, 255]).status(1), Some(255));
        assert_eq!(list(4, &[0x21]).status(1), Some(2));
        assert_eq!(list(1, &[]).status(u64::MAX), None);
    }

    #[test]
    fn references() {
        let r = |json: &str| reference(Some(&parse(json.as_bytes()).unwrap()));
        assert_eq!(reference(None), Ok(None));
        assert_eq!(
            r(r#"{"status_list":{"idx":3,"uri":"https://s/1"}}"#),
            Ok(Some(StatusRef::List {
                idx: 3,
                uri: "https://s/1".into()
            }))
        );
        assert_eq!(r(r#"{"other":{}}"#), Ok(Some(StatusRef::Other)));
        for bad in [
            "{}",
            "[]",
            r#"{"status_list":1}"#,
            r#"{"status_list":{"idx":-1,"uri":"u"}}"#,
            r#"{"status_list":{"idx":1.5,"uri":"u"}}"#,
            r#"{"status_list":{"idx":1,"uri":""}}"#,
            r#"{"status_list":{"uri":"u"}}"#,
        ] {
            assert!(r(bad).is_err(), "{bad}");
        }
    }
}
