//! The audit record: one per decision, with the minimum of
//! draft-ietf-wimse-aims §11, hash-chained. No credential header, proof or
//! body is copied into it, and JWS-looking text that reaches a text member
//! (a token in the path, a tool name or a `sub`) is replaced by `[token]`
//! before the member is cut to length.
//!
//! The gate writes each [`AuditRecord`] as one event under the
//! `visado::audit` tracing target, every member of the record a field of the
//! event. The schema is documented in `docs/audit.md`; members are only ever
//! added, and [`AUDIT_VERSION`] changes when one changes meaning.
//!
//! Records are chained: each carries the [`hash`](AuditRecord::hash) of the
//! previous record in [`prev`](AuditRecord::prev), and its own hash is
//! SHA-256 over the record without `hash` (see [`AuditRecord::digest`]). A
//! record removed from or changed inside the log breaks the chain, which
//! [`verify_chain`] finds. A restart starts a new chain at `seq` 0.

use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The version of the record schema.
pub const AUDIT_VERSION: u32 = 1;

/// One decision.
///
/// In every text member (`id`, `txn`, `agent`, `principal`, `chain_issuer`,
/// each element of `chain_actors`, `resource`, `tool`, `action`, `detail`)
/// the gate replaces JWS-looking text by `[token]`, then cuts the member to
/// [`MAX_TEXT`](crate::recent::MAX_TEXT) characters.
///
/// Member order is part of the schema: [`digest`](Self::digest) hashes the
/// members in this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// [`AUDIT_VERSION`].
    pub audit_version: u32,
    /// Position in this process's chain, from 0.
    pub seq: u64,
    /// `hash` of the previous record, empty for `seq` 0.
    pub prev: String,
    /// The check's own identifier, unique per decision.
    pub id: String,
    /// The correlation id: the transaction (`txn`) the request belongs to,
    /// or empty when the gate stopped before it was known.
    pub txn: String,
    /// When the gate decided, in seconds since the Unix epoch.
    pub time: u64,
    /// The agent: the authenticated caller, empty if authentication failed.
    pub agent: String,
    /// How the agent authenticated (`wit-wpt`, `wit-httpsig`, `mtls`,
    /// `jwt-svid`, `bearer`, `oauth-dpop`), empty if it did not.
    pub auth_method: String,
    /// Whether the agent proved possession of a key for this request, rather
    /// than presenting a bearer credential.
    pub sender_constrained: bool,
    /// The delegating subject: on whose behalf, empty until known.
    pub principal: String,
    /// The verified delegation chain's format, empty without one.
    pub chain_profile: String,
    /// The chain's trust anchor (issuer of the first hop).
    pub chain_issuer: String,
    /// The number of hops in the chain, 0 without one.
    pub chain_hops: u32,
    /// The hop actors, first hop first, as a JSON array of strings.
    pub chain_actors: String,
    /// How the chain's depth bound was read (`aat-holder-cap`,
    /// `asor-strict` or `uncapped`); empty without a chain.
    pub depth_semantics: String,
    /// The resource: `scheme://authority/path`, without the query.
    pub resource: String,
    /// The MCP tool of a JSON-RPC `tools/call` body, otherwise empty.
    pub tool: String,
    /// The action: the HTTP method.
    pub action: String,
    /// `allow` or `deny`.
    pub decision: String,
    /// The HTTP status: 200 for an allow.
    pub status: u16,
    /// The stable reason code: `ok` for an allow.
    pub reason: String,
    /// Why, in words, for a denial.
    pub detail: String,
    /// What the PDP said: `allow`, `deny`, `error:<code>`, or `not_asked`.
    pub pdp: String,
    /// What the caller can do about the decision: `none` (allowed),
    /// `reauthenticate` (401, see the challenge), `retry_later` (503) or
    /// `refused`.
    pub remediation: String,
    /// SHA-256 of this record without `hash`, lowercase hex.
    pub hash: String,
}

impl AuditRecord {
    /// SHA-256, lowercase hex, over the record's JSON serialization (members
    /// in declaration order, no whitespace) with `hash` left out, or `None`
    /// if the record cannot be serialized.
    #[must_use]
    pub fn digest(&self) -> Option<String> {
        let text = serde_json::to_string(&Ordered(self)).ok()?;
        Some(hex(&Sha256::digest(text.as_bytes())))
    }
}

/// The record without `hash`, serialized in declaration order.
struct Ordered<'a>(&'a AuditRecord);

impl Serialize for Ordered<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let r = self.0;
        let mut m = s.serialize_struct("AuditRecord", 24)?;
        m.serialize_field("audit_version", &r.audit_version)?;
        m.serialize_field("seq", &r.seq)?;
        m.serialize_field("prev", &r.prev)?;
        m.serialize_field("id", &r.id)?;
        m.serialize_field("txn", &r.txn)?;
        m.serialize_field("time", &r.time)?;
        m.serialize_field("agent", &r.agent)?;
        m.serialize_field("auth_method", &r.auth_method)?;
        m.serialize_field("sender_constrained", &r.sender_constrained)?;
        m.serialize_field("principal", &r.principal)?;
        m.serialize_field("chain_profile", &r.chain_profile)?;
        m.serialize_field("chain_issuer", &r.chain_issuer)?;
        m.serialize_field("chain_hops", &r.chain_hops)?;
        m.serialize_field("chain_actors", &r.chain_actors)?;
        m.serialize_field("depth_semantics", &r.depth_semantics)?;
        m.serialize_field("resource", &r.resource)?;
        m.serialize_field("tool", &r.tool)?;
        m.serialize_field("action", &r.action)?;
        m.serialize_field("decision", &r.decision)?;
        m.serialize_field("status", &r.status)?;
        m.serialize_field("reason", &r.reason)?;
        m.serialize_field("detail", &r.detail)?;
        m.serialize_field("pdp", &r.pdp)?;
        m.serialize_field("remediation", &r.remediation)?;
        m.end()
    }
}

/// `text` with every JWS-looking run (`eyJ` followed by base64url and dots,
/// as a JOSE header starts) replaced by `[token]`, so an error message that
/// quotes a credential does not put it in the log.
pub(crate) fn scrub_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("eyJ") {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
            .unwrap_or(tail.len());
        out.push_str("[token]");
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Why a sequence of records is not one unbroken chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreak {
    /// The record at this index does not hash to its `hash`.
    Altered(usize),
    /// The record at this index does not follow the one before it: its
    /// `prev` or `seq` does not match.
    Gap(usize),
}

/// Checks that `records`, in log order, form one chain: each hashes to its
/// own `hash` and names the previous record's hash and the next `seq`. The
/// first record may start anywhere, so a tail of the log can be checked.
///
/// # Errors
///
/// The first [`ChainBreak`] found.
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), ChainBreak> {
    for (i, record) in records.iter().enumerate() {
        if record.digest().as_deref() != Some(record.hash.as_str()) {
            return Err(ChainBreak::Altered(i));
        }
        if let Some(before) = i.checked_sub(1).map(|j| &records[j])
            && (record.prev != before.hash || before.seq.checked_add(1) != Some(record.seq))
        {
            return Err(ChainBreak::Gap(i));
        }
    }
    Ok(())
}

/// The state of this process's chain.
#[derive(Debug, Default)]
pub(crate) struct AuditChain {
    state: Mutex<(u64, String)>,
}

impl AuditChain {
    /// Links `record` to the chain, sets its `seq`, `prev` and `hash`, and
    /// writes it, all under one lock so the log order is the chain order.
    /// The write happens under the lock for that reason: a slow log sink
    /// slows every decision, which the per-line size bound keeps small.
    pub(crate) fn append(&self, mut record: AuditRecord) -> AuditRecord {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        record.seq = state.0;
        record.prev.clone_from(&state.1);
        // A record that cannot be serialized gets an empty hash, which
        // verify_chain reports as altered: the break shows in the log.
        record.hash = record.digest().unwrap_or_else(|| {
            tracing::error!(target: "visado::audit", id = %record.id, "audit record not serializable");
            String::new()
        });
        emit(&record);
        state.0 = state.0.saturating_add(1);
        state.1.clone_from(&record.hash);
        record
    }
}

fn emit(r: &AuditRecord) {
    tracing::info!(
        target: "visado::audit",
        audit_version = r.audit_version,
        seq = r.seq,
        prev = %r.prev,
        id = %r.id,
        txn = %r.txn,
        time = r.time,
        agent = %r.agent,
        auth_method = %r.auth_method,
        sender_constrained = r.sender_constrained,
        principal = %r.principal,
        chain_profile = %r.chain_profile,
        chain_issuer = %r.chain_issuer,
        chain_hops = r.chain_hops,
        chain_actors = %r.chain_actors,
        depth_semantics = %r.depth_semantics,
        resource = %r.resource,
        tool = %r.tool,
        action = %r.action,
        decision = %r.decision,
        status = r.status,
        reason = %r.reason,
        detail = %r.detail,
        pdp = %r.pdp,
        remediation = %r.remediation,
        hash = %r.hash,
    );
}

#[cfg(test)]
mod tests {
    use super::{AUDIT_VERSION, AuditChain, AuditRecord, ChainBreak, verify_chain};

    fn record(id: &str) -> AuditRecord {
        AuditRecord {
            audit_version: AUDIT_VERSION,
            seq: 0,
            prev: String::new(),
            id: id.into(),
            txn: "t".into(),
            time: 1,
            agent: "spiffe://td.example/agent-a".into(),
            auth_method: "wit-wpt".into(),
            sender_constrained: true,
            principal: "bob".into(),
            chain_profile: String::new(),
            chain_issuer: String::new(),
            chain_hops: 0,
            chain_actors: "[]".into(),
            depth_semantics: String::new(),
            resource: "http://tools.td.example/tickets".into(),
            tool: String::new(),
            action: "GET".into(),
            decision: "allow".into(),
            status: 200,
            reason: "ok".into(),
            detail: String::new(),
            pdp: "allow".into(),
            remediation: "none".into(),
            hash: String::new(),
        }
    }

    #[test]
    fn appended_records_form_a_chain() {
        let chain = AuditChain::default();
        let records: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|id| chain.append(record(id)))
            .collect();
        assert_eq!(records[0].seq, 0);
        assert_eq!(records[0].prev, "");
        assert_eq!(records[1].prev, records[0].hash);
        assert_eq!(records[2].seq, 2);
        assert_eq!(records[0].hash.len(), 64);
        assert_eq!(verify_chain(&records), Ok(()));
        // A tail of the log is checked on its own.
        assert_eq!(verify_chain(&records[1..]), Ok(()));
    }

    #[test]
    fn an_altered_record_breaks_the_chain() {
        let chain = AuditChain::default();
        let mut records: Vec<_> = ["a", "b"]
            .iter()
            .map(|id| chain.append(record(id)))
            .collect();
        records[1].decision = "deny".into();
        assert_eq!(verify_chain(&records), Err(ChainBreak::Altered(1)));
    }

    #[test]
    fn tokens_are_scrubbed() {
        assert_eq!(
            super::scrub_tokens("bad aud in eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJib2IifQ.c2ln, again"),
            "bad aud in [token], again"
        );
        assert_eq!(super::scrub_tokens("no token here"), "no token here");
        assert_eq!(super::scrub_tokens("eyJ"), "[token]");
    }

    /// A `seq` of `u64::MAX` followed by `seq: 0` is a gap, not a wrap.
    #[test]
    fn seq_does_not_wrap() {
        let mut first = record("a");
        first.seq = u64::MAX;
        first.hash = first.digest().unwrap();
        let mut second = record("b");
        second.seq = 0;
        second.prev.clone_from(&first.hash);
        second.hash = second.digest().unwrap();
        assert_eq!(verify_chain(&[first, second]), Err(ChainBreak::Gap(1)));
    }

    #[test]
    fn a_removed_record_breaks_the_chain() {
        let chain = AuditChain::default();
        let mut records: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|id| chain.append(record(id)))
            .collect();
        records.remove(1);
        assert_eq!(verify_chain(&records), Err(ChainBreak::Gap(1)));
    }

    #[test]
    fn the_digest_covers_every_member_but_hash() {
        let base = record("a");
        let digest = base.digest().unwrap();
        let mut with_hash = base.clone();
        with_hash.hash = "anything".into();
        assert_eq!(with_hash.digest().unwrap(), digest);
        let mut other = base.clone();
        other.remediation = "refused".into();
        assert_ne!(other.digest().unwrap(), digest);
        let mut other = base;
        other.sender_constrained = false;
        assert_ne!(other.digest().unwrap(), digest);
    }

    #[test]
    fn the_digest_is_stable() {
        // Pinned, so a change to member order or encoding is noticed: it
        // would break every chain already written.
        assert_eq!(
            record("a").digest().unwrap(),
            super::hex(&<sha2::Sha256 as sha2::Digest>::digest(
                br#"{"audit_version":1,"seq":0,"prev":"","id":"a","txn":"t","time":1,"agent":"spiffe://td.example/agent-a","auth_method":"wit-wpt","sender_constrained":true,"principal":"bob","chain_profile":"","chain_issuer":"","chain_hops":0,"chain_actors":"[]","depth_semantics":"","resource":"http://tools.td.example/tickets","tool":"","action":"GET","decision":"allow","status":200,"reason":"ok","detail":"","pdp":"allow","remediation":"none"}"#
            ))
        );
    }
}
