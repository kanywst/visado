//! The offline verification algorithm (§6).

use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use visado_chain::dpop::{Nonces, Rejection};
use visado_chain::jose::{self, Compact};
use visado_chain::json::{self, ParseError, Value};
use visado_chain::replay::ReplayCache;
use visado_chain::{
    ActorId, Assurance, Authority as NormalizedAuthority, ChainDecoder, Cnf, Hop, KeyThumbprint,
    Link, NormalizedChain, Principal, Profile, SignerBinding, TrustRef, Validity,
};
use wimsey_jose::{Algorithm, SIGNATURE_LEN, VerifyingKey};

use crate::authority::{Authority, DETAIL_TYPE, RunningTotals};
use crate::dpop::{self, HttpRequest, ProofChecks};
use crate::error::{AsorError, Outcome};
use crate::status::{self, DEFAULT_STATUS_MAX_AGE, StatusLists, StatusRef};

/// The JOSE `typ` values of a Delegation Token (RFC 9068 §2.1).
pub const TYPS: [&str; 2] = ["at+jwt", "application/at+jwt"];

/// The largest integer magnitude a token may carry (§3): 2^53-1.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A signature algorithm a verifier may accept (step 1). Each is
/// fully specified (RFC 9864); `EdDSA` is not one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Alg {
    /// `Ed25519`, which the draft requires implementations to support.
    Ed25519,
    /// `ES256`.
    Es256,
    /// `HS256`, for the published test vectors only: a shared secret lets
    /// every verifier forge tokens.
    Hs256,
}

impl Alg {
    /// The JOSE `alg` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Es256 => "ES256",
            Self::Hs256 => "HS256",
        }
    }

    /// The algorithm named `alg`, if this crate implements it.
    #[must_use]
    pub fn from_name(alg: &str) -> Option<Self> {
        match alg {
            "Ed25519" => Some(Self::Ed25519),
            "ES256" => Some(Self::Es256),
            "HS256" => Some(Self::Hs256),
            _ => None,
        }
    }
}

#[derive(Clone)]
enum AnchorKey {
    Public(VerifyingKey),
    Secret(Vec<u8>),
}

/// A key the verifier trusts to sign Delegation Tokens, with the algorithm
/// configured for it (step 1) and the issuer whose tokens it signs.
#[derive(Clone)]
pub struct TrustAnchor {
    issuer: String,
    key: AnchorKey,
    alg: Alg,
    kid: Option<String>,
    thumbprint: String,
}

impl fmt::Debug for TrustAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("issuer", &self.issuer)
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

impl TrustAnchor {
    /// An anchor for tokens whose `iss` is `issuer`, signed by `key` under
    /// `Ed25519` or `ES256`, as the key's type gives.
    #[must_use]
    pub fn new(issuer: impl Into<String>, key: VerifyingKey) -> Self {
        // An unknown future key type gets `Ed25519`, which `verifies`
        // then refuses because the key does not fit it.
        let alg = if key.algorithm() == Algorithm::Es256 {
            Alg::Es256
        } else {
            Alg::Ed25519
        };
        let thumbprint = jose::key_thumbprint(&key);
        Self {
            issuer: issuer.into(),
            key: AnchorKey::Public(key),
            alg,
            kid: None,
            thumbprint,
        }
    }

    /// An `HS256` anchor with a shared secret. Only for running the
    /// published test vectors, which are signed this way: anyone who can
    /// verify such a token can also mint one.
    #[must_use]
    pub fn hs256(issuer: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        let secret = secret.into();
        let thumbprint = format!("hs256:{}", jose::hash(&hex(&Sha256::digest(&secret))));
        Self {
            issuer: issuer.into(),
            key: AnchorKey::Secret(secret),
            alg: Alg::Hs256,
            kid: None,
            thumbprint,
        }
    }

    /// Sets the `kid` a token may use to select this anchor.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) const fn alg(&self) -> Alg {
        self.alg
    }

    pub(crate) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    pub(crate) fn verifies(&self, jws: Compact<'_>) -> bool {
        match &self.key {
            AnchorKey::Public(key) => match jose::b64(jws.signature) {
                Some(sig) if sig.len() == SIGNATURE_LEN && fits(self.alg, key) => {
                    key.verify(jws.signing_input.as_bytes(), &sig).is_ok()
                }
                _ => false,
            },
            AnchorKey::Secret(secret) => {
                let (Ok(mut mac), Some(sig)) = (
                    Hmac::<Sha256>::new_from_slice(secret),
                    jose::b64(jws.signature),
                ) else {
                    return false;
                };
                mac.update(jws.signing_input.as_bytes());
                mac.verify_slice(&sig).is_ok()
            }
        }
    }
}

fn fits(alg: Alg, key: &VerifyingKey) -> bool {
    match alg {
        Alg::Ed25519 => matches!(key.algorithm(), Algorithm::Ed25519 | Algorithm::EdDsa),
        Alg::Es256 => key.algorithm() == Algorithm::Es256,
        Alg::Hs256 => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Size bounds, checked before anything is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most tokens a chain may have.
    pub max_tokens: usize,
    /// The largest token, in bytes.
    pub max_token_size: usize,
    /// The largest chain, in bytes.
    pub max_chain_size: usize,
    /// The largest DPoP proof, in bytes.
    pub max_proof_size: usize,
    /// The largest action parameters, in bytes.
    pub max_params_size: usize,
    /// The DPoP `iat` window, in seconds either side of now.
    pub proof_window: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tokens: 32,
            max_token_size: 64 * 1024,
            max_chain_size: 256 * 1024,
            max_proof_size: 8 * 1024,
            max_params_size: 64 * 1024,
            proof_window: 60,
        }
    }
}

/// What a holder sends with one request.
#[derive(Clone, Copy)]
pub struct Presentation<'a> {
    /// The chain, root first, each token in compact serialization.
    pub chain: &'a [String],
    /// The DPoP proof for this request.
    pub dpop: &'a str,
}

// Tokens are bearer-equivalent: Debug shows only how many there are.
impl std::fmt::Debug for Presentation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presentation")
            .field("chain_tokens", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// The action being authorized (step 8).
#[derive(Clone, Copy)]
pub struct Action<'a> {
    /// The operation, as a scope value.
    pub scope: &'a str,
    /// The action's parameters as JSON object text. A per-action constraint
    /// reads the member named by its key; an absent member fails the constraint.
    pub params_json: &'a str,
    /// Where cumulative constraints read their running totals. `None`
    /// denies any leaf with a cumulative constraint.
    pub totals: Option<&'a dyn RunningTotals>,
}

impl fmt::Debug for Action<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Action")
            .field("scope", &self.scope)
            .field("params_json", &self.params_json)
            .field("totals", &self.totals.is_some())
            .finish()
    }
}

/// A permitted action.
#[derive(Debug, Clone)]
pub struct Authorized {
    /// The verified chain, with `holder_proof` set.
    pub chain: NormalizedChain,
    /// The DPoP proof `jti`.
    pub proof_jti: String,
}

/// Verifies asor Delegation Chains for one enforcement point.
#[derive(Debug, Clone)]
pub struct Verifier {
    anchors: Vec<TrustAnchor>,
    algorithms: Vec<Alg>,
    audiences: Vec<String>,
    limits: Limits,
    status: Option<StatusSource>,
    status_max_age: i64,
    dpop_nonces: Option<Nonces>,
}

/// The status list source, which has no `Debug` of its own.
#[derive(Clone)]
struct StatusSource(Arc<dyn StatusLists>);

impl fmt::Debug for StatusSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StatusLists")
    }
}

/// One token after parsing, before any numbered step.
struct Token<'a> {
    jws: Compact<'a>,
    compact: &'a str,
    alg: String,
    kid: Option<String>,
    iss: String,
    jti: String,
    sub: String,
    client_id: String,
    audience: Vec<String>,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    jkt: String,
    depth: u32,
    max_depth: Option<u32>,
    par_hash: Option<String>,
    status: Option<StatusRef>,
    authority: Authority,
}

/// A chain that passed the parse rules and steps 1 to 5.
struct Verified<'a> {
    anchor: &'a TrustAnchor,
    tokens: Vec<Token<'a>>,
}

impl Verifier {
    /// A verifier trusting `anchors`, accepting `Ed25519` and `ES256`, for
    /// an enforcement point identified by `audiences` (exact string match).
    #[must_use]
    pub fn new(anchors: Vec<TrustAnchor>, audiences: Vec<String>) -> Self {
        Self {
            anchors,
            algorithms: vec![Alg::Ed25519, Alg::Es256],
            audiences,
            limits: Limits::default(),
            status: None,
            status_max_age: DEFAULT_STATUS_MAX_AGE,
            dpop_nonces: None,
        }
    }

    /// Requires the leaf's DPoP proof (step 6) to carry a nonce `nonces`
    /// accepts (RFC 9449 §4.3 item 10 and §9), or stops requiring one with
    /// `None`. A proof refused only for its nonce is `holder_binding_failed`
    /// with [`AsorError::dpop_nonce`](crate::AsorError::dpop_nonce) set.
    #[must_use]
    pub fn with_dpop_nonces(mut self, nonces: Option<Nonces>) -> Self {
        self.dpop_nonces = nonces;
        self
    }

    /// Checks `status` claims (step 7) against the lists `lists` holds.
    /// Without a source, a token with a `status` claim is denied as
    /// `status_unknown` by [`Verifier::verify`].
    #[must_use]
    pub fn with_status_lists(mut self, lists: Arc<dyn StatusLists>) -> Self {
        self.status = Some(StatusSource(lists));
        self
    }

    /// How long, in seconds, a fetched status list is trusted when its own
    /// `ttl` is longer or absent. The default is
    /// [`DEFAULT_STATUS_MAX_AGE`](crate::DEFAULT_STATUS_MAX_AGE).
    #[must_use]
    pub const fn with_status_max_age(mut self, seconds: i64) -> Self {
        self.status_max_age = seconds;
        self
    }

    /// Replaces the list of accepted algorithms (step 1).
    #[must_use]
    pub fn with_algorithms(mut self, algorithms: Vec<Alg>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Replaces the limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Runs the whole algorithm for one request at `now`: the parse rules,
    /// steps 1 to 5, the DPoP proof (6), status (7), and the audience and
    /// action (8). Pass `replay` to reject a DPoP `jti` seen before.
    ///
    /// Step 7 looks every `status` reference up in the configured
    /// [`StatusLists`]; without one, a chain with a `status` claim is
    /// denied as `status_unknown`.
    ///
    /// # Errors
    ///
    /// The first check that failed.
    pub fn verify(
        &self,
        presentation: &Presentation<'_>,
        request: &HttpRequest<'_>,
        action: &Action<'_>,
        now: i64,
        replay: Option<&dyn ReplayCache>,
    ) -> Result<Authorized, AsorError> {
        let chain = self.chain(presentation.chain, now)?;
        let leaf = chain
            .tokens
            .last()
            .ok_or(AsorError::new(Outcome::Malformed, "empty chain"))?;
        let window = ProofChecks {
            max_size: self.limits.max_proof_size,
            iat_window: self.limits.proof_window,
            nonces: self.dpop_nonces.as_ref(),
        };
        let proof = dpop::verify(
            presentation.dpop,
            &leaf.jkt,
            leaf.compact,
            request,
            &window,
            now,
            replay,
        )
        .map_err(|rejection| {
            let error = AsorError::new(Outcome::HolderBindingFailed, rejection.reason());
            match rejection {
                Rejection::Nonce(nonce) => error.with_dpop_nonce(nonce),
                Rejection::Proof(_) | Rejection::KeyMismatch => error,
            }
        })?;
        self.status(&chain.tokens, now)?;
        self.audience(leaf, chain.tokens.len() - 1)?;
        if action.params_json.len() > self.limits.max_params_size {
            return Err(AsorError::new(
                Outcome::CeilingExceeded,
                "action parameters too large",
            ));
        }
        let params = json::parse(action.params_json.as_bytes())
            .ok()
            .filter(|p| p.as_object().is_some())
            .ok_or(AsorError::new(
                Outcome::CeilingExceeded,
                "action parameters are not a JSON object",
            ))?;
        leaf.authority
            .permits(&leaf.jti, action.scope, &params, action.totals)
            .map_err(|(outcome, reason)| AsorError::new(outcome, reason))?;
        Ok(Authorized {
            chain: normalize(&chain, true),
            proof_jti: proof.jti,
        })
    }

    /// What a verifier with an audience but no request can check: the parse
    /// rules, steps 1 to 5, step 7, and the audience half of step 8 (§6.1).
    /// Without status lists, a chain with a `status` claim fails as
    /// `status_unknown`, as in [`Verifier::verify`]. The published vectors
    /// test this. The result has `holder_proof: false`.
    ///
    /// # Errors
    ///
    /// The first check that failed.
    pub fn check(&self, tokens: &[String], now: i64) -> Result<NormalizedChain, AsorError> {
        let chain = self.chain(tokens, now)?;
        self.status(&chain.tokens, now)?;
        let n = chain.tokens.len() - 1;
        let leaf = chain
            .tokens
            .last()
            .ok_or(AsorError::new(Outcome::Malformed, "empty chain"))?;
        self.audience(leaf, n)?;
        Ok(normalize(&chain, false))
    }

    /// Step 7: every token with a `status` reference is `VALID` in a list
    /// that is neither expired nor stale.
    fn status(&self, tokens: &[Token<'_>], now: i64) -> Result<(), AsorError> {
        let lists = self.status.as_ref().map(|s| &*s.0);
        for (i, token) in tokens.iter().enumerate() {
            if let Some(reference) = &token.status {
                status::check(reference, lists, self.status_max_age, now)
                    .map_err(|(outcome, reason)| AsorError::at(outcome, i, reason))?;
            }
        }
        Ok(())
    }

    fn audience(&self, leaf: &Token<'_>, i: usize) -> Result<(), AsorError> {
        if leaf.audience.iter().any(|a| self.audiences.contains(a)) {
            Ok(())
        } else {
            Err(AsorError::at(
                Outcome::AudienceMismatch,
                i,
                "leaf aud does not name this enforcement point",
            ))
        }
    }

    /// The parse rules and steps 1 to 5.
    fn chain<'a>(&'a self, chain: &'a [String], now: i64) -> Result<Verified<'a>, AsorError> {
        let malformed = |reason| AsorError::new(Outcome::Malformed, reason);
        if chain.is_empty() {
            return Err(malformed("empty chain"));
        }
        if chain.len() > self.limits.max_tokens {
            return Err(malformed("too many tokens"));
        }
        let mut total = 0usize;
        for (i, token) in chain.iter().enumerate() {
            if token.len() > self.limits.max_token_size {
                return Err(AsorError::at(Outcome::Malformed, i, "token too large"));
            }
            total = total.saturating_add(token.len());
        }
        if total > self.limits.max_chain_size {
            return Err(malformed("chain too large"));
        }

        // Every token is decoded and checked for JCS before any claim rule,
        // and every claim rule runs before step 1.
        let decoded = chain
            .iter()
            .enumerate()
            .map(|(i, token)| decode(token).map_err(|(o, r)| AsorError::at(o, i, r)))
            .collect::<Result<Vec<_>, _>>()?;
        let tokens = decoded
            .into_iter()
            .enumerate()
            .map(|(i, d)| claims(i, &d).map_err(|r| AsorError::at(Outcome::Malformed, i, r)))
            .collect::<Result<Vec<_>, _>>()?;

        let anchor = self.signatures(&tokens)?;
        par_hashes(&tokens)?;
        depth_and_principal(&tokens)?;
        attenuation(&tokens)?;
        time(&tokens, now)?;
        Ok(Verified { anchor, tokens })
    }

    /// Step 1. Returns the anchor of `DT_0`.
    fn signatures<'a>(&'a self, tokens: &[Token<'_>]) -> Result<&'a TrustAnchor, AsorError> {
        let mut root: Option<&TrustAnchor> = None;
        for (i, token) in tokens.iter().enumerate() {
            let err = |reason| AsorError::at(Outcome::SignatureInvalid, i, reason);
            let alg = Alg::from_name(&token.alg)
                .filter(|a| self.algorithms.contains(a))
                .ok_or(err("alg is not on the accepted list"))?;
            let by_kid = token
                .kid
                .as_deref()
                .filter(|kid| self.anchors.iter().any(|a| a.kid.as_deref() == Some(*kid)));
            // Every token must verify under the root's anchor: the draft has
            // one signer per chain, and the normalized chain records that
            // anchor as the signer of every hop.
            let anchor = match root {
                Some(root) => Some(root)
                    .filter(|a| a.alg == alg && a.issuer == token.iss && a.verifies(token.jws))
                    .ok_or(err("signature does not verify under the root's anchor"))?,
                None => self
                    .anchors
                    .iter()
                    .filter(|a| by_kid.is_none() || a.kid.as_deref() == by_kid)
                    .filter(|a| a.alg == alg && a.issuer == token.iss)
                    .find(|a| a.verifies(token.jws))
                    .ok_or(err("signature does not verify under a trusted key"))?,
            };
            if i == 0 {
                root = Some(anchor);
            }
        }
        root.ok_or(AsorError::new(Outcome::Malformed, "empty chain"))
    }
}

impl ChainDecoder for Verifier {
    type Input = [String];
    type Error = AsorError;

    /// The parse rules and steps 1 to 5: no proof, status, audience or
    /// action, so `holder_proof` is `false` and the chain must not
    /// authorize anything on its own (§6.1).
    fn decode(&self, input: &[String], now: i64) -> Result<NormalizedChain, AsorError> {
        self.chain(input, now).map(|chain| normalize(&chain, false))
    }
}

/// A token's parts and parsed JSON, before the claim rules.
struct Decoded<'a> {
    compact: &'a str,
    jws: Compact<'a>,
    header: Value,
    claims: Value,
}

/// Splits and decodes one token and checks that both JSON parts are exactly
/// their JCS serialization (§3).
fn decode(token: &str) -> Result<Decoded<'_>, (Outcome, &'static str)> {
    let malformed = |reason| (Outcome::Malformed, reason);
    let jws = jose::split(token).ok_or(malformed("not three dot-separated parts"))?;
    let header_bytes = jose::b64(jws.header).ok_or(malformed("header is not base64url"))?;
    let payload_bytes = jose::b64(jws.payload).ok_or(malformed("payload is not base64url"))?;
    if jose::b64(jws.signature).is_none() {
        return Err(malformed("signature is not base64url"));
    }
    let header = canonical(&header_bytes)?;
    let claims = canonical(&payload_bytes)?;
    Ok(Decoded {
        compact: token,
        jws,
        header,
        claims,
    })
}

fn canonical(bytes: &[u8]) -> Result<Value, (Outcome, &'static str)> {
    let value = json::parse(bytes).map_err(|e| match e {
        ParseError::DuplicateMember => (Outcome::DuplicateMember, "a member name repeats"),
        ParseError::Syntax | ParseError::TooDeep => (Outcome::Malformed, "not JSON"),
    })?;
    if value.as_object().is_none() {
        return Err((Outcome::Malformed, "not a JSON object"));
    }
    numbers(&value)?;
    if value.jcs().as_bytes() != bytes {
        return Err((Outcome::NonCanonical, "not the JCS serialization"));
    }
    Ok(value)
}

/// Every number is finite and, as a double, no larger in magnitude than
/// 2^53-1 (§3).
fn numbers(value: &Value) -> Result<(), (Outcome, &'static str)> {
    match value {
        Value::Number(n) => {
            let f = n.to_f64();
            if !f.is_finite() {
                Err((Outcome::NonFinite, "a number is not finite"))
            } else if f.abs() > MAX_SAFE_INTEGER {
                Err((Outcome::Malformed, "a number exceeds 2^53-1"))
            } else {
                Ok(())
            }
        }
        Value::Array(items) => items.iter().try_for_each(numbers),
        Value::Object(members) => members.iter().try_for_each(|(_, v)| numbers(v)),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// The protected header: `typ`, no `crit`, `alg` and an optional `kid`.
fn header(header: &Value) -> Result<(String, Option<String>), &'static str> {
    let typ = header.get("typ").and_then(Value::as_str);
    if !typ.is_some_and(|t| TYPS.contains(&t)) {
        return Err("typ is not at+jwt");
    }
    if header.get("crit").is_some() {
        return Err("crit is not understood");
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("alg missing")?
        .to_owned();
    let kid = match header.get("kid") {
        None => None,
        Some(kid) => Some(kid.as_str().ok_or("kid is not a string")?.to_owned()),
    };
    Ok((alg, kid))
}

/// The claim rules of §3 and §4 for token `index`. Every failure is
/// `malformed`.
fn claims<'a>(index: usize, decoded: &Decoded<'a>) -> Result<Token<'a>, &'static str> {
    let (alg, kid) = header(&decoded.header)?;
    let claims = &decoded.claims;
    let text = |name| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    };
    let int = |name| claims.get(name).map(Value::as_integer);
    let iss = text("iss").ok_or("iss is not a non-empty string")?;
    let jti = text("jti").ok_or("jti is not a non-empty string")?;
    let sub = text("sub").ok_or("sub is not a non-empty string")?;
    let client_id = claims
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or("client_id is not a string")?
        .to_owned();
    let audience = match claims.get("aud") {
        Some(Value::String(aud)) => vec![aud.clone()],
        Some(Value::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|aud| aud.as_str().map(ToOwned::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or("aud is not an array of strings")?,
        _ => return Err("aud is not a string or a non-empty array of strings"),
    };
    let iat = int("iat").flatten().ok_or("iat is not an integer")?;
    let exp = int("exp").flatten().ok_or("exp is not an integer")?;
    let nbf = match int("nbf") {
        None => None,
        Some(nbf) => Some(nbf.ok_or("nbf is not an integer")?),
    };
    let jkt = claims
        .get("cnf")
        .filter(|cnf| cnf.as_object().is_some())
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or("cnf carries no jkt")?
        .to_owned();
    let depth = claims
        .get("del_depth")
        .and_then(Value::as_count)
        .ok_or("del_depth is not a non-negative integer")?;
    let max_depth = match claims.get("del_max_depth") {
        None if index == 0 => return Err("`DT_0` has no del_max_depth"),
        None => None,
        Some(max) => Some(
            max.as_count()
                .filter(|m| *m > 0)
                .ok_or("del_max_depth is not a positive integer")?,
        ),
    };
    let par_hash = match (index, claims.get("par_hash")) {
        (0, None) => None,
        (0, Some(_)) => return Err("`DT_0` carries par_hash"),
        (_, None) => return Err("par_hash missing"),
        (_, Some(hash)) => {
            let hash = hash.as_str().ok_or("par_hash is not a string")?;
            jose::b64(hash).ok_or("par_hash is not base64url")?;
            Some(hash.to_owned())
        }
    };
    let status = status::reference(claims.get("status"))?;
    let authority = Authority::parse(claims.get("authorization_details"))
        .ok_or("authorization_details is not one closed agent_delegation detail")?;
    Ok(Token {
        jws: decoded.jws,
        compact: decoded.compact,
        alg,
        kid,
        iss,
        jti,
        sub,
        client_id,
        audience,
        iat,
        exp,
        nbf,
        jkt,
        depth,
        max_depth,
        par_hash,
        status,
        authority,
    })
}

/// Step 2: each child's `par_hash` is the SHA-256 of its parent's JWS
/// Signing Input, compared in constant time.
fn par_hashes(tokens: &[Token<'_>]) -> Result<(), AsorError> {
    for (i, pair) in tokens.windows(2).enumerate() {
        let [parent, child] = pair else { continue };
        let expected = Sha256::digest(parent.jws.signing_input.as_bytes());
        let got = child
            .par_hash
            .as_deref()
            .and_then(jose::b64)
            .unwrap_or_default();
        if !constant_time_eq(&expected, &got) {
            return Err(AsorError::at(
                Outcome::ParHashMismatch,
                i + 1,
                "par_hash does not match the parent",
            ));
        }
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Step 3: depth, then principal. Only `DT_0`'s `del_max_depth` bounds the
/// chain: `n < DT_0.del_max_depth`.
fn depth_and_principal(tokens: &[Token<'_>]) -> Result<(), AsorError> {
    let err = |outcome, i, reason| AsorError::at(outcome, i, reason);
    let root = tokens
        .first()
        .ok_or(AsorError::new(Outcome::Malformed, "empty chain"))?;
    for (i, token) in tokens.iter().enumerate() {
        if usize::try_from(token.depth).ok() != Some(i) {
            return Err(err(Outcome::DepthInvalid, i, "del_depth out of sequence"));
        }
    }
    let n = tokens.len() - 1;
    let max = root.max_depth.unwrap_or(0);
    if usize::try_from(max).map_or(true, |max| n >= max) {
        return Err(err(
            Outcome::DepthInvalid,
            n,
            "chain reaches `DT_0`.del_max_depth",
        ));
    }
    for (i, token) in tokens.iter().enumerate() {
        if token.sub != root.sub {
            return Err(err(Outcome::PrincipalAltered, i, "sub differs from `DT_0`"));
        }
    }
    Ok(())
}

/// Step 4: rules 1, 2, 3 and 5 of §4.3 for each child against its parent.
/// For rule 5 a child without `del_max_depth` keeps its parent's bound.
fn attenuation(tokens: &[Token<'_>]) -> Result<(), AsorError> {
    let mut bound = tokens.first().and_then(|t| t.max_depth);
    for (i, pair) in tokens.windows(2).enumerate() {
        let [parent, child] = pair else { continue };
        let err = |reason| AsorError::at(Outcome::NotNarrower, i + 1, reason);
        if !child.authority.subsumed_by(&parent.authority) {
            return Err(err("authority not subsumed by the parent's"));
        }
        if let Some(own) = child.max_depth {
            if bound.is_some_and(|b| own > b) {
                return Err(err("del_max_depth exceeds the parent's"));
            }
            bound = Some(own);
        }
    }
    Ok(())
}

/// Step 5: nbf <= now < exp for every token, and `exp` non-increasing.
fn time(tokens: &[Token<'_>], now: i64) -> Result<(), AsorError> {
    let mut previous: Option<i64> = None;
    for (i, token) in tokens.iter().enumerate() {
        let err = |reason| AsorError::at(Outcome::Expired, i, reason);
        if token.nbf.is_some_and(|nbf| now < nbf) {
            return Err(err("not yet valid"));
        }
        if now >= token.exp {
            return Err(err("expired"));
        }
        if previous.is_some_and(|p| token.exp > p) {
            return Err(err("exp exceeds the parent's"));
        }
        previous = Some(token.exp);
    }
    Ok(())
}

fn normalize(chain: &Verified<'_>, holder_proof: bool) -> NormalizedChain {
    let root_max = chain
        .tokens
        .first()
        .and_then(|t| t.max_depth)
        .map(|m| m.saturating_sub(1));
    let signer = KeyThumbprint(chain.anchor.thumbprint.clone());
    let mut hops: Vec<Hop> = Vec::with_capacity(chain.tokens.len());
    for token in &chain.tokens {
        let actor = ActorId::Name(token.client_id.clone());
        let delegator = hops.last().map(|parent| parent.actor.clone());
        let link = token.par_hash.clone().map_or(Link::Root, Link::ParHash);
        hops.push(Hop {
            id: token.jti.clone(),
            depth: token.depth,
            max_depth: root_max,
            actor,
            delegator,
            signer: signer.clone(),
            signer_binding: SignerBinding::RootAnchor,
            link,
            authority: NormalizedAuthority {
                detail_type: DETAIL_TYPE.to_owned(),
                json: token.authority.jcs.clone(),
            },
            validity: Validity {
                issued_at: token.iat,
                expires_at: token.exp,
            },
            audience: Some(token.audience.clone()),
            cnf: Some(Cnf {
                thumbprint: KeyThumbprint(token.jkt.clone()),
            }),
            assurance: Assurance::Verified,
        });
    }
    let principal =
        chain
            .tokens
            .first()
            .map_or(Principal::Unspecified, |root| Principal::Subject {
                issuer: root.iss.clone(),
                subject: root.sub.clone(),
            });
    NormalizedChain {
        profile: Profile::Asor03,
        principal,
        root: TrustRef {
            issuer: chain.anchor.issuer.clone(),
            key: signer,
        },
        hops,
        holder_proof,
    }
}
