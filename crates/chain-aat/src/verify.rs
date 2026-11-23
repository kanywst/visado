//! The §8 chain verification algorithm.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use visado_chain::{
    ActorId, Assurance, Authority, ChainDecoder, Cnf, Hop, KeyThumbprint, Link, NormalizedChain,
    Principal, Profile, SignerBinding, TrustRef, Validity,
};
use wimsey_jose::VerifyingKey;

use visado_chain::jose::{self as jose, Compact, HolderKey, THUMBPRINT_URI_PREFIX};
use visado_chain::json::{self, Value};
use visado_chain::replay::{DEFAULT_PROOF_SKEW, Recorded, ReplayCache};

use crate::constraint::ToolMap;
use crate::error::{AatError, Step};
use crate::jws;

/// The JOSE `typ` of an AAT (§3.5).
pub const TYP: &str = "aat+jwt";
/// The JOSE `typ` of a PoP JWT (§3.5).
pub const POP_TYP: &str = "aat-pop+jwt";
/// The `authorization_details` type of the AAT entry (§3.3).
pub const DETAIL_TYPE: &str = "attenuating_agent_token";

/// A root issuer the enforcement point trusts.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    issuer: String,
    key: VerifyingKey,
    kid: Option<String>,
    thumbprint: String,
}

impl TrustAnchor {
    /// An anchor for root tokens whose `iss` is `issuer`, signed by `key`.
    #[must_use]
    pub fn new(issuer: impl Into<String>, key: VerifyingKey) -> Self {
        let thumbprint = jose::key_thumbprint(&key);
        Self {
            issuer: issuer.into(),
            key,
            kid: None,
            thumbprint,
        }
    }

    /// Sets the `kid` a root token may use to select this anchor.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

/// The implementation-defined limits of §4.3, §4.4, §3.4 and §9.9.
///
/// The defaults are the draft's recommended values, and 1024 for
/// [`max_constraint_nodes`](Self::max_constraint_nodes), which the draft
/// does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `MAX_IAT_SKEW`, in seconds.
    pub max_iat_skew: i64,
    /// `MAX_TOKEN_LIFETIME`, in seconds.
    pub max_token_lifetime: i64,
    /// `MAX_DELEGATION_DEPTH`. The draft requires at least 8.
    pub max_delegation_depth: u32,
    /// `MAX_CONSTRAINT_DEPTH`.
    pub max_constraint_depth: usize,
    /// The most constraint nodes one token may carry, across all its tools.
    /// Not in the draft; bounds the work of steps 4p and 6b.
    pub max_constraint_nodes: usize,
    /// `MAX_TOKEN_SIZE`, in bytes. Also bounds the PoP JWT and the arguments.
    pub max_token_size: usize,
    /// `MAX_CHAIN_SIZE`, in bytes.
    pub max_chain_size: usize,
    /// The PoP `iat` window, in seconds either side of now.
    pub pop_window: i64,
    /// How far ahead of now a PoP `iat` may be, in seconds; the smaller of
    /// this and `pop_window` applies. A PoP `jti` is remembered until `iat`
    /// plus `pop_window`.
    pub pop_max_future: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_iat_skew: 30,
            max_token_lifetime: 90 * 24 * 60 * 60,
            max_delegation_depth: 8,
            max_constraint_depth: 32,
            max_constraint_nodes: 1024,
            max_token_size: 64 * 1024,
            max_chain_size: 256 * 1024,
            pop_window: 30,
            pop_max_future: DEFAULT_PROOF_SKEW,
        }
    }
}

/// Optional enforcement-point requirements (§9.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Deny unless some token in the chain carries `aud` (§8 step 6c).
    pub require_chain_aud: bool,
    /// Deny a PoP JWT without `aat_aud` (§8 step 7d).
    pub require_pop_aud: bool,
    /// When set, a PoP JWT must carry one of these nonces (§8 step 7h).
    pub nonces: Option<BTreeSet<String>>,
}

/// What a holder sends for one tool invocation (§7.4).
#[derive(Clone, Copy)]
pub struct Presentation<'a> {
    /// The chain, root first, each token in compact serialization.
    pub chain: &'a [String],
    /// The PoP JWT.
    pub pop: &'a str,
}

// Tokens are bearer-equivalent: Debug shows only how many there are.
impl std::fmt::Debug for Presentation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presentation")
            .field("chain_tokens", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// The tool invocation being authorized.
#[derive(Debug, Clone, Copy)]
pub struct Invocation<'a> {
    /// The tool identifier.
    pub tool: &'a str,
    /// The arguments as the JSON object text that was received. Kept as text
    /// so numbers are checked as written (§3.4).
    pub args_json: &'a str,
}

/// A permitted invocation.
#[derive(Debug, Clone)]
pub struct Authorized {
    /// The verified chain.
    pub chain: NormalizedChain,
    /// The PoP JWT `jti`.
    pub pop_jti: String,
    /// The last second the PoP is accepted in: its `iat` plus the PoP
    /// window. A caller that records `pop_jti` itself, after checks of its
    /// own, keeps it until then.
    pub pop_until: i64,
}

/// Verifies AAT chains and invocations for one enforcement point.
#[derive(Debug, Clone)]
pub struct Verifier {
    anchors: Vec<TrustAnchor>,
    audiences: Vec<String>,
    limits: Limits,
    policy: Policy,
}

/// One token after its §8 step 3 or 4 checks.
struct Token<'a> {
    jws: Compact<'a>,
    jti: String,
    iat: i64,
    exp: i64,
    depth: u32,
    max_depth: u32,
    holder: HolderKey,
    tools: BTreeMap<String, ToolMap>,
    tools_jcs: String,
    /// `aud` as a list, once checked to be a string or array of strings.
    audience: Option<Vec<String>>,
    claims: Value,
}

/// A chain that passed §8 steps 1 to 5.
struct Verified<'a> {
    anchor: &'a TrustAnchor,
    tokens: Vec<Token<'a>>,
}

impl Verifier {
    /// A verifier trusting `anchors`, for an enforcement point identified by
    /// `audiences` (compared by exact string match), with the default limits
    /// and no optional requirements.
    #[must_use]
    pub fn new(anchors: Vec<TrustAnchor>, audiences: Vec<String>) -> Self {
        Self {
            anchors,
            audiences,
            limits: Limits::default(),
            policy: Policy::default(),
        }
    }

    /// Replaces the limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Replaces the policy.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// The authority algebra for this verifier's limits.
    #[must_use]
    pub const fn algebra(&self) -> crate::Algebra {
        crate::Algebra::new(self.limits)
    }

    /// Runs the whole §8 algorithm for one invocation at time `now`.
    ///
    /// Pass `replay` for tools whose PoP `jti` values are tracked (§7.3); it
    /// is consulted only after every other check passes.
    ///
    /// The PoP JWT's size, header and signature (steps 7a and 7b) are
    /// checked before the invocation (6b) and chain audience (6c), as §8
    /// recommends, so arguments are only matched against constraints for a
    /// holder that signed the request. The rest of step 7 follows 6c.
    ///
    /// # Errors
    ///
    /// The first failing step, in that order.
    pub fn verify(
        &self,
        presentation: &Presentation<'_>,
        invocation: &Invocation<'_>,
        now: i64,
        replay: Option<&dyn ReplayCache>,
    ) -> Result<Authorized, AatError> {
        let chain = self.chain(presentation.chain, now)?;
        let leaf = chain
            .tokens
            .last()
            .ok_or(AatError::new(Step::S1, "empty chain"))?;
        let pop = self.pop_signature(leaf, presentation.pop)?;
        let args = self.invocation(leaf, invocation)?;
        self.chain_audience(&chain.tokens)?;
        let (pop_jti, pop_until) =
            self.pop_claims(leaf, &pop, invocation.tool, &args, now, replay)?;
        Ok(Authorized {
            chain: normalize(&chain, true),
            pop_jti,
            pop_until,
        })
    }

    /// §8 steps 1 to 5.
    fn chain<'a>(&'a self, chain: &'a [String], now: i64) -> Result<Verified<'a>, AatError> {
        if chain.is_empty() {
            return Err(AatError::new(Step::S1, "empty chain"));
        }
        let parts = self.sizes_and_cycles(chain)?;
        let first = *parts
            .first()
            .ok_or(AatError::new(Step::S1, "empty chain"))?;
        let (anchor, root) = self.root(first, now)?;
        let mut tokens = vec![root];
        for (i, jws) in parts.iter().enumerate().skip(1) {
            let parent = tokens
                .last()
                .ok_or(AatError::new(Step::S1, "empty chain"))?;
            let child = self.child(i, parent, *jws, now)?;
            tokens.push(child);
        }
        let leaf_depth = tokens.last().map_or(0, |t| t.depth);
        if usize::try_from(leaf_depth).ok().map(|d| d + 1) != Some(tokens.len()) {
            return Err(AatError::new(
                Step::S5,
                "chain length does not match leaf depth",
            ));
        }
        // The type half of step 6c, run here so a decoded chain never
        // reads a malformed `aud` as unrestricted.
        for (i, token) in tokens.iter_mut().enumerate() {
            if let Some(aud) = token.claims.get("aud") {
                let list = audience_list(aud).ok_or(AatError::at(
                    Step::S6c,
                    i,
                    "aud is not a string or an array of strings",
                ))?;
                token.audience = Some(list);
            }
        }
        Ok(Verified { anchor, tokens })
    }

    /// §8 step 2.
    fn sizes_and_cycles<'a>(&self, chain: &'a [String]) -> Result<Vec<Compact<'a>>, AatError> {
        let mut total = 0usize;
        for (i, token) in chain.iter().enumerate() {
            if token.len() > self.limits.max_token_size {
                return Err(AatError::at(Step::S2a, i, "token exceeds MAX_TOKEN_SIZE"));
            }
            total = total.saturating_add(token.len());
        }
        if total > self.limits.max_chain_size {
            return Err(AatError::new(Step::S2b, "chain exceeds MAX_CHAIN_SIZE"));
        }
        let mut seen = HashSet::new();
        let mut parts = Vec::with_capacity(chain.len());
        for (i, token) in chain.iter().enumerate() {
            let jti = jose::split(token).and_then(|jws| {
                parts.push(jws);
                json::top_level_string(&jose::b64(jws.payload)?, "jti")
            });
            let Some(jti) = jti else {
                return Err(AatError::at(Step::S2c, i, "no string jti"));
            };
            if !seen.insert(jti) {
                return Err(AatError::at(Step::S2c, i, "jti repeats in the chain"));
            }
        }
        Ok(parts)
    }

    /// §8 step 3.
    fn root<'a>(
        &'a self,
        jws: Compact<'a>,
        now: i64,
    ) -> Result<(&'a TrustAnchor, Token<'a>), AatError> {
        let err = |step, reason| AatError::at(step, 0, reason);
        let header = jws::header(jws.header, TYP).ok_or(err(Step::S3a, "bad protected header"))?;
        let by_kid = header
            .kid
            .as_deref()
            .filter(|kid| self.anchors.iter().any(|a| a.kid.as_deref() == Some(*kid)));
        let candidates: Vec<&TrustAnchor> = self
            .anchors
            .iter()
            .filter(|a| by_kid.is_none() || a.kid.as_deref() == by_kid)
            .filter(|a| header.alg.fits(&a.key))
            .collect();
        if candidates.is_empty() {
            return Err(err(Step::S3a, "no trust anchor for this alg"));
        }
        // Anchors may share a key under different issuers, so keep every
        // anchor whose key verifies and pick by `iss` at step 3k.
        let verified: Vec<&TrustAnchor> = candidates
            .into_iter()
            .filter(|a| jose::signature_ok(&a.key, jws))
            .collect();
        if verified.is_empty() {
            return Err(err(
                Step::S3b,
                "signature does not verify under a trust anchor",
            ));
        }
        let claims = parse_claims(jws).ok_or(err(Step::S3b, "claims do not parse"))?;
        let (Some(iat), Some(exp)) = (int(&claims, "iat"), int(&claims, "exp")) else {
            return Err(err(Step::S3b, "iat or exp missing or not a NumericDate"));
        };
        if int(&claims, "del_depth") != Some(0) {
            return Err(err(Step::S3c, "del_depth is not 0"));
        }
        if claims.get("par_hash").is_some() {
            return Err(err(Step::S3d, "root carries par_hash"));
        }
        if exp <= now {
            return Err(err(Step::S3e, "expired"));
        }
        if iat > now.saturating_add(self.limits.max_iat_skew) {
            return Err(err(Step::S3f, "iat beyond MAX_IAT_SKEW"));
        }
        if exp <= iat {
            return Err(err(Step::S3g, "exp not after iat"));
        }
        if exp > iat.saturating_add(self.limits.max_token_lifetime) {
            return Err(err(Step::S3h, "lifetime exceeds MAX_TOKEN_LIFETIME"));
        }
        let max_depth = count(&claims, "del_max_depth")
            .filter(|d| *d <= self.limits.max_delegation_depth)
            .ok_or(err(Step::S3i, "bad del_max_depth"))?;
        let jti = non_empty(&claims, "jti").ok_or(err(Step::S3j, "bad jti"))?;
        let anchor = claims
            .get("iss")
            .and_then(Value::as_str)
            .filter(|iss| is_uri(iss))
            .and_then(|iss| verified.into_iter().find(|a| a.issuer == iss))
            .ok_or(err(Step::S3k, "iss does not match the trust anchor"))?;
        let holder = jose::holder_key(claims.get("cnf")).ok_or(err(Step::S3l, "bad cnf.jwk"))?;
        let ad = claims.get("authorization_details");
        if ad.and_then(Value::as_array).is_none_or(<[Value]>::is_empty) {
            return Err(err(Step::S3m, "authorization_details missing or empty"));
        }
        let tools_value = aat_tools(ad).ok_or(err(Step::S3m, "no single AAT entry"))?;
        let tools = self
            .tool_maps(tools_value)
            .ok_or(err(Step::S3n, "constraint not well-formed"))?;
        let tools_jcs = Value::Object(tools_value.to_vec()).jcs();
        let token = Token {
            jws,
            jti,
            iat,
            exp,
            depth: 0,
            max_depth,
            holder,
            tools,
            tools_jcs,
            audience: None,
            claims,
        };
        Ok((anchor, token))
    }

    /// §8 step 4 for one (parent, child) pair.
    fn child<'a>(
        &self,
        i: usize,
        parent: &Token<'_>,
        jws: Compact<'a>,
        now: i64,
    ) -> Result<Token<'a>, AatError> {
        let err = |step, reason| AatError::at(step, i, reason);
        let header = jws::header(jws.header, TYP).ok_or(err(Step::S4a, "bad protected header"))?;
        if !header.alg.fits(&parent.holder.key) {
            return Err(err(Step::S4a, "alg does not fit the parent cnf key"));
        }
        if !jose::signature_ok(&parent.holder.key, jws) {
            return Err(err(
                Step::S4b,
                "signature does not verify under the parent cnf key",
            ));
        }
        let claims = parse_claims(jws).ok_or(err(Step::S4b, "claims do not parse"))?;
        let jti = non_empty(&claims, "jti").ok_or(err(Step::S4b1, "bad jti"))?;
        let holder = jose::holder_key(claims.get("cnf")).ok_or(err(Step::S4b2, "bad cnf.jwk"))?;
        let ad = claims.get("authorization_details");
        if ad.and_then(Value::as_array).is_none() {
            return Err(err(Step::S4b3, "authorization_details is not an array"));
        }
        let (Some(depth), Some(max_depth)) =
            (count(&claims, "del_depth"), count(&claims, "del_max_depth"))
        else {
            return Err(err(Step::S4b4, "bad del_depth or del_max_depth"));
        };
        let iss = claims.get("iss").and_then(Value::as_str);
        let par_hash = claims.get("par_hash").and_then(Value::as_str);
        let (Some(iss), Some(par_hash), Some(iat), Some(exp)) =
            (iss, par_hash, int(&claims, "iat"), int(&claims, "exp"))
        else {
            return Err(err(
                Step::S4b5,
                "iss, par_hash, iat or exp missing or malformed",
            ));
        };
        if iss.strip_prefix(THUMBPRINT_URI_PREFIX) != Some(parent.holder.thumbprint.as_str()) {
            return Err(err(
                Step::S4c,
                "iss is not the parent holder's thumbprint URI",
            ));
        }
        let checks = [
            (
                Some(depth) == parent.depth.checked_add(1),
                Step::S4d,
                "del_depth is not parent + 1",
            ),
            (depth <= parent.max_depth, Step::S4e, "parent is terminal"),
            (
                depth <= self.limits.max_delegation_depth,
                Step::S4f,
                "beyond MAX_DELEGATION_DEPTH",
            ),
            (
                max_depth <= parent.max_depth,
                Step::S4g,
                "del_max_depth raised",
            ),
            (exp <= parent.exp, Step::S4h, "outlives the parent"),
            (exp > now, Step::S4i, "expired"),
            (iat >= parent.iat, Step::S4j, "iat before the parent's"),
            (
                iat <= now.saturating_add(self.limits.max_iat_skew),
                Step::S4k,
                "iat beyond MAX_IAT_SKEW",
            ),
            (exp > iat, Step::S4l, "exp not after iat"),
            (
                depth <= max_depth,
                Step::S4m,
                "del_depth above del_max_depth",
            ),
        ];
        if let Some((_, step, reason)) = checks.into_iter().find(|(ok, _, _)| !ok) {
            return Err(err(step, reason));
        }
        let tools_value = aat_tools(ad).ok_or(err(Step::S4n, "no single AAT entry"))?;
        let tools = self
            .tool_maps(tools_value)
            .ok_or(err(Step::S4o, "constraint not well-formed"))?;
        attenuation(&tools, &parent.tools)
            .map_err(|step| err(step, "capabilities do not attenuate the parent's"))?;
        if par_hash != jose::hash(parent.jws.signing_input) {
            return Err(err(Step::S4q, "par_hash does not match the parent"));
        }
        let tools_jcs = Value::Object(tools_value.to_vec()).jcs();
        Ok(Token {
            jws,
            jti,
            iat,
            exp,
            depth,
            max_depth,
            holder,
            tools,
            tools_jcs,
            audience: None,
            claims,
        })
    }

    fn tool_maps(&self, tools: &[(String, Value)]) -> Option<BTreeMap<String, ToolMap>> {
        tool_maps(tools, &self.limits)
    }

    /// §8 step 6b. Returns the parsed arguments for step 7f.
    fn invocation(&self, leaf: &Token<'_>, invocation: &Invocation<'_>) -> Result<Value, AatError> {
        invocation_args(&leaf.tools, invocation, &self.limits)
            .map_err(|reason| AatError::new(Step::S6b, reason))
    }

    /// §8 step 6c.
    fn chain_audience(&self, tokens: &[Token<'_>]) -> Result<(), AatError> {
        let mut any = false;
        for (i, token) in tokens.iter().enumerate() {
            let Some(values) = &token.audience else {
                continue;
            };
            any = true;
            let ok = values.iter().any(|v| self.audiences.iter().any(|a| a == v));
            if !ok {
                return Err(AatError::at(
                    Step::S6c,
                    i,
                    "aud does not identify this enforcement point",
                ));
            }
        }
        if self.policy.require_chain_aud && !any {
            return Err(AatError::new(
                Step::S6c,
                "no token in the chain carries aud",
            ));
        }
        Ok(())
    }

    /// §8 steps 7a and 7b. Returns the PoP claims.
    fn pop_signature(&self, leaf: &Token<'_>, pop: &str) -> Result<Value, AatError> {
        let deny = AatError::new;
        if pop.len() > self.limits.max_token_size {
            return Err(deny(Step::S7a, "PoP JWT too large"));
        }
        let jws = jose::split(pop).ok_or(deny(Step::S7a, "PoP JWT is not a compact JWS"))?;
        let header = jws::header(jws.header, POP_TYP).ok_or(deny(Step::S7a, "bad PoP header"))?;
        if !header.alg.fits(&leaf.holder.key) {
            return Err(deny(Step::S7a, "PoP alg does not fit the leaf cnf key"));
        }
        if !jose::signature_ok(&leaf.holder.key, jws) {
            return Err(deny(
                Step::S7b,
                "PoP signature does not verify under the leaf cnf key",
            ));
        }
        parse_claims(jws).ok_or(deny(Step::S7b, "PoP claims do not parse"))
    }

    /// §8 steps 7c to 7i, on claims whose signature verified. Returns the
    /// PoP `jti` and the last second the PoP is accepted in.
    fn pop_claims(
        &self,
        leaf: &Token<'_>,
        claims: &Value,
        tool: &str,
        args: &Value,
        now: i64,
        replay: Option<&dyn ReplayCache>,
    ) -> Result<(String, i64), AatError> {
        let deny = AatError::new;
        let jti = non_empty(claims, "jti");
        let aat_id = non_empty(claims, "aat_id");
        let aat_hash = non_empty(claims, "aat_hash");
        let aat_tool = non_empty(claims, "aat_tool");
        let iat = int(claims, "iat");
        let hta = claims.get("hta").filter(|h| h.as_object().is_some());
        let (Some(jti), Some(aat_id), Some(aat_hash), Some(aat_tool), Some(iat), Some(hta)) =
            (jti, aat_id, aat_hash, aat_tool, iat, hta)
        else {
            return Err(deny(Step::S7c, "PoP claim missing or malformed"));
        };
        if aat_id != leaf.jti || aat_hash != jose::hash(leaf.jws.signing_input) {
            return Err(deny(Step::S7c, "PoP is not bound to the leaf"));
        }
        match claims.get("aat_aud") {
            Some(aud) => {
                if !aud
                    .as_str()
                    .is_some_and(|aud| self.audiences.iter().any(|a| a == aud))
                {
                    return Err(deny(
                        Step::S7d,
                        "aat_aud does not identify this enforcement point",
                    ));
                }
            }
            None if self.policy.require_pop_aud => {
                return Err(deny(Step::S7d, "aat_aud required"));
            }
            None => {}
        }
        if aat_tool != tool {
            return Err(deny(Step::S7e, "aat_tool is not the invoked tool"));
        }
        if !hta.numbers_admissible() || hta.jcs() != args.jcs() {
            return Err(deny(Step::S7f, "hta does not match the arguments"));
        }
        if iat.abs_diff(now) > self.limits.pop_window.unsigned_abs() {
            return Err(deny(Step::S7g, "PoP iat outside the window"));
        }
        let future = self.limits.pop_max_future.clamp(0, self.limits.pop_window);
        if iat > now.saturating_add(future) {
            return Err(deny(Step::S7g, "PoP iat in the future"));
        }
        if let Some(nonces) = &self.policy.nonces {
            let nonce = claims.get("nonce").and_then(Value::as_str);
            if !nonce.is_some_and(|n| nonces.contains(n)) {
                return Err(deny(Step::S7h, "nonce missing or not accepted"));
            }
        }
        let until = iat.saturating_add(self.limits.pop_window);
        if let Some(cache) = replay {
            match cache.check_and_record(&leaf.holder.thumbprint, &jti, until, now) {
                Recorded::Fresh => {}
                Recorded::Replayed => return Err(deny(Step::S7i, "PoP jti already accepted")),
                Recorded::OverQuota => {
                    return Err(deny(Step::S7i, "PoP jti not recorded: holder over quota"));
                }
                Recorded::Full => {
                    return Err(deny(Step::S7i, "PoP jti not recorded: replay cache full"));
                }
            }
        }
        Ok((jti, until))
    }
}

impl ChainDecoder for Verifier {
    type Input = [String];
    type Error = AatError;

    /// §8 steps 1 to 5, plus the check that every `aud` is a string or an
    /// array of strings. No invocation, audience match or PoP checks, so
    /// `holder_proof` is `false` and the result must not authorize an
    /// invocation on its own (§7.3).
    fn decode(&self, input: &[String], now: i64) -> Result<NormalizedChain, AatError> {
        self.chain(input, now).map(|chain| normalize(&chain, false))
    }
}

/// Parses each tool's constraint map (§8 steps 3n and 4o) within the
/// constraint depth and node limits.
pub(crate) fn tool_maps(
    tools: &[(String, Value)],
    limits: &Limits,
) -> Option<BTreeMap<String, ToolMap>> {
    let mut nodes = limits.max_constraint_nodes;
    tools
        .iter()
        .map(|(name, map)| {
            let map = ToolMap::parse(map.as_object()?, limits.max_constraint_depth, &mut nodes)?;
            Some((name.clone(), map))
        })
        .collect()
}

/// §8 step 6b against the leaf's `tools`. Returns the parsed arguments.
pub(crate) fn invocation_args(
    tools: &BTreeMap<String, ToolMap>,
    invocation: &Invocation<'_>,
    limits: &Limits,
) -> Result<Value, &'static str> {
    let map = tools
        .get(invocation.tool)
        .ok_or("tool not granted by the leaf")?;
    if invocation.args_json.len() > limits.max_token_size {
        return Err("arguments too large");
    }
    let args = json::parse(invocation.args_json.as_bytes())
        .map_err(|_| "arguments are not a JSON object without duplicate members")?;
    let members = args.as_object().ok_or("arguments are not a JSON object")?;
    if !args.numbers_admissible() {
        return Err("argument number is not admissible");
    }
    if !map.permits(members) {
        return Err("arguments violate the leaf constraints");
    }
    Ok(args)
}

/// §8 step 4p: every child tool is in the parent (4p1), and each tool's
/// constraint map attenuates the parent's. Each rule runs over every tool
/// before the next (4p2, then 4p3, then 4p4), so the earliest failing rule
/// across tools is reported.
pub(crate) fn attenuation(
    child: &BTreeMap<String, ToolMap>,
    parent: &BTreeMap<String, ToolMap>,
) -> Result<(), Step> {
    if child.keys().any(|t| !parent.contains_key(t)) {
        return Err(Step::S4p1);
    }
    let first = child
        .iter()
        .filter_map(|(name, map)| parent.get(name).and_then(|p| map.attenuates(p).err()))
        .min();
    first.map_or(Ok(()), Err)
}

fn normalize(chain: &Verified<'_>, holder_proof: bool) -> NormalizedChain {
    let mut hops: Vec<Hop> = Vec::with_capacity(chain.tokens.len());
    for token in &chain.tokens {
        let actor = ActorId::Key(KeyThumbprint(token.holder.thumbprint.clone()));
        let (delegator, signer, signer_binding, link) = match hops.last() {
            None => (
                None,
                KeyThumbprint(chain.anchor.thumbprint.clone()),
                SignerBinding::RootAnchor,
                Link::Root,
            ),
            Some(parent) => {
                let par_hash = token
                    .claims
                    .get("par_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let signer = match &parent.cnf {
                    Some(cnf) => cnf.thumbprint.clone(),
                    None => KeyThumbprint(String::new()),
                };
                (
                    Some(parent.actor.clone()),
                    signer,
                    SignerBinding::ParentCnf,
                    Link::ParHash(par_hash),
                )
            }
        };
        hops.push(Hop {
            id: token.jti.clone(),
            depth: token.depth,
            max_depth: Some(token.max_depth),
            actor,
            principal: Principal::Unspecified,
            delegator,
            signer,
            signer_binding,
            link,
            authority: Authority {
                detail_type: DETAIL_TYPE.to_owned(),
                json: token.tools_jcs.clone(),
            },
            validity: Validity {
                issued_at: token.iat,
                expires_at: token.exp,
            },
            audience: token.audience.clone(),
            cnf: Some(Cnf {
                thumbprint: KeyThumbprint(token.holder.thumbprint.clone()),
            }),
            status: None,
            assurance: Assurance::Verified,
        });
    }
    NormalizedChain {
        profile: Profile::Aat02,
        principal: Principal::Unspecified,
        root: TrustRef {
            issuer: chain.anchor.issuer.clone(),
            key: KeyThumbprint(chain.anchor.thumbprint.clone()),
        },
        hops,
        holder_proof,
    }
}

/// Parses a payload after its signature verified, rejecting duplicate
/// member names. The claims must be a JSON object.
fn parse_claims(jws: Compact<'_>) -> Option<Value> {
    let claims = json::parse(&jose::b64(jws.payload)?).ok()?;
    claims.as_object()?;
    Some(claims)
}

fn int(claims: &Value, name: &str) -> Option<i64> {
    claims.get(name).and_then(Value::as_integer)
}

fn count(claims: &Value, name: &str) -> Option<u32> {
    claims.get(name).and_then(Value::as_count)
}

fn non_empty(claims: &Value, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// The `tools` members of the single AAT entry, if there is exactly one and
/// its `tools` is an object whose values are objects (§8 steps 3m and 4n).
fn aat_tools(ad: Option<&Value>) -> Option<&[(String, Value)]> {
    let mut entries = ad?
        .as_array()?
        .iter()
        .filter(|e| e.get("type").and_then(Value::as_str) == Some(DETAIL_TYPE));
    let entry = entries.next()?;
    if entries.next().is_some() {
        return None;
    }
    let tools = entry.get("tools")?.as_object()?;
    tools
        .iter()
        .all(|(_, v)| v.as_object().is_some())
        .then_some(tools)
}

/// `aud` as a list: a string, or an array of strings (RFC 7519 §4.1.3).
fn audience_list(aud: &Value) -> Option<Vec<String>> {
    match aud {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(items) => items
            .iter()
            .map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => None,
    }
}

/// An absolute URI: a scheme (RFC 3986 §3.1), a colon, and no whitespace or
/// control characters.
fn is_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}
