//! The decision pipeline, independent of the transport.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use tracing::Instrument;
use visado_authzen::{Action, Entity, EvaluationRequest, Pdp};
use visado_chain::{ActorId, Hop, NormalizedChain, Principal, Profile};
use visado_chain_aat::{Invocation, MemoryReplayCache, Presentation, Verifier, jwk_thumbprint};
use visado_chain_act::{ActError, ActToken, Caller as ActCaller};
use visado_chain_asor::{Action as AsorAction, HttpRequest};
use visado_credentials::{
    AccessToken, AuthError, Authenticated, Authenticator, DPOP_ALGS, Method, RequestView,
};
use visado_txn_token::{
    KeySet, Replacement, Scope, TxnTokenClaims, Validation, VerifiedTxnToken, mint, replace, verify,
};
use wimsey_jose::SigningKey;

use crate::recent::{ChainSummary, Decision, PdpResult, RequestLog, RequestSummary, bounded};

/// The header carrying an AAT chain, root first, comma-separated.
pub const AAT_CHAIN_HEADER: &str = "aat-chain";
/// The header carrying the AAT proof of possession.
pub const AAT_POP_HEADER: &str = "aat-pop";
/// The header carrying an asor Delegation Chain, root first, comma-separated.
pub const ASOR_CHAIN_HEADER: &str = "agent-delegation-chain";
/// The header carrying a DPoP proof (RFC 9449): for a DPoP-bound access
/// token, or for the asor leaf key.
pub const DPOP_HEADER: &str = visado_credentials::DPOP_HEADER;

/// Headers always removed before the request goes upstream, in addition to the
/// authenticator's user token header. The upstream gets the Transaction Token
/// instead (MCP and the Txn-Token draft both forbid forwarding the inbound
/// access token).
pub const STRIPPED_HEADERS: [&str; 4] = [
    "authorization",
    "workload-identity-token",
    "signature-input",
    "signature",
];

/// Settings for one trust domain.
#[derive(Debug)]
pub struct GateConfig {
    /// The trust domain: `aud` of minted Transaction Tokens.
    pub trust_domain: String,
    /// Key that signs Transaction Tokens.
    pub signing_key: SigningKey,
    /// `kid` for that key.
    pub kid: String,
    /// Lifetime of minted Transaction Tokens, in seconds.
    pub txn_lifetime: u64,
    /// Scope for a workload that calls on its own behalf, with no user token.
    pub default_scope: Scope,
    /// Workloads (by WIT `sub`) allowed to forward a Transaction Token from an
    /// earlier hop. Anyone else's inbound `Txn-Token` is rejected.
    pub internal_callers: BTreeSet<String>,
    /// Authorities (host and optional port) this gate protects. Requests for
    /// any other authority are denied. Empty means any authority.
    pub allowed_authorities: BTreeSet<String>,
    /// AAT delegation-chain verification. `None` rejects requests that carry
    /// an `AAT-Chain` header.
    pub aat: Option<Verifier>,
    /// asor delegation-chain verification. `None` rejects requests that
    /// carry an `Agent-Delegation-Chain` header.
    pub asor: Option<visado_chain_asor::Verifier>,
    /// RFC 8693 `act` chains in the caller's access token. `None` rejects
    /// requests whose access token carries an `act` claim.
    pub act: Option<visado_chain_act::Verifier>,
    /// Deny requests that carry no delegation chain of any format.
    pub require_chain: bool,
}

/// The parts of the request the gate looks at.
#[derive(Debug, Clone)]
pub struct CheckInput {
    /// HTTP method.
    pub method: String,
    /// `http` or `https`.
    pub scheme: String,
    /// Host and optional port.
    pub authority: String,
    /// Path and query.
    pub path: String,
    /// Headers, names lowercased.
    pub headers: Vec<(String, String)>,
    /// The request body exactly as received, when the proxy sends it
    /// (`with_request_body` in Envoy).
    pub body: Option<Vec<u8>>,
    /// The peer certificate from the proxy's own TLS termination, URL-encoded
    /// PEM as in Envoy's `source.certificate`.
    pub peer_certificate: Option<String>,
}

/// What to do with the request.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Forward it, with these headers set and removed.
    Allow {
        /// `txn` of the Transaction Token now on the request.
        txn: String,
        /// Headers to set, overwriting any existing value.
        set: Vec<(String, String)>,
        /// Headers to remove.
        remove: Vec<String>,
    },
    /// Reject it.
    Deny {
        /// HTTP status: 401 for authentication failures, 403 otherwise.
        status: u16,
        /// Stable reason code.
        code: String,
        /// `WWW-Authenticate` value for a 401.
        challenge: Option<String>,
    },
}

/// The decision pipeline: authenticate, authorize, mint.
#[derive(Debug)]
pub struct Gate<P> {
    config: GateConfig,
    authenticator: Authenticator,
    pdp: P,
    txn_keys: KeySet,
    stripped: Vec<String>,
    aat_replay: MemoryReplayCache,
    dpop_replay: MemoryReplayCache,
    log: Option<Arc<RequestLog>>,
}

impl<P: Pdp> Gate<P> {
    /// A gate. Inbound Transaction Tokens are verified with the gate's own key.
    pub fn new(config: GateConfig, authenticator: Authenticator, pdp: P) -> Self {
        let txn_keys =
            KeySet::new().with_key(config.kid.clone(), config.signing_key.verifying_key());
        let mut stripped: Vec<String> = STRIPPED_HEADERS.iter().map(|h| (*h).to_owned()).collect();
        stripped.extend(
            [
                AAT_CHAIN_HEADER,
                AAT_POP_HEADER,
                ASOR_CHAIN_HEADER,
                DPOP_HEADER,
            ]
            .map(str::to_owned),
        );
        stripped.push(authenticator.user_token_header().to_owned());
        Self {
            config,
            authenticator,
            pdp,
            txn_keys,
            stripped,
            aat_replay: MemoryReplayCache::new(100_000),
            dpop_replay: MemoryReplayCache::new(100_000),
            log: None,
        }
    }

    /// Records a summary of every decision in `log`, for the chain view.
    /// The summaries hold identifiers and outcomes, never tokens.
    #[must_use]
    pub fn with_request_log(mut self, log: Arc<RequestLog>) -> Self {
        self.log = Some(log);
        self
    }

    /// Decides on `input` at `now`. `txn` is the identifier used if a new
    /// Transaction Token is minted.
    pub async fn check(&self, input: &CheckInput, now: u64, txn: &str) -> Outcome {
        let resource = resource_id(input);
        let span = tracing::info_span!(
            "visado.authorize",
            otel.name = %format!("visado.authorize {resource}"),
            otel.kind = "server",
            http.request.method = %input.method,
            url.full = %resource,
            visado.txn = tracing::field::Empty,
            visado.agent = tracing::field::Empty,
            visado.principal = tracing::field::Empty,
            visado.decision = tracing::field::Empty,
            visado.reason = tracing::field::Empty,
        );
        let result = self.decide(input, now, txn).instrument(span.clone()).await;
        let (trail, decision, reason) = match &result {
            Ok(allowed) => (&allowed.trail, "allow", "ok"),
            Err(denied) => (&*denied.trail, "deny", denied.code),
        };
        span.record("visado.txn", trail.txn.as_str());
        span.record("visado.agent", trail.agent.as_str());
        span.record("visado.principal", trail.principal.as_str());
        span.record("visado.decision", decision);
        span.record("visado.reason", reason);
        if let Some(log) = &self.log {
            log.record(summary(input, now, txn, &result));
        }
        match result {
            Ok(allowed) => {
                audit(input, &allowed.trail, "allow", "ok", "");
                Outcome::Allow {
                    txn: allowed.trail.txn,
                    set: vec![("txn-token".into(), allowed.token)],
                    remove: self.stripped.clone(),
                }
            }
            Err(denied) => {
                audit(
                    input,
                    &denied.trail,
                    "deny",
                    denied.code,
                    denied.detail.as_deref().unwrap_or(""),
                );
                Outcome::Deny {
                    status: denied.status,
                    code: denied.code.to_owned(),
                    challenge: denied.challenge.map(Challenge::render),
                }
            }
        }
    }

    async fn decide(&self, input: &CheckInput, now: u64, txn: &str) -> Result<Allowed, Denied> {
        let mut trail = Trail::default();
        self.check_target(input)?;
        let caller = self.authenticate(input, now)?;
        trail.agent.clone_from(&caller.caller);
        trail.method = Some(caller.method);
        let chain = self.verify_chain(input, &caller, now, &trail)?;
        if self.log.is_some() {
            trail.chain = chain
                .as_ref()
                .map(|c| Box::new(ChainSummary::from_chain(c)));
        }

        let inbound = input
            .headers
            .iter()
            .find(|(n, _)| n == "txn-token")
            .map(|(_, v)| v.as_str());
        let forwarded = match inbound {
            Some(token) => Some(self.accept_forwarded(&caller, token, now, &trail)?),
            None => None,
        };
        // A chain that names its principal must be about the forwarded
        // transaction's subject; otherwise the replaced token would record
        // one user's delegation inside another user's transaction.
        if let (Some(claims), Some(chain)) = (&forwarded, &chain)
            && let Principal::Subject { subject, .. } = &chain.principal
            && subject != &claims.sub
        {
            let mut denied = Denied::new(403, "chain.principal_mismatch", &trail);
            denied.detail = Some(
                format!(
                    "chain principal {subject:?} is not the transaction subject {:?}",
                    claims.sub
                )
                .into_boxed_str(),
            );
            return Err(denied);
        }
        let (principal, scope) = match &forwarded {
            Some(claims) => (claims.sub.clone(), claims.scope.clone()),
            None => self.principal_and_scope(&caller, &trail)?,
        };
        trail.principal.clone_from(&principal);
        trail.txn = forwarded
            .as_ref()
            .map_or_else(|| txn.to_owned(), |c| c.txn.clone());

        let mut request = evaluation_request(input, &caller, &principal, &scope, &trail.txn);
        if let Some(chain) = &chain {
            request = request.with_context("chain", chain_context(chain, &caller, Reader::Pdp));
        }
        match self.pdp.evaluate(&request, &trail.txn).await {
            Ok(decision) if decision.allowed => trail.pdp = Some(PdpResult::Allow),
            Ok(_) => {
                trail.pdp = Some(PdpResult::Deny);
                return Err(Denied::new(403, "pdp.deny", &trail));
            }
            Err(e) => {
                trail.pdp = Some(PdpResult::Error(e.code().to_owned()));
                return Err(Denied::new(403, e.code(), &trail));
            }
        }

        let token = if let (Some(claims), Some(token)) = (forwarded, inbound) {
            match &chain {
                // A chain verified at this hop is recorded in the token. The
                // forwarded token is replaced, never widened: tctx only gains
                // a member named after this caller, scope and identity stay,
                // and the lifetime does not grow.
                Some(chain) => self.replace_with_chain(claims, chain, &caller, now, &trail)?,
                None => token.to_owned(),
            }
        } else {
            let claims = TxnTokenClaims {
                iss: None,
                iat: now,
                aud: self.config.trust_domain.clone(),
                exp: now + self.config.txn_lifetime,
                txn: trail.txn.clone(),
                sub: principal,
                scope,
                req_wl: requesting_workload(&caller),
                tctx: Some(tctx(&caller, chain.as_ref())),
                rctx: Some(rctx(input)),
            };
            mint(&claims, Some(&self.config.kid), &self.config.signing_key)
                .map_err(|e| Denied::new(403, e.code(), &trail))?
        };
        Ok(Allowed { token, trail })
    }

    /// Verifies the delegation chain if the request carries one (see
    /// docs/bindings.md): an AAT chain, an asor chain, or an RFC 8693 `act`
    /// claim in the caller's access token, never more than one. Only a key
    /// holding caller may present an AAT or asor chain, and the chain's
    /// holder must be the workload that proved possession of that key. An
    /// `act` chain's current actor must be the caller.
    fn verify_chain(
        &self,
        input: &CheckInput,
        caller: &Authenticated,
        now: u64,
        trail: &Trail,
    ) -> Result<Option<NormalizedChain>, Denied> {
        let aat = header(input, AAT_CHAIN_HEADER);
        let asor = header(input, ASOR_CHAIN_HEADER);
        let act = caller.user.as_ref().filter(|user| user.act.is_some());
        let chain = match (aat, asor, act) {
            (None, None, None) => {
                if self.config.require_chain {
                    return Err(Denied::new(403, "chain.required", trail));
                }
                return Ok(None);
            }
            (None, None, Some(user)) => return self.verify_act(caller, user, trail).map(Some),
            (Some(chain), None, None) => self.verify_aat(input, caller, chain, now, trail)?,
            (None, Some(chain), None) => self.verify_asor(input, caller, chain, now, trail)?,
            _ => return Err(Denied::new(400, "chain.ambiguous", trail)),
        };
        // The chain must belong to the caller: its leaf holder key is the
        // key the caller proved possession of with its WIT.
        let key = caller
            .proof_key
            .as_ref()
            .ok_or_else(|| Denied::new(403, "chain.unbound_caller", trail))?;
        let holder = chain
            .leaf()
            .and_then(|leaf| leaf.cnf.as_ref())
            .map(|c| c.thumbprint.0.as_str());
        if holder != Some(jwk_thumbprint(key).as_str()) {
            return Err(Denied::new(403, "chain.holder_mismatch", trail));
        }
        Ok(Some(chain))
    }

    fn verify_aat(
        &self,
        input: &CheckInput,
        caller: &Authenticated,
        chain_header: &str,
        now: u64,
        trail: &Trail,
    ) -> Result<NormalizedChain, Denied> {
        let Some(verifier) = &self.config.aat else {
            return Err(Denied::new(403, "chain.unsupported", trail));
        };
        // The chain must belong to the caller: the leaf holder must be the key
        // the caller proved possession of (the WIT key, or the certificate key
        // over mTLS). A bearer caller has no such key and cannot present one.
        if caller.proof_key.is_none() {
            return Err(Denied::new(403, "chain.unbound_caller", trail));
        }
        let pop = header(input, AAT_POP_HEADER)
            .ok_or_else(|| Denied::new(401, "chain.missing_pop", trail))?;
        let chain = split_chain(chain_header);
        let (tool, args) =
            invocation(input).ok_or_else(|| Denied::new(400, "chain.bad_invocation", trail))?;
        let now = i64::try_from(now).map_err(|_| Denied::new(500, "internal.clock", trail))?;
        verifier
            .verify(
                &Presentation { chain: &chain, pop },
                &Invocation {
                    tool: &tool,
                    args_json: &args,
                },
                now,
                Some(&self.aat_replay),
            )
            .map(|authorized| authorized.chain)
            .map_err(|e| Denied::new(403, e.code(), trail))
    }

    /// An asor chain: the tool is the action's scope and its arguments the
    /// action's parameters; the DPoP proof binds the leaf key to this
    /// request.
    fn verify_asor(
        &self,
        input: &CheckInput,
        caller: &Authenticated,
        chain_header: &str,
        now: u64,
        trail: &Trail,
    ) -> Result<NormalizedChain, Denied> {
        let Some(verifier) = &self.config.asor else {
            return Err(Denied::new(403, "chain.unsupported", trail));
        };
        if caller.proof_key.is_none() {
            return Err(Denied::new(403, "chain.unbound_caller", trail));
        }
        // The one DPoP header already proves the caller's access token, so
        // it cannot also prove the leaf key.
        if caller.method == Method::OAuthDpop {
            return Err(Denied::new(400, "chain.proof_conflict", trail));
        }
        let proof = header(input, DPOP_HEADER)
            .ok_or_else(|| Denied::new(401, "chain.missing_pop", trail))?;
        let chain = split_chain(chain_header);
        let (tool, args) =
            invocation(input).ok_or_else(|| Denied::new(400, "chain.bad_invocation", trail))?;
        let uri = format!("{}://{}{}", input.scheme, input.authority, input.path);
        let now = i64::try_from(now).map_err(|_| Denied::new(500, "internal.clock", trail))?;
        verifier
            .verify(
                &visado_chain_asor::Presentation {
                    chain: &chain,
                    dpop: proof,
                },
                &HttpRequest {
                    method: &input.method,
                    uri: &uri,
                },
                &AsorAction {
                    scope: &tool,
                    params_json: &args,
                    totals: None,
                },
                now,
                Some(&self.dpop_replay),
            )
            .map(|authorized| authorized.chain)
            .map_err(|e| Denied::new(403, e.code(), trail))
    }

    /// An RFC 8693 `act` chain from the caller's access token, which
    /// `visado-credentials` already verified. Only a caller that proved
    /// possession of a key may present one, and the current actor must be
    /// that caller; prior actors are recorded but not checked against
    /// anything.
    fn verify_act(
        &self,
        caller: &Authenticated,
        user: &AccessToken,
        trail: &Trail,
    ) -> Result<NormalizedChain, Denied> {
        let Some(verifier) = &self.config.act else {
            return Err(Denied::new(403, "chain.unsupported", trail));
        };
        // As for AAT and asor, the chain must belong to a caller that proved
        // possession of a key for this request; a bearer token alone does
        // not show who presents it.
        if caller.proof_key.is_none() {
            return Err(Denied::new(403, "chain.unbound_caller", trail));
        }
        let Some(act) = user.act.as_ref() else {
            return Err(Denied::new(500, "internal.act", trail));
        };
        let token = ActToken {
            issuer: &user.issuer,
            subject: &user.subject,
            id: user.id.as_deref(),
            key_thumbprint: &user.key_thumbprint,
            issued_at: user.issued_at,
            expires_at: user.expires_at,
            act,
        };
        let presenter = ActCaller {
            id: &caller.caller,
            proved_key: caller.proof_key.is_some(),
        };
        verifier.verify(&token, &presenter).map_err(|e| {
            let mut denied = Denied::new(403, e.as_str(), trail);
            // Identifiers only, never the token.
            denied.detail = Some(match (e, act.get("sub").and_then(Value::as_str)) {
                (ActError::ActorMismatch, Some(actor)) => format!(
                    "current actor {actor:?} is bound to {:?}, not to the caller {:?}",
                    verifier.bound_caller(actor),
                    caller.caller
                )
                .into_boxed_str(),
                _ => e.to_string().into_boxed_str(),
            });
            denied
        })
    }

    fn replace_with_chain(
        &self,
        claims: TxnTokenClaims,
        chain: &NormalizedChain,
        caller: &Authenticated,
        now: u64,
        trail: &Trail,
    ) -> Result<String, Denied> {
        let max_exp = claims.exp;
        let previous = VerifiedTxnToken {
            claims,
            kid: Some(self.config.kid.clone()),
        };
        let mut additions = Map::new();
        additions.insert(
            format!("chain:{}", caller.caller),
            chain_context(chain, caller, Reader::TxnToken),
        );
        let next = replace(
            &previous,
            Replacement {
                tctx_additions: additions,
                req_wl: Some(requesting_workload(caller)),
                ..Replacement::default()
            },
            now,
            self.config.txn_lifetime,
            Some(max_exp),
        )
        .map_err(|e| Denied::new(403, e.code(), trail))?;
        mint(&next, Some(&self.config.kid), &self.config.signing_key)
            .map_err(|e| Denied::new(403, e.code(), trail))
    }

    fn check_target(&self, input: &CheckInput) -> Result<(), Denied> {
        let none = Trail::default();
        if input.scheme.is_empty() {
            return Err(Denied::new(400, "request.no_scheme", &none));
        }
        if !self.config.allowed_authorities.is_empty()
            && !self.config.allowed_authorities.contains(&input.authority)
        {
            return Err(Denied::new(403, "request.unknown_authority", &none));
        }
        if !is_normalized(&input.path) {
            return Err(Denied::new(400, "request.unnormalized_path", &none));
        }
        Ok(())
    }

    fn authenticate(&self, input: &CheckInput, now: u64) -> Result<Authenticated, Denied> {
        let view = RequestView {
            method: &input.method,
            scheme: &input.scheme,
            authority: &input.authority,
            path: &input.path,
            headers: &input.headers,
            body: input.body.as_deref(),
            peer_certificate: input.peer_certificate.as_deref(),
        };
        self.authenticator.authenticate(&view, now).map_err(|e| {
            let wimse = input
                .headers
                .iter()
                .any(|(n, _)| n == "workload-identity-token");
            let dpop = !wimse
                && header(input, "authorization").is_some_and(|a| {
                    a.trim_start()
                        .split_once(' ')
                        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("dpop"))
                });
            let (status, challenge) = match e {
                AuthError::ReplayCacheFull => (503, None),
                // draft-ietf-wimse-http-signature: a failed signed request is
                // a 400 that does not say which check failed.
                AuthError::HttpSig(_) => (400, None),
                // No scheme the client could answer: the certificate came
                // from the TLS handshake.
                AuthError::Certificate(_) | AuthError::CertificateUntrustedDomain => (401, None),
                // RFC 9449 §7.1.
                AuthError::DpopProof(_) | AuthError::DpopReplay => {
                    (401, Some(Challenge::Dpop(DpopError::InvalidProof)))
                }
                AuthError::DpopBinding(_) | AuthError::DpopBound => {
                    (401, Some(Challenge::Dpop(DpopError::InvalidToken)))
                }
                _ if wimse => (401, Some(Challenge::Wpt)),
                AuthError::MissingCredentials => (401, Some(Challenge::Bearer)),
                _ if dpop => (401, Some(Challenge::Dpop(DpopError::InvalidToken))),
                _ => (401, Some(Challenge::Bearer)),
            };
            let mut denied = Denied::new(status, e.code(), &Trail::default());
            denied.challenge = challenge;
            denied.detail = Some(e.to_string().into_boxed_str());
            denied
        })
    }

    /// An inbound Transaction Token is accepted only from a configured internal
    /// workload that proved possession of a key for this request, and only if
    /// it verifies against this gate's key and domain. With a WPT the token is
    /// bound through `tth`; with an HTTP signature it is a covered component;
    /// with mTLS it arrived on the connection the certificate authenticated.
    /// Bearer callers (an access token or a JWT-SVID) and OAuth clients
    /// (DPoP-bound tokens) cannot forward one.
    fn accept_forwarded(
        &self,
        caller: &Authenticated,
        token: &str,
        now: u64,
        trail: &Trail,
    ) -> Result<TxnTokenClaims, Denied> {
        if !matches!(
            caller.method,
            Method::WitWpt | Method::WitHttpSig | Method::Mtls
        ) || !self.config.internal_callers.contains(&caller.caller)
        {
            return Err(Denied::new(403, "txn.untrusted_hop", trail));
        }
        let validation = Validation::new(&self.config.trust_domain, now);
        verify(token, &self.txn_keys, &validation)
            .map(|verified| verified.claims)
            .map_err(|e| Denied::new(403, e.code(), trail))
    }

    /// Who the transaction is for, and with what scope. A user token without a
    /// scope grants nothing; the default scope is only for a workload calling
    /// on its own behalf.
    fn principal_and_scope(
        &self,
        caller: &Authenticated,
        trail: &Trail,
    ) -> Result<(String, Scope), Denied> {
        match &caller.user {
            Some(user) => match user.scope.as_deref().map(Scope::parse) {
                Some(scope) if !scope.is_empty() => Ok((user.subject.clone(), scope)),
                _ => Err(Denied::new(403, "token.no_scope", trail)),
            },
            None => Ok((caller.caller.clone(), self.config.default_scope.clone())),
        }
    }
}

/// The first value of header `name`.
fn header<'a>(input: &'a CheckInput, name: &str) -> Option<&'a str> {
    input
        .headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// A chain header's tokens. A comma never appears in a compact JWS, so a
/// proxy that joins repeated headers with commas does not change it.
fn split_chain(value: &str) -> Vec<String> {
    value.split(',').map(|t| t.trim().to_owned()).collect()
}

/// What is known about the request so far, for the audit event.
#[derive(Debug, Default, Clone)]
struct Trail {
    agent: String,
    principal: String,
    txn: String,
    /// How the caller authenticated, once it has.
    method: Option<Method>,
    /// What the PDP said, once asked.
    pdp: Option<PdpResult>,
    /// The verified chain, kept only when there is a request log.
    chain: Option<Box<ChainSummary>>,
}

struct Allowed {
    token: String,
    trail: Trail,
}

struct Denied {
    status: u16,
    code: &'static str,
    challenge: Option<Challenge>,
    /// Why, for the audit record only. Never contains a token.
    detail: Option<Box<str>>,
    trail: Box<Trail>,
}

/// The `WWW-Authenticate` challenge for a 401.
#[derive(Debug, Clone, Copy)]
enum Challenge {
    Wpt,
    /// `Bearer`, with `DPoP` alongside so a client can tell DPoP is accepted.
    Bearer,
    /// `DPoP` with an RFC 9449 §7.1 `error` code.
    Dpop(DpopError),
}

/// The `error` of a `DPoP` challenge (RFC 9449 §7.1).
#[derive(Debug, Clone, Copy)]
enum DpopError {
    /// The proof is missing, repeated or invalid.
    InvalidProof,
    /// The token is invalid or not bound to the proof key.
    InvalidToken,
}

impl Challenge {
    fn render(self) -> String {
        let algs = DPOP_ALGS.join(" ");
        match self {
            Self::Wpt => "WPT".to_owned(),
            Self::Bearer => format!("Bearer, DPoP algs=\"{algs}\""),
            Self::Dpop(error) => {
                let error = match error {
                    DpopError::InvalidProof => "invalid_dpop_proof",
                    DpopError::InvalidToken => "invalid_token",
                };
                format!("DPoP error=\"{error}\", algs=\"{algs}\"")
            }
        }
    }
}

impl Denied {
    fn new(status: u16, code: &'static str, trail: &Trail) -> Self {
        Self {
            status,
            code,
            challenge: None,
            detail: None,
            trail: Box::new(trail.clone()),
        }
    }
}

/// Rejects paths an upstream might resolve differently from how they are
/// authorized: dot segments, encoded dots or slashes, empty segments, and
/// backslashes.
fn is_normalized(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if !path.starts_with('/') || path.contains('\\') || path.contains("//") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    !path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
}

/// `req_wl` for the token. Access token callers are OAuth clients, not
/// workloads, so they are marked to keep them apart from workload identifiers.
fn requesting_workload(caller: &Authenticated) -> String {
    match caller.method {
        Method::Bearer | Method::OAuthDpop => format!("oauth-client:{}", caller.caller),
        _ => caller.caller.clone(),
    }
}

fn resource_id(input: &CheckInput) -> String {
    let path = input.path.split(['?', '#']).next().unwrap_or("");
    format!("{}://{}{}", input.scheme, input.authority, path)
}

fn evaluation_request(
    input: &CheckInput,
    caller: &Authenticated,
    principal: &str,
    scope: &Scope,
    txn: &str,
) -> EvaluationRequest {
    let principal = (principal != caller.caller).then(|| Entity::new("user", principal));
    let mut request = EvaluationRequest::for_agent(
        caller.caller.clone(),
        principal,
        Entity::new("http_resource", resource_id(input)),
        Action::new(input.method.clone()),
    );
    if matches!(caller.method, Method::Bearer | Method::OAuthDpop) {
        request.subject.kind = "client".into();
    }
    request
        .with_context("scope", json!(scope.to_string()))
        .with_context("auth_method", json!(method_name(caller.method)))
        .with_context("txn", json!(txn))
}

const fn method_name(method: Method) -> &'static str {
    match method {
        Method::WitWpt => "wit-wpt",
        Method::WitHttpSig => "wit-httpsig",
        Method::Mtls => "mtls",
        Method::JwtSvid => "jwt-svid",
        Method::Bearer => "bearer",
        Method::OAuthDpop => "oauth-dpop",
    }
}

fn tctx(caller: &Authenticated, chain: Option<&NormalizedChain>) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("agent".into(), json!(caller.caller));
    map.insert("auth_method".into(), json!(method_name(caller.method)));
    if let Some(chain) = chain {
        map.insert(
            "chain".into(),
            chain_context(chain, caller, Reader::TxnToken),
        );
    }
    map
}

/// Who a chain context is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// The PDP, which makes the access decision.
    Pdp,
    /// The Transaction Token, a record for downstream services.
    TxnToken,
}

/// The chain as the PDP and the Transaction Token see it: format, depth, the
/// holders from root to leaf, and the leaf's authority. An RFC 8693 `act`
/// chain has its own shape (see [`act_context`]).
fn chain_context(chain: &NormalizedChain, caller: &Authenticated, reader: Reader) -> Value {
    if chain.profile == Profile::Rfc8693Act {
        return act_context(chain, caller, reader);
    }
    let holders: Vec<String> = chain
        .hops
        .iter()
        .filter_map(|hop| hop.cnf.as_ref().map(|c| c.thumbprint.0.clone()))
        .collect();
    let mut context = json!({
        "profile": chain.profile.as_str(),
        "issuer": chain.root.issuer,
        "depth": chain.hops.len().saturating_sub(1),
        "holders": holders,
        "authority": chain.leaf().map(|leaf| leaf.authority.json.clone()),
    });
    if let Principal::Subject { subject, .. } = &chain.principal {
        context["principal"] = json!(subject);
    }
    context
}

/// An RFC 8693 `act` chain: the issuer, the principal, the current actor
/// and the kind of caller it was bound to (`workload` or `client`). RFC 8693 §4.1 says prior actors "are not to be considered in
/// access control decisions", so the PDP does not get them; the Transaction
/// Token records them, least recent first, with the depth.
fn act_context(chain: &NormalizedChain, caller: &Authenticated, reader: Reader) -> Value {
    let (current, prior) = chain
        .hops
        .split_last()
        .map_or((None, &[][..]), |(current, prior)| (Some(current), prior));
    let mut context = json!({
        "profile": chain.profile.as_str(),
        "issuer": chain.root.issuer,
        "actor": current.map(actor_json),
        "caller_kind": caller_kind(caller.method),
    });
    if let Principal::Subject { subject, .. } = &chain.principal {
        context["principal"] = json!(subject);
    }
    if reader == Reader::TxnToken {
        context["depth"] = json!(prior.len());
        context["prior_actors"] = prior.iter().map(actor_json).collect();
    }
    context
}

/// What the caller the current actor was bound to is, so a policy can tell a
/// workload from an OAuth client with the same name.
const fn caller_kind(method: Method) -> &'static str {
    match method {
        Method::Bearer | Method::OAuthDpop => "client",
        Method::WitWpt | Method::WitHttpSig | Method::Mtls | Method::JwtSvid => "workload",
    }
}

fn actor_json(hop: &Hop) -> Value {
    match &hop.actor {
        ActorId::Subject { issuer, subject } => json!({ "iss": issuer, "sub": subject }),
        ActorId::Name(name) => json!({ "sub": name }),
        ActorId::Key(key) => json!({ "jkt": key.0 }),
        _ => Value::Null,
    }
}

/// The tool and its arguments the chain must authorize.
///
/// Two forms are accepted:
///
/// - A JSON-RPC `tools/call` object: `params.name` and the exact text of
///   `params.arguments` (an object, `{}` when absent).
/// - GET, HEAD, DELETE or OPTIONS with no body and no query string: the tool
///   `<METHOD> <path>` with no arguments.
///
/// Everything else is refused rather than guessed, because the chain would
/// otherwise be checked against less than the request carries: batches,
/// other JSON-RPC methods, bodies that are not UTF-8 JSON, malformed
/// `tools/call`, query strings, and a missing body on a method that carries
/// one.
fn invocation(input: &CheckInput) -> Option<(String, String)> {
    use serde_json::value::RawValue;

    #[derive(serde::Deserialize)]
    struct Call<'a> {
        method: String,
        #[serde(borrow, default)]
        params: Option<&'a RawValue>,
    }
    #[derive(serde::Deserialize)]
    struct Params<'a> {
        name: String,
        #[serde(borrow, default)]
        arguments: Option<&'a RawValue>,
    }

    let body = match input.body.as_deref() {
        // A body that is not UTF-8 is refused: decoding it lossily would check
        // different text from the bytes the upstream gets.
        Some(bytes) => Some(std::str::from_utf8(bytes).ok()?),
        None => None,
    };
    let Some(body) = body.filter(|b| !b.trim().is_empty()) else {
        let bodiless = matches!(input.method.as_str(), "GET" | "HEAD" | "DELETE" | "OPTIONS");
        if !bodiless || input.path.contains(['?', '#']) {
            return None;
        }
        return Some((format!("{} {}", input.method, input.path), "{}".to_owned()));
    };
    if !body.trim_start().starts_with('{') {
        return None;
    }
    let call: Call<'_> = serde_json::from_str(body).ok()?;
    if call.method != "tools/call" {
        return None;
    }
    let params: Params<'_> = serde_json::from_str(call.params?.get()).ok()?;
    let args = params.arguments.map_or("{}", RawValue::get);
    if !args.trim_start().starts_with('{') {
        return None;
    }
    Some((params.name, args.to_owned()))
}

fn rctx(input: &CheckInput) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("method".into(), json!(input.method));
    map.insert("resource".into(), json!(resource_id(input)));
    map
}

/// The request log entry for one decision: identifiers and outcomes only.
fn summary(
    input: &CheckInput,
    now: u64,
    id: &str,
    result: &Result<Allowed, Denied>,
) -> RequestSummary {
    let (trail, decision, status, code) = match result {
        Ok(allowed) => (&allowed.trail, Decision::Allow, 200, "ok"),
        Err(denied) => (&*denied.trail, Decision::Deny, denied.status, denied.code),
    };
    let known = |s: &str| (!s.is_empty()).then(|| bounded(s));
    RequestSummary {
        id: bounded(id),
        txn: known(&trail.txn),
        time: now,
        method: bounded(&input.method),
        resource: bounded(&resource_id(input)),
        caller: known(&trail.agent),
        auth_method: trail.method.map(method_name),
        principal: known(&trail.principal),
        decision,
        status,
        code: code.to_owned(),
        pdp: trail.pdp.clone(),
        chain: trail.chain.as_deref().cloned(),
    }
}

fn audit(input: &CheckInput, trail: &Trail, decision: &str, reason: &str, detail: &str) {
    tracing::info!(
        target: "visado::audit",
        txn = %trail.txn,
        agent = %trail.agent,
        principal = %trail.principal,
        resource = %resource_id(input),
        action = %input.method,
        decision,
        reason,
        detail,
    );
}
