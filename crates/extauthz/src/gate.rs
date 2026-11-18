//! The decision pipeline, independent of the transport.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use tracing::Instrument;
use visado_authzen::{Action, Entity, EvaluationRequest, Pdp};
use visado_chain::NormalizedChain;
use visado_chain_aat::{Invocation, MemoryReplayCache, Presentation, Verifier, jwk_thumbprint};
use visado_credentials::{AuthError, Authenticated, Authenticator, Method, RequestView};
use visado_txn_token::{KeySet, Scope, TxnTokenClaims, Validation, mint, verify};
use wimsey_jose::SigningKey;

/// The header carrying an AAT chain, root first, comma-separated.
pub const AAT_CHAIN_HEADER: &str = "aat-chain";
/// The header carrying the AAT proof of possession.
pub const AAT_POP_HEADER: &str = "aat-pop";

/// Headers always removed before the request goes upstream, in addition to the
/// authenticator's user token header. The upstream gets the Transaction Token
/// instead (MCP and the Txn-Token draft both forbid forwarding the inbound
/// access token).
pub const STRIPPED_HEADERS: [&str; 2] = ["authorization", "workload-identity-token"];

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
    /// Deny requests that carry no AAT chain.
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
    /// The request body, when the proxy sends it.
    pub body: Option<String>,
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
}

impl<P: Pdp> Gate<P> {
    /// A gate. Inbound Transaction Tokens are verified with the gate's own key.
    pub fn new(config: GateConfig, authenticator: Authenticator, pdp: P) -> Self {
        let txn_keys =
            KeySet::new().with_key(config.kid.clone(), config.signing_key.verifying_key());
        let mut stripped: Vec<String> = STRIPPED_HEADERS.iter().map(|h| (*h).to_owned()).collect();
        stripped.extend([AAT_CHAIN_HEADER.to_owned(), AAT_POP_HEADER.to_owned()]);
        stripped.push(authenticator.user_token_header().to_owned());
        Self {
            config,
            authenticator,
            pdp,
            txn_keys,
            stripped,
            aat_replay: MemoryReplayCache::new(100_000),
        }
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
            Err(denied) => (&denied.trail, "deny", denied.code),
        };
        span.record("visado.txn", trail.txn.as_str());
        span.record("visado.agent", trail.agent.as_str());
        span.record("visado.principal", trail.principal.as_str());
        span.record("visado.decision", decision);
        span.record("visado.reason", reason);
        match result {
            Ok(allowed) => {
                audit(input, &allowed.trail, "allow", "ok");
                Outcome::Allow {
                    txn: allowed.trail.txn,
                    set: vec![("txn-token".into(), allowed.token)],
                    remove: self.stripped.clone(),
                }
            }
            Err(denied) => {
                audit(input, &denied.trail, "deny", denied.code);
                Outcome::Deny {
                    status: denied.status,
                    code: denied.code.to_owned(),
                    challenge: denied.challenge.map(ToOwned::to_owned),
                }
            }
        }
    }

    async fn decide(&self, input: &CheckInput, now: u64, txn: &str) -> Result<Allowed, Denied> {
        let mut trail = Trail::default();
        self.check_target(input)?;
        let caller = self.authenticate(input, now)?;
        trail.agent.clone_from(&caller.caller);
        let chain = self.verify_chain(input, &caller, now, &trail)?;

        let inbound = input
            .headers
            .iter()
            .find(|(n, _)| n == "txn-token")
            .map(|(_, v)| v.as_str());
        let forwarded = match inbound {
            Some(token) => Some(self.accept_forwarded(&caller, token, now, &trail)?),
            None => None,
        };
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
            request = request.with_context("chain", chain_context(chain));
        }
        match self.pdp.evaluate(&request, &trail.txn).await {
            Ok(decision) if decision.allowed => {}
            Ok(_) => return Err(Denied::new(403, "pdp.deny", &trail)),
            Err(e) => return Err(Denied::new(403, e.code(), &trail)),
        }

        let token = if let (Some(_), Some(token)) = (forwarded, inbound) {
            token.to_owned()
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

    /// Verifies an AAT chain if the request carries one (see docs/bindings.md).
    /// With a WIT, the chain's holder must be the workload that proved
    /// possession of the WIT key.
    fn verify_chain(
        &self,
        input: &CheckInput,
        caller: &Authenticated,
        now: u64,
        trail: &Trail,
    ) -> Result<Option<NormalizedChain>, Denied> {
        let header = |name: &str| {
            input
                .headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let Some(chain_header) = header(AAT_CHAIN_HEADER) else {
            if self.config.require_chain {
                return Err(Denied::new(403, "chain.required", trail));
            }
            return Ok(None);
        };
        let Some(verifier) = &self.config.aat else {
            return Err(Denied::new(403, "chain.unsupported", trail));
        };
        // The chain must belong to the caller. Only a WIT caller has proved
        // possession of a key that can be compared with the chain's holder, so
        // a bearer-only caller cannot present a chain.
        let Some(key) = &caller.proof_key else {
            return Err(Denied::new(403, "chain.unbound_caller", trail));
        };
        let pop =
            header(AAT_POP_HEADER).ok_or_else(|| Denied::new(401, "chain.missing_pop", trail))?;
        let chain: Vec<String> = chain_header
            .split(',')
            .map(|t| t.trim().to_owned())
            .collect();
        let (tool, args) =
            invocation(input).ok_or_else(|| Denied::new(400, "chain.bad_invocation", trail))?;
        let now = i64::try_from(now).map_err(|_| Denied::new(500, "internal.clock", trail))?;
        let authorized = verifier
            .verify(
                &Presentation { chain: &chain, pop },
                &Invocation {
                    tool: &tool,
                    args_json: &args,
                },
                now,
                Some(&self.aat_replay),
            )
            .map_err(|e| Denied::new(403, e.code(), trail))?;
        let holder = authorized
            .chain
            .leaf()
            .and_then(|leaf| leaf.cnf.as_ref())
            .map(|c| c.thumbprint.0.as_str());
        if holder != Some(jwk_thumbprint(key).as_str()) {
            return Err(Denied::new(403, "chain.holder_mismatch", trail));
        }
        Ok(Some(authorized.chain))
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
            scheme: &input.scheme,
            authority: &input.authority,
            path: &input.path,
            headers: &input.headers,
        };
        self.authenticator.authenticate(&view, now).map_err(|e| {
            let wimse = input
                .headers
                .iter()
                .any(|(n, _)| n == "workload-identity-token");
            let status = if matches!(e, AuthError::ReplayCacheFull) {
                503
            } else {
                401
            };
            let mut denied = Denied::new(status, e.code(), &Trail::default());
            denied.challenge = Some(if wimse { "WPT" } else { "Bearer" });
            denied
        })
    }

    /// An inbound Transaction Token is accepted only from a configured internal
    /// workload, and only if it verifies against this gate's key and domain.
    fn accept_forwarded(
        &self,
        caller: &Authenticated,
        token: &str,
        now: u64,
        trail: &Trail,
    ) -> Result<TxnTokenClaims, Denied> {
        if caller.method != Method::WitWpt || !self.config.internal_callers.contains(&caller.caller)
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

/// What is known about the request so far, for the audit event.
#[derive(Debug, Default, Clone)]
struct Trail {
    agent: String,
    principal: String,
    txn: String,
}

struct Allowed {
    token: String,
    trail: Trail,
}

struct Denied {
    status: u16,
    code: &'static str,
    challenge: Option<&'static str>,
    trail: Trail,
}

impl Denied {
    fn new(status: u16, code: &'static str, trail: &Trail) -> Self {
        Self {
            status,
            code,
            challenge: None,
            trail: trail.clone(),
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

/// `req_wl` for the token. Bearer callers are OAuth clients, not workloads,
/// so they are marked to keep them apart from workload identifiers.
fn requesting_workload(caller: &Authenticated) -> String {
    match caller.method {
        Method::WitWpt => caller.caller.clone(),
        Method::Bearer => format!("oauth-client:{}", caller.caller),
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
    if caller.method == Method::Bearer {
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
        Method::Bearer => "bearer",
    }
}

fn tctx(caller: &Authenticated, chain: Option<&NormalizedChain>) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("agent".into(), json!(caller.caller));
    map.insert("auth_method".into(), json!(method_name(caller.method)));
    if let Some(chain) = chain {
        map.insert("chain".into(), chain_context(chain));
    }
    map
}

/// The chain as the PDP and the Transaction Token see it: format, depth, the
/// holders from root to leaf, and the leaf's authority.
fn chain_context(chain: &NormalizedChain) -> Value {
    let holders: Vec<String> = chain
        .hops
        .iter()
        .filter_map(|hop| hop.cnf.as_ref().map(|c| c.thumbprint.0.clone()))
        .collect();
    json!({
        "profile": chain.profile.as_str(),
        "issuer": chain.root.issuer,
        "depth": chain.hops.len().saturating_sub(1),
        "holders": holders,
        "authority": chain.leaf().map(|leaf| leaf.authority.json.clone()),
    })
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
/// other JSON-RPC methods, bodies that are not JSON, malformed `tools/call`,
/// query strings, and a missing body on a method that carries one.
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

    let Some(body) = input.body.as_deref().filter(|b| !b.trim().is_empty()) else {
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

fn audit(input: &CheckInput, trail: &Trail, decision: &str, reason: &str) {
    tracing::info!(
        target: "visado::audit",
        txn = %trail.txn,
        agent = %trail.agent,
        principal = %trail.principal,
        resource = %resource_id(input),
        action = %input.method,
        decision,
        reason,
    );
}
