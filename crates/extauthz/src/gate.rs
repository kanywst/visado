//! The decision pipeline, independent of the transport.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use visado_authzen::{Action, Entity, EvaluationRequest, Pdp};
use visado_credentials::{Authenticated, Authenticator, Method, RequestView};
use visado_txn_token::{KeySet, Scope, TxnTokenClaims, Validation, mint, verify};
use wimsey_jose::SigningKey;

/// Headers removed before the request goes upstream. The upstream gets the
/// Transaction Token instead (MCP and the Txn-Token draft both forbid
/// forwarding the inbound access token).
pub const STRIPPED_HEADERS: [&str; 3] =
    ["authorization", "workload-identity-token", "x-user-token"];

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
    /// Scope used when the caller presents no access token.
    pub default_scope: Scope,
    /// Callers allowed to forward a Transaction Token from an earlier hop.
    /// Anyone else's inbound `Txn-Token` is rejected.
    pub internal_callers: BTreeSet<String>,
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
}

impl<P: Pdp> Gate<P> {
    /// A gate. Inbound Transaction Tokens are verified with the gate's own key.
    pub fn new(config: GateConfig, authenticator: Authenticator, pdp: P) -> Self {
        let txn_keys =
            KeySet::new().with_key(config.kid.clone(), config.signing_key.verifying_key());
        Self {
            config,
            authenticator,
            pdp,
            txn_keys,
        }
    }

    /// Decides on `input` at `now`. `txn` is the identifier used if a new
    /// Transaction Token is minted.
    pub async fn check(&self, input: &CheckInput, now: u64, txn: &str) -> Outcome {
        let view = RequestView {
            scheme: &input.scheme,
            authority: &input.authority,
            path: &input.path,
            headers: &input.headers,
        };
        let caller = match self.authenticator.authenticate(&view, now) {
            Ok(caller) => caller,
            Err(e) => {
                let challenge = if input
                    .headers
                    .iter()
                    .any(|(n, _)| n == "workload-identity-token")
                {
                    "WPT"
                } else {
                    "Bearer"
                };
                return deny(input, None, 401, e.code(), Some(challenge));
            }
        };

        let inbound = input
            .headers
            .iter()
            .find(|(n, _)| n == "txn-token")
            .map(|(_, v)| v.as_str());
        let context = match inbound {
            Some(token) => {
                if !self.config.internal_callers.contains(&caller.caller) {
                    return deny(input, Some(&caller), 403, "txn.untrusted_hop", None);
                }
                let validation = Validation::new(&self.config.trust_domain, now);
                match verify(token, &self.txn_keys, &validation) {
                    Ok(verified) => Context::Forwarded(Box::new(verified.claims)),
                    Err(e) => return deny(input, Some(&caller), 403, e.code(), None),
                }
            }
            None => Context::Fresh,
        };

        let (principal, scope, txn_id) = match &context {
            Context::Forwarded(claims) => {
                (claims.sub.clone(), claims.scope.clone(), claims.txn.clone())
            }
            Context::Fresh => {
                let principal = caller
                    .user
                    .as_ref()
                    .map_or_else(|| caller.caller.clone(), |u| u.subject.clone());
                let scope = caller
                    .user
                    .as_ref()
                    .and_then(|u| u.scope.as_deref())
                    .map_or_else(|| self.config.default_scope.clone(), Scope::parse);
                (principal, scope, txn.to_owned())
            }
        };

        let request = evaluation_request(input, &caller, &principal, &scope, &txn_id);
        match self.pdp.evaluate(&request, &txn_id).await {
            Ok(decision) if decision.allowed => {}
            Ok(_) => return deny(input, Some(&caller), 403, "pdp.deny", None),
            Err(e) => return deny(input, Some(&caller), 403, e.code(), None),
        }

        let token = match context {
            Context::Forwarded(_) => inbound.unwrap_or_default().to_owned(),
            Context::Fresh => {
                let claims = TxnTokenClaims {
                    iss: None,
                    iat: now,
                    aud: self.config.trust_domain.clone(),
                    exp: now + self.config.txn_lifetime,
                    txn: txn_id.clone(),
                    sub: principal.clone(),
                    scope,
                    req_wl: caller.caller.clone(),
                    tctx: Some(tctx(&caller)),
                    rctx: Some(rctx(input)),
                };
                match mint(&claims, Some(&self.config.kid), &self.config.signing_key) {
                    Ok(token) => token,
                    Err(e) => return deny(input, Some(&caller), 403, e.code(), None),
                }
            }
        };

        audit(input, Some(&caller), &principal, &txn_id, "allow", "ok");
        Outcome::Allow {
            txn: txn_id,
            set: vec![("txn-token".into(), token)],
            remove: STRIPPED_HEADERS.iter().map(|h| (*h).to_owned()).collect(),
        }
    }
}

fn deny(
    input: &CheckInput,
    caller: Option<&Authenticated>,
    status: u16,
    code: &str,
    challenge: Option<&str>,
) -> Outcome {
    audit(input, caller, "", "", "deny", code);
    Outcome::Deny {
        status,
        code: code.to_owned(),
        challenge: challenge.map(ToOwned::to_owned),
    }
}

enum Context {
    Fresh,
    Forwarded(Box<TxnTokenClaims>),
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
    EvaluationRequest::for_agent(
        caller.caller.clone(),
        principal,
        Entity::new("http_resource", resource_id(input)),
        Action::new(input.method.clone()),
    )
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

fn tctx(caller: &Authenticated) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("agent".into(), json!(caller.caller));
    map.insert("auth_method".into(), json!(method_name(caller.method)));
    map
}

fn rctx(input: &CheckInput) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("method".into(), json!(input.method));
    map.insert("resource".into(), json!(resource_id(input)));
    map
}

fn audit(
    input: &CheckInput,
    caller: Option<&Authenticated>,
    principal: &str,
    txn: &str,
    decision: &str,
    reason: &str,
) {
    tracing::info!(
        target: "visado::audit",
        txn,
        agent = caller.map_or("", |c| c.caller.as_str()),
        principal,
        resource = %resource_id(input),
        action = %input.method,
        decision,
        reason,
    );
}
