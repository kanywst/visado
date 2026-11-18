//! Caller authentication for visado.
//!
//! Two kinds of caller are recognised:
//!
//! - A workload presenting a WIMSE Workload Identity Token in the
//!   `Workload-Identity-Token` header and a Workload Proof Token in
//!   `Authorization: WPT`. An OAuth access token for the user it acts for may
//!   ride along in a separate header, and is used only if the WPT binds it
//!   through `oth`.
//! - A client presenting only an OAuth access token as `Authorization: Bearer`.
//!   The client is identified by `client_id` (or `azp`).
//!
//! Trust anchors come from configuration. Keys are never fetched from URLs in a
//! token.

mod error;
mod oauth;
mod replay;
mod request;
mod wimse;

use std::sync::Mutex;

pub use error::AuthError;
pub use oauth::{AccessToken, OAuthIssuer};
pub use request::RequestView;
pub use wimse::WitIssuer;

use replay::ReplayCache;

/// The `Workload-Identity-Token` header, lowercased.
pub const WIT_HEADER: &str = "workload-identity-token";

/// How the caller proved its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// WIT with a WPT.
    WitWpt,
    /// OAuth access token only.
    Bearer,
}

/// The authenticated caller and, if present, the user it acts for.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// The caller's identifier: a workload identifier for [`Method::WitWpt`],
    /// the OAuth client for [`Method::Bearer`].
    pub caller: String,
    /// How the caller authenticated.
    pub method: Method,
    /// The user's access token, when one was presented and bound.
    pub user: Option<AccessToken>,
}

/// Verifies callers against configured trust anchors.
#[derive(Debug)]
pub struct Authenticator {
    wit_issuers: Vec<WitIssuer>,
    oauth_issuers: Vec<OAuthIssuer>,
    user_token_header: String,
    leeway: u64,
    max_wpt_lifetime: u64,
    replay: Mutex<ReplayCache>,
}

impl Authenticator {
    /// An authenticator that trusts nothing until issuers are added.
    #[must_use]
    pub fn new() -> Self {
        Self {
            wit_issuers: Vec::new(),
            oauth_issuers: Vec::new(),
            user_token_header: "x-user-token".into(),
            leeway: 30,
            max_wpt_lifetime: 300,
            replay: Mutex::new(ReplayCache::new(100_000)),
        }
    }

    /// Trusts WITs from `issuer`.
    #[must_use]
    pub fn with_wit_issuer(mut self, issuer: WitIssuer) -> Self {
        self.wit_issuers.push(issuer);
        self
    }

    /// Trusts access tokens from `issuer`.
    #[must_use]
    pub fn with_oauth_issuer(mut self, issuer: OAuthIssuer) -> Self {
        self.oauth_issuers.push(issuer);
        self
    }

    /// The header that carries the user's access token next to a WPT.
    /// Default `x-user-token`.
    #[must_use]
    pub fn with_user_token_header(mut self, name: &str) -> Self {
        self.user_token_header = name.to_ascii_lowercase();
        self
    }

    /// Clock-skew tolerance in seconds, at most 60. Default 30.
    #[must_use]
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = seconds.min(60);
        self
    }

    /// Authenticates the caller of `request` at `now`.
    ///
    /// # Errors
    ///
    /// The [`AuthError`] for the first check that failed.
    pub fn authenticate(
        &self,
        request: &RequestView<'_>,
        now: u64,
    ) -> Result<Authenticated, AuthError> {
        let wit = request.single(WIT_HEADER)?;
        let authorization = request.single("authorization")?;
        match (wit, authorization) {
            (Some(wit), Some(authorization)) => {
                self.authenticate_wimse(request, wit, authorization, now)
            }
            (None, Some(authorization)) => self.authenticate_bearer(authorization, now),
            (Some(_), None) => Err(AuthError::MissingProof),
            (None, None) => Err(AuthError::MissingCredentials),
        }
    }

    fn authenticate_wimse(
        &self,
        request: &RequestView<'_>,
        wit: &str,
        authorization: &str,
        now: u64,
    ) -> Result<Authenticated, AuthError> {
        let verified = wimse::verify_wit(&self.wit_issuers, wit, now, self.leeway)?;
        let proof = wimsey_wpt::scheme::from_credentials(authorization)
            .map_err(|_| AuthError::MissingProof)?;

        let audience = request.audience();
        let txn_token = request.single(visado_txn_header())?;
        let user_token = request.single(&self.user_token_header)?;
        let mut validation = wimsey_wpt::Validation::new(now, &audience, wit)
            .with_leeway(self.leeway)
            .with_max_lifetime(self.max_wpt_lifetime);
        if let Some(txn) = txn_token {
            validation = validation.with_txn_token(txn);
        }
        if let Some(token) = user_token {
            validation = validation.with_other_token(&self.user_token_header, token);
        }
        let wpt = wimsey_wpt::verify(proof, &verified.pop_key, &validation)
            .map_err(|e| AuthError::Wpt(e.to_string()))?;

        let fresh = self.replay.lock().map_err(|_| AuthError::Internal)?.insert(
            &wpt.claims.jti,
            wpt.claims.exp.saturating_add(self.leeway),
            now,
        );
        if !fresh {
            return Err(AuthError::Replay);
        }

        let user = match user_token {
            None => None,
            Some(token) => {
                let bound = wpt
                    .claims
                    .oth
                    .as_ref()
                    .is_some_and(|oth| oth.contains_key(&self.user_token_header));
                if !bound {
                    return Err(AuthError::UnboundUserToken);
                }
                Some(oauth::verify(&self.oauth_issuers, token, now, self.leeway)?)
            }
        };
        Ok(Authenticated {
            caller: verified.claims.sub.as_str().to_owned(),
            method: Method::WitWpt,
            user,
        })
    }

    fn authenticate_bearer(
        &self,
        authorization: &str,
        now: u64,
    ) -> Result<Authenticated, AuthError> {
        let (scheme, token) = authorization
            .trim()
            .split_once(' ')
            .ok_or(AuthError::MissingCredentials)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(AuthError::MissingCredentials);
        }
        let token = oauth::verify(&self.oauth_issuers, token.trim(), now, self.leeway)?;
        let caller = token.client_id.clone().ok_or(AuthError::NoClient)?;
        Ok(Authenticated {
            caller,
            method: Method::Bearer,
            user: Some(token),
        })
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

const fn visado_txn_header() -> &'static str {
    "txn-token"
}
