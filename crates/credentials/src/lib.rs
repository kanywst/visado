//! Caller authentication for visado.
//!
//! These callers are recognised:
//!
//! - A workload presenting a WIMSE Workload Identity Token in the
//!   `Workload-Identity-Token` header and a Workload Proof Token in
//!   `Authorization: WPT`. An OAuth access token for the user it acts for may
//!   ride along in a separate header, and is used only if the WPT binds it
//!   through `oth`.
//! - A workload presenting a WIT and signing the request with its key, per
//!   draft-ietf-wimse-http-signature-08 (RFC 9421 `Signature-Input` and
//!   `Signature`). A user token in the separate header is used only if the
//!   signature covers it.
//! - A client presenting only an OAuth access token as `Authorization: Bearer`.
//!   The client is identified by `client_id` (or `azp`).
//! - A client presenting a DPoP-bound access token (`cnf.jkt`) as
//!   `Authorization: DPoP` with a `DPoP` proof (RFC 9449) for the request,
//!   made with the key the token is bound to. With
//!   [`Authenticator::with_dpop_nonces`], the proof must also carry a nonce
//!   this server issued (RFC 9449 §9).
//! - A workload presenting a SPIFFE JWT-SVID as `Authorization: Bearer`, told
//!   apart from an access token by a SPIFFE ID in `sub` and an `iss` that is
//!   not a configured OAuth issuer.
//! - A workload that presented no credential header but authenticated to the
//!   proxy with an X.509-SVID over mTLS. The proxy must be the TLS terminator
//!   and pass the certificate out of band (Envoy's `source.certificate`).
//!
//! Trust anchors come from configuration. Keys are never fetched from URLs in a
//! token.

mod error;
mod httpsig;
mod mtls;
mod oauth;
mod request;
mod svid;
mod wimse;

pub use error::AuthError;
pub use mtls::X509Bundle;
pub use oauth::{AccessToken, OAuthIssuer};
pub use request::RequestView;
pub use svid::JwtBundle;
pub use visado_chain::dpop::{MIN_NONCE_KEY_LEN as MIN_DPOP_NONCE_KEY_LEN, NonceError, Nonces};
pub use wimse::WitIssuer;

use visado_chain::dpop::{self as dpop_proof, Expected, HttpRequest, Rejection};
use visado_chain::replay::{MemoryReplayCache, Recorded, ReplayCache};

/// The default number of live proofs each replay cache holds.
pub const DEFAULT_REPLAY_CAPACITY: usize = 100_000;

/// The longest WPT `jti` or signature `nonce` accepted, in bytes.
pub const MAX_JTI_LEN: usize = 256;

/// The longest credential header value accepted, in bytes. Longer values are
/// rejected before they are decoded.
pub const MAX_CREDENTIAL_LEN: usize = 16 * 1024;

/// The RFC 9457 problem type for a signed request that failed, which
/// draft-ietf-wimse-http-signature asks a server to answer with status 400.
pub const PROBLEM_SIGNATURE_INVALID: &str = wimsey_httpsig::PROBLEM_SIGNATURE_INVALID;

/// The `Workload-Identity-Token` header, lowercased.
pub const WIT_HEADER: &str = "workload-identity-token";

/// The RFC 9449 `DPoP` header, lowercased.
pub const DPOP_HEADER: &str = "dpop";

/// The `alg` values a DPoP proof may use, for the `algs` parameter of a
/// `DPoP` challenge (RFC 9449 §7.1). Only asymmetric algorithms.
pub const DPOP_ALGS: &[&str] = &["ES256", "EdDSA", "Ed25519"];

/// How the caller proved its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// WIT with a WPT.
    WitWpt,
    /// WIT with an HTTP message signature.
    WitHttpSig,
    /// X.509-SVID over mTLS, terminated by the proxy.
    Mtls,
    /// SPIFFE JWT-SVID, a bearer token.
    JwtSvid,
    /// OAuth access token only.
    Bearer,
    /// OAuth access token bound to a key proven with a DPoP proof
    /// (RFC 9449).
    OAuthDpop,
}

/// The authenticated caller and, if present, the user it acts for.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// The caller's identifier: a workload identifier, or the OAuth client
    /// for [`Method::Bearer`] and [`Method::OAuthDpop`].
    pub caller: String,
    /// How the caller authenticated.
    pub method: Method,
    /// The user's access token, when one was presented and bound.
    pub user: Option<AccessToken>,
    /// The key the caller proved possession of for this request: the WIT
    /// `cnf` key for [`Method::WitWpt`] and [`Method::WitHttpSig`], the
    /// certificate's key for [`Method::Mtls`] when it is Ed25519 or P-256, the
    /// DPoP proof key for [`Method::OAuthDpop`], and `None` for the bearer
    /// methods [`Method::Bearer`] and [`Method::JwtSvid`].
    pub proof_key: Option<wimsey_jose::VerifyingKey>,
}

/// Verifies callers against configured trust anchors.
#[derive(Debug)]
pub struct Authenticator {
    wit_issuers: Vec<WitIssuer>,
    oauth_issuers: Vec<OAuthIssuer>,
    x509_bundles: Vec<X509Bundle>,
    jwt_bundles: Vec<JwtBundle>,
    jwt_audiences: Vec<String>,
    user_token_header: String,
    leeway: u64,
    max_wpt_lifetime: u64,
    max_signature_lifetime: u64,
    dpop_iat_window: u64,
    dpop_nonces: Option<Nonces>,
    replay_capacity: usize,
    replay_key_quota: Option<usize>,
    replay: Replay,
}

/// One replay cache per proof type, so a flood of one kind of proof cannot
/// refuse callers that use another.
#[derive(Debug)]
struct Replay {
    /// WPT `jti` values, per WIT `sub`.
    wpt: MemoryReplayCache,
    /// HTTP signature nonces, per WIT `sub`.
    signature: MemoryReplayCache,
    /// DPoP proof `jti` values, per proof key thumbprint.
    dpop: MemoryReplayCache,
}

impl Replay {
    fn new(capacity: usize, key_quota: usize) -> Self {
        let cache = || MemoryReplayCache::new(capacity).with_owner_quota(key_quota);
        Self {
            wpt: cache(),
            signature: cache(),
            dpop: cache(),
        }
    }
}

/// The share of a replay cache one key or workload may hold unless
/// configured: a quarter, so at least four of them are needed to fill it.
#[must_use]
pub const fn default_replay_key_quota(capacity: usize) -> usize {
    if capacity < 4 { capacity } else { capacity / 4 }
}

impl Authenticator {
    /// An authenticator that trusts nothing until issuers are added.
    #[must_use]
    pub fn new() -> Self {
        Self {
            wit_issuers: Vec::new(),
            oauth_issuers: Vec::new(),
            x509_bundles: Vec::new(),
            jwt_bundles: Vec::new(),
            jwt_audiences: Vec::new(),
            user_token_header: "x-user-token".into(),
            leeway: 30,
            max_wpt_lifetime: 60,
            max_signature_lifetime: 60,
            dpop_iat_window: 60,
            dpop_nonces: None,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            replay_key_quota: None,
            replay: Replay::new(
                DEFAULT_REPLAY_CAPACITY,
                default_replay_key_quota(DEFAULT_REPLAY_CAPACITY),
            ),
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

    /// Trusts X.509-SVIDs issued by the CA in `bundle`. Without any bundle the
    /// peer certificate is ignored.
    #[must_use]
    pub fn with_x509_bundle(mut self, bundle: X509Bundle) -> Self {
        self.x509_bundles.push(bundle);
        self
    }

    /// Trusts JWT-SVIDs signed with the keys in `bundle`.
    #[must_use]
    pub fn with_jwt_bundle(mut self, bundle: JwtBundle) -> Self {
        self.jwt_bundles.push(bundle);
        self
    }

    /// Accepts JWT-SVIDs whose `aud` contains `audience`. At least one is
    /// needed when a JWT bundle is configured.
    #[must_use]
    pub fn with_jwt_svid_audience(mut self, audience: impl Into<String>) -> Self {
        self.jwt_audiences.push(audience.into());
        self
    }

    /// The header that carries the user's access token next to a WPT.
    /// Default `x-user-token`.
    #[must_use]
    pub fn with_user_token_header(mut self, name: &str) -> Self {
        self.user_token_header = name.to_ascii_lowercase();
        self
    }

    /// The header that carries the user's access token next to a WPT,
    /// lowercased. Callers that forward requests must remove it.
    #[must_use]
    pub fn user_token_header(&self) -> &str {
        &self.user_token_header
    }

    /// Bounds the replay caches: at most `capacity` live proofs in each of
    /// the three (WPT `jti` values, HTTP signature nonces, DPoP proof `jti`
    /// values), a WPT living at most `max_wpt_lifetime` seconds. Defaults:
    /// [`DEFAULT_REPLAY_CAPACITY`] and 60. When a cache is full, new proofs of
    /// that type are rejected ([`AuthError::ReplayCacheFull`]).
    #[must_use]
    pub fn with_replay_limits(mut self, capacity: usize, max_wpt_lifetime: u64) -> Self {
        self.replay_capacity = capacity;
        self.max_wpt_lifetime = max_wpt_lifetime;
        self.rebuild_replay();
        self
    }

    /// The most live proofs one workload (by WIT `sub`) or one DPoP key may
    /// hold in each replay cache. Past it, that caller's new proofs are
    /// rejected ([`AuthError::ReplayQuota`]) while others still have room.
    /// Default: [`default_replay_key_quota`] of the capacity.
    #[must_use]
    pub fn with_replay_key_quota(mut self, quota: usize) -> Self {
        self.replay_key_quota = Some(quota);
        self.rebuild_replay();
        self
    }

    fn rebuild_replay(&mut self) {
        let quota = self
            .replay_key_quota
            .unwrap_or_else(|| default_replay_key_quota(self.replay_capacity));
        self.replay = Replay::new(self.replay_capacity, quota);
    }

    /// The longest window between an HTTP signature's `created` and
    /// `expires`, and the oldest `created` accepted, in seconds. Default 60.
    #[must_use]
    pub const fn with_signature_lifetime(mut self, seconds: u64) -> Self {
        self.max_signature_lifetime = seconds;
        self
    }

    /// How far a DPoP proof's `iat` may be from now, either way, in seconds.
    /// A proof's `jti` is remembered for that long after its `iat`. Default
    /// 60.
    #[must_use]
    pub const fn with_dpop_iat_window(mut self, seconds: u64) -> Self {
        self.dpop_iat_window = seconds;
        self
    }

    /// Requires every DPoP proof for an access token to carry a nonce
    /// `nonces` accepts (RFC 9449 §9). A proof that is valid except for its
    /// nonce fails with [`AuthError::DpopNonce`]; the caller answers with a
    /// fresh nonce from [`Authenticator::dpop_nonces`].
    #[must_use]
    pub fn with_dpop_nonces(mut self, nonces: Nonces) -> Self {
        self.dpop_nonces = Some(nonces);
        self
    }

    /// The nonces DPoP proofs must carry, when they are required.
    #[must_use]
    pub const fn dpop_nonces(&self) -> Option<&Nonces> {
        self.dpop_nonces.as_ref()
    }

    /// Checks that identifiers from different OAuth issuers cannot collide
    /// (with more than one issuer, each needs a subject prefix), and that
    /// JWT-SVIDs have an audience to be checked against.
    ///
    /// # Errors
    ///
    /// A description of the problem.
    pub fn check(&self) -> Result<(), String> {
        if !self.jwt_bundles.is_empty() && self.jwt_audiences.is_empty() {
            return Err("JWT-SVID bundles need at least one audience".into());
        }
        if self.oauth_issuers.len() > 1 && self.oauth_issuers.iter().any(|i| !i.has_prefix()) {
            return Err(
                "with more than one OAuth issuer, every issuer needs a subject_prefix".into(),
            );
        }
        Ok(())
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
        for name in [
            WIT_HEADER,
            "authorization",
            SIGNATURE_INPUT_HEADER,
            SIGNATURE_HEADER,
            DPOP_HEADER,
            self.user_token_header.as_str(),
        ] {
            if request
                .headers
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v.len())
                .sum::<usize>()
                > MAX_CREDENTIAL_LEN
            {
                return Err(AuthError::TooLarge);
            }
        }
        let wit = request.single(WIT_HEADER)?;
        let authorization = request.single("authorization")?;
        let signed = request
            .headers
            .iter()
            .any(|(n, _)| n == SIGNATURE_INPUT_HEADER);
        match (wit, authorization) {
            (Some(wit), Some(authorization)) if is_wpt(authorization) => {
                self.authenticate_wimse(request, wit, authorization, now)
            }
            // The user token goes in its own header, bound by the signature;
            // an Authorization header next to a signature would be ignored,
            // so it is refused instead.
            (Some(_), Some(_)) if signed => Err(AuthError::Ambiguous),
            (Some(wit), None) if signed => self.authenticate_signed(request, wit, now),
            (Some(_), _) => Err(AuthError::MissingProof),
            (None, Some(authorization)) if is_scheme(authorization, "dpop") => {
                self.authenticate_dpop(request, authorization, now)
            }
            (None, Some(authorization)) => self.authenticate_bearer(request, authorization, now),
            (None, None) => match request.peer_certificate {
                Some(certificate) if !self.x509_bundles.is_empty() => {
                    self.authenticate_mtls(request, certificate, now)
                }
                _ => Err(AuthError::MissingCredentials),
            },
        }
    }

    fn authenticate_mtls(
        &self,
        request: &RequestView<'_>,
        certificate: &str,
        now: u64,
    ) -> Result<Authenticated, AuthError> {
        // Nothing in a certificate can bind a user token to this request.
        if request.single(&self.user_token_header)?.is_some() {
            return Err(AuthError::UnboundUserToken);
        }
        let peer = mtls::verify(&self.x509_bundles, certificate, now)?;
        Ok(Authenticated {
            caller: peer.id,
            method: Method::Mtls,
            user: None,
            proof_key: peer.key,
        })
    }

    fn authenticate_signed(
        &self,
        request: &RequestView<'_>,
        wit: &str,
        now: u64,
    ) -> Result<Authenticated, AuthError> {
        // Every failure of the WIT or the signature is reported alike.
        let hide = |e: AuthError| match e {
            AuthError::ReplayCacheFull
            | AuthError::ReplayQuota
            | AuthError::Internal
            | AuthError::TooLarge
            | AuthError::HttpSig(_) => e,
            other => AuthError::HttpSig(other.to_string()),
        };
        let verified = wimse::verify_wit(&self.wit_issuers, wit, now, self.leeway).map_err(hide)?;
        let signature_input = joined(request, SIGNATURE_INPUT_HEADER);
        let signature = joined(request, SIGNATURE_HEADER)
            .ok_or_else(|| AuthError::HttpSig("no Signature header".into()))?;
        let policy = httpsig::Policy {
            now,
            leeway: self.leeway,
            max_lifetime: self.max_signature_lifetime,
            user_token_header: &self.user_token_header,
        };
        let signed = httpsig::verify(
            request,
            signature_input.as_deref().unwrap_or_default(),
            &signature,
            &verified.pop_key,
            &policy,
        )
        .map_err(hide)?;
        let (Some(nonce), Some(expires)) = (&signed.params.nonce, signed.params.expires) else {
            return Err(AuthError::HttpSig("nonce or expires missing".into()));
        };
        if nonce.len() > MAX_JTI_LEN {
            return Err(AuthError::HttpSig("nonce too long".into()));
        }

        let caller = verified.claims.sub.as_str();
        record(
            &self.replay.signature,
            caller,
            nonce,
            expires.saturating_add(self.leeway),
            now,
        )
        .map_err(|e| match e {
            AuthError::Replay => AuthError::HttpSig("nonce replayed".into()),
            other => other,
        })?;

        // Covered by the signature when present (checked above).
        let user = match request.single(&self.user_token_header)? {
            None => None,
            Some(token) => Some(oauth::verify(&self.oauth_issuers, token, now, self.leeway)?),
        };
        Ok(Authenticated {
            caller: caller.to_owned(),
            method: Method::WitHttpSig,
            user,
            proof_key: Some(verified.pop_key.clone()),
        })
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
        if wpt.claims.jti.len() > MAX_JTI_LEN {
            return Err(AuthError::Wpt("jti too long".into()));
        }

        let caller = verified.claims.sub.as_str();
        record(
            &self.replay.wpt,
            caller,
            &wpt.claims.jti,
            wpt.claims.exp.saturating_add(self.leeway),
            now,
        )?;

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
            caller: caller.to_owned(),
            method: Method::WitWpt,
            user,
            proof_key: Some(verified.pop_key.clone()),
        })
    }

    /// `Authorization: DPoP` with one `DPoP` proof, per RFC 9449 §4.3 and
    /// §7.1. The token must be bound to the proof key (`cnf.jkt`), the proof
    /// must carry a server nonce when nonces are required (§9), and the
    /// proof's `jti` is recorded for the proof key only once every check has
    /// passed.
    fn authenticate_dpop(
        &self,
        request: &RequestView<'_>,
        authorization: &str,
        now: u64,
    ) -> Result<Authenticated, AuthError> {
        let token = authorization
            .trim()
            .split_once(' ')
            .map(|(_, token)| token.trim())
            .filter(|token| !token.is_empty())
            .ok_or(AuthError::MissingCredentials)?;
        // Exactly one proof (RFC 9449 §4.3 item 1). A compact JWS has no
        // comma, so a comma means a proxy joined two header lines.
        let mut proofs = request.headers.iter().filter(|(n, _)| n == DPOP_HEADER);
        let proof = match (proofs.next(), proofs.next()) {
            (Some((_, proof)), None) if !proof.contains(',') => proof.trim(),
            (None, _) => return Err(AuthError::DpopProof("no DPoP header".into())),
            _ => return Err(AuthError::DpopProof("more than one DPoP proof".into())),
        };
        let (token_claims, binding) =
            oauth::verify_bound(&self.oauth_issuers, token, now, self.leeway)?;
        let oauth::Binding::Dpop(jkt) = binding else {
            return Err(AuthError::DpopBinding("token has no cnf.jkt".into()));
        };
        let now_i = i64::try_from(now).map_err(|_| AuthError::Internal)?;
        let window = i64::try_from(self.dpop_iat_window).unwrap_or(i64::MAX);
        let expected = Expected {
            jkt: &jkt,
            access_token: token,
            algs: DPOP_ALGS,
            max_size: MAX_CREDENTIAL_LEN,
            iat_window: window,
            nonces: self.dpop_nonces.as_ref(),
        };
        let uri = request.audience();
        let target = HttpRequest {
            method: request.method,
            uri: &uri,
        };
        let proof = dpop_proof::verify(proof, &expected, &target, now_i).map_err(|e| match e {
            Rejection::KeyMismatch => AuthError::DpopBinding(e.reason().into()),
            Rejection::Proof(reason) => AuthError::DpopProof(reason.into()),
            Rejection::Nonce(nonce) => AuthError::DpopNonce(nonce),
        })?;
        let caller = token_claims.client_id.clone().ok_or(AuthError::NoClient)?;
        let expires = u64::try_from(proof.iat.saturating_add(window)).unwrap_or(0);
        record(
            &self.replay.dpop,
            &jkt,
            &proof.jti,
            expires.saturating_add(self.leeway),
            now,
        )
        .map_err(|e| match e {
            AuthError::Replay => AuthError::DpopReplay,
            other => other,
        })?;
        Ok(Authenticated {
            caller,
            method: Method::OAuthDpop,
            user: Some(token_claims),
            proof_key: Some(proof.key.key),
        })
    }

    fn authenticate_bearer(
        &self,
        request: &RequestView<'_>,
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
        let token = token.trim();
        if !self.jwt_bundles.is_empty() {
            let issuers: Vec<&str> = self.oauth_issuers.iter().map(OAuthIssuer::issuer).collect();
            if svid::is_svid(token, &issuers) {
                // A bearer token cannot bind a user token to this request.
                if request.single(&self.user_token_header)?.is_some() {
                    return Err(AuthError::UnboundUserToken);
                }
                let caller = svid::verify(
                    &self.jwt_bundles,
                    &self.jwt_audiences,
                    token,
                    now,
                    self.leeway,
                )?;
                return Ok(Authenticated {
                    caller,
                    method: Method::JwtSvid,
                    user: None,
                    proof_key: None,
                });
            }
        }
        let token = oauth::verify(&self.oauth_issuers, token, now, self.leeway)?;
        let caller = token.client_id.clone().ok_or(AuthError::NoClient)?;
        Ok(Authenticated {
            caller,
            method: Method::Bearer,
            user: Some(token),
            proof_key: None,
        })
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

/// Records proof `id` of `owner` in `cache` until `until`, the last second at
/// which the proof could still be accepted.
fn record(
    cache: &MemoryReplayCache,
    owner: &str,
    id: &str,
    until: u64,
    now: u64,
) -> Result<(), AuthError> {
    let secs = |t: u64| i64::try_from(t).unwrap_or(i64::MAX);
    match cache.check_and_record(owner, id, secs(until), secs(now)) {
        Recorded::Fresh => Ok(()),
        Recorded::Replayed => Err(AuthError::Replay),
        Recorded::OverQuota => Err(AuthError::ReplayQuota),
        Recorded::Full => Err(AuthError::ReplayCacheFull),
    }
}

const fn visado_txn_header() -> &'static str {
    "txn-token"
}

/// The RFC 9421 `Signature-Input` header, lowercased.
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";

/// The RFC 9421 `Signature` header, lowercased.
pub const SIGNATURE_HEADER: &str = "signature";

/// Whether `authorization` uses the `WPT` scheme.
fn is_wpt(authorization: &str) -> bool {
    is_scheme(authorization, "wpt")
}

/// Whether `authorization` uses the auth scheme `scheme` (case-insensitive).
fn is_scheme(authorization: &str, scheme: &str) -> bool {
    authorization
        .trim_start()
        .split_once(' ')
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// The values of a list-valued header joined with `, `, as HTTP combines
/// repeated field lines. `None` when absent.
fn joined(request: &RequestView<'_>, name: &str) -> Option<String> {
    let values: Vec<&str> = request
        .headers
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.trim())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}
