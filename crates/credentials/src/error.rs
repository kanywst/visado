/// Why a caller was not authenticated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Neither a WIT nor an access token was presented.
    #[error("no credentials")]
    MissingCredentials,
    /// A WIT was presented without a usable `Authorization: WPT` proof.
    #[error("missing proof of possession")]
    MissingProof,
    /// A header that must appear at most once appeared more than once.
    #[error("header `{0}` repeated")]
    RepeatedHeader(String),
    /// The WIT names a trust domain with no configured issuer.
    #[error("untrusted trust domain")]
    UntrustedDomain,
    /// The WIT did not verify.
    #[error("invalid WIT: {0}")]
    Wit(String),
    /// The WPT did not verify.
    #[error("invalid WPT: {0}")]
    Wpt(String),
    /// The WPT's `jti` was already used.
    #[error("proof replayed")]
    Replay,
    /// The replay cache is full, so the proof cannot be recorded.
    #[error("replay cache full")]
    ReplayCacheFull,
    /// A user token was sent but the WPT does not bind it.
    #[error("user token not bound by the proof")]
    UnboundUserToken,
    /// The access token's issuer is not configured.
    #[error("untrusted token issuer")]
    UntrustedIssuer,
    /// The access token did not verify.
    #[error("invalid access token: {0}")]
    AccessToken(String),
    /// The access token has expired.
    #[error("access token expired")]
    Expired,
    /// The access token is sender-constrained by a `cnf` other than a lone
    /// `jkt` (such as an mTLS `x5t#S256`), which is not supported.
    #[error("sender-constrained access tokens are not supported")]
    SenderConstrained,
    /// A DPoP-bound access token (`cnf.jkt`) was presented without its
    /// proof: as `Authorization: Bearer` or as a user token (RFC 9449 §7.1).
    #[error("DPoP-bound access token presented without a DPoP proof")]
    DpopBound,
    /// The `DPoP` proof is missing, repeated or invalid (RFC 9449
    /// `invalid_dpop_proof`).
    #[error("invalid DPoP proof: {0}")]
    DpopProof(String),
    /// The DPoP proof is valid but lacks a nonce this server issued, when
    /// nonces are required (RFC 9449 §9 `use_dpop_nonce`).
    #[error("{}", .0.reason())]
    DpopNonce(visado_chain::dpop::NonceError),
    /// The DPoP proof's `jti` was already accepted for this key.
    #[error("DPoP proof replayed")]
    DpopReplay,
    /// The access token sent with `Authorization: DPoP` is not bound to the
    /// proof key: it has no `cnf.jkt`, or the proof was made with another
    /// key (RFC 9449 `invalid_token`).
    #[error("access token not bound to the DPoP key: {0}")]
    DpopBinding(String),
    /// A WIT with an HTTP message signature did not verify: the WIT, the
    /// signature, its profile, its time window, the body digest or a replayed
    /// nonce. One code for all of them, because draft-ietf-wimse-http-signature
    /// forbids telling the peer which check failed; the detail is for the
    /// audit record.
    #[error("invalid signed request: {0}")]
    HttpSig(String),
    /// The peer certificate did not verify.
    #[error("invalid peer certificate: {0}")]
    Certificate(String),
    /// The peer certificate names a trust domain with no configured CA.
    #[error("untrusted certificate trust domain")]
    CertificateUntrustedDomain,
    /// The JWT-SVID did not verify.
    #[error("invalid JWT-SVID: {0}")]
    JwtSvid(String),
    /// The JWT-SVID names a trust domain with no configured bundle.
    #[error("untrusted JWT-SVID trust domain")]
    JwtSvidUntrustedDomain,
    /// The request carries credentials for more than one method, or a header
    /// the chosen method does not use.
    #[error("ambiguous credentials")]
    Ambiguous,
    /// A credential is longer than [`crate::MAX_CREDENTIAL_LEN`].
    #[error("credential too large")]
    TooLarge,
    /// A bearer-only caller's token names no client.
    #[error("access token names no client")]
    NoClient,
    /// An internal error, such as a poisoned lock.
    #[error("internal error")]
    Internal,
}

impl AuthError {
    /// Stable error code for responses and audit records.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingCredentials => "credential.missing",
            Self::MissingProof => "wpt.missing",
            Self::RepeatedHeader(_) => "credential.repeated_header",
            Self::UntrustedDomain => "wit.untrusted_domain",
            Self::Wit(_) => "wit.invalid",
            Self::Wpt(_) => "wpt.invalid",
            Self::Replay => "wpt.replay",
            Self::ReplayCacheFull => "wpt.replay_cache_full",
            Self::UnboundUserToken => "credential.unbound_user_token",
            Self::UntrustedIssuer => "token.untrusted_issuer",
            Self::AccessToken(_) => "token.invalid",
            Self::Expired => "token.expired",
            Self::SenderConstrained => "token.sender_constrained",
            Self::DpopBound => "token.dpop_bound",
            Self::DpopProof(_) => "dpop.invalid",
            Self::DpopNonce(e) => e.code(),
            Self::DpopReplay => "dpop.replay",
            Self::DpopBinding(_) => "dpop.binding",
            Self::NoClient => "token.no_client",
            Self::HttpSig(_) => "httpsig.invalid",
            Self::Ambiguous => "credential.ambiguous",
            Self::Certificate(_) => "mtls.invalid",
            Self::CertificateUntrustedDomain => "mtls.untrusted_domain",
            Self::JwtSvid(_) => "jwt_svid.invalid",
            Self::JwtSvidUntrustedDomain => "jwt_svid.untrusted_domain",
            Self::TooLarge => "credential.too_large",
            Self::Internal => "internal",
        }
    }
}
