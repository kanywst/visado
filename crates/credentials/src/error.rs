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
            Self::UnboundUserToken => "credential.unbound_user_token",
            Self::UntrustedIssuer => "token.untrusted_issuer",
            Self::AccessToken(_) => "token.invalid",
            Self::Expired => "token.expired",
            Self::NoClient => "token.no_client",
            Self::Internal => "internal",
        }
    }
}
