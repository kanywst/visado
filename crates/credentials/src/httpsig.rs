//! WIT with an RFC 9421 HTTP Message Signature, per
//! draft-ietf-wimse-http-signature-08.

use wimsey_httpsig::{Component, HttpRequest, VerifiedSignature, VerifyConfig};
use wimsey_jose::VerifyingKey;

use crate::error::AuthError;
use crate::request::RequestView;

/// The header Envoy adds to the check request when it sent only part of the
/// body (`allow_partial_message`).
pub(crate) const PARTIAL_BODY_HEADER: &str = "x-envoy-auth-partial-body";

/// What the signature check needs besides the request and the key.
pub(crate) struct Policy<'a> {
    pub(crate) now: u64,
    pub(crate) leeway: u64,
    pub(crate) max_lifetime: u64,
    /// A header whose presence makes it a required covered component.
    pub(crate) user_token_header: &'a str,
}

/// The request as RFC 9421 sees it. Pseudo-headers are left out: they are not
/// header fields, and their values are the derived components.
pub(crate) fn message(request: &RequestView<'_>) -> HttpRequest {
    let target = request.path.split('#').next().unwrap_or("");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_owned())),
        None => (target, None),
    };
    HttpRequest {
        method: request.method.to_owned(),
        authority: request.authority.to_owned(),
        path: path.to_owned(),
        query,
        headers: request
            .headers
            .iter()
            .filter(|(name, _)| !name.starts_with(':'))
            .cloned()
            .collect(),
    }
}

/// Verifies the WIMSE signature on `request` with the WIT's `cnf` key.
///
/// Checks the draft's profile (`created`, `expires`, `nonce`, `tag` and
/// `wimse-aud` present, no `keyid` or `alg`), that every component the profile
/// requires is covered (plus the user token header when present), the
/// signature, the audience, the time window, and the body against a covered
/// `Content-Digest`. Replay of the nonce is the caller's.
pub(crate) fn verify(
    request: &RequestView<'_>,
    signature_input: &str,
    signature: &str,
    key: &VerifyingKey,
    policy: &Policy<'_>,
) -> Result<VerifiedSignature, AuthError> {
    let invalid = |e: wimsey_httpsig::HttpSigError| AuthError::HttpSig(e.to_string());
    let message = message(request);
    let mut required = wimsey_httpsig::request_components(&message);
    if request.single(policy.user_token_header)?.is_some() {
        required.push(Component::header(policy.user_token_header));
    }
    let config = VerifyConfig {
        now: Some(policy.now),
        leeway: policy.leeway,
        required_components: required,
        max_age: Some(policy.max_lifetime.saturating_add(policy.leeway)),
        wimse_profile: true,
        expected_audiences: vec![request.audience()],
        ..VerifyConfig::default()
    };
    let verified = wimsey_httpsig::verify(&message, signature_input, signature, key, &config)
        .map_err(invalid)?;

    // The profile makes both present; bound the window the replay cache has
    // to cover.
    let (Some(created), Some(expires)) = (verified.params.created, verified.params.expires) else {
        return Err(AuthError::HttpSig("created or expires missing".into()));
    };
    if expires.saturating_sub(created) > policy.max_lifetime {
        return Err(AuthError::HttpSig("lifetime too long".into()));
    }

    // A request with a body must cover Content-Digest, or the body could be
    // swapped under a valid signature. The body counts as present when Envoy
    // sent one or Content-Length says there is one.
    let covers_digest = verified
        .components
        .contains(&Component::header("content-digest"));
    let has_body = request.body.is_some_and(|b| !b.is_empty())
        || request.headers.iter().any(|(n, v)| {
            n == "content-length" && v.trim().parse::<u64>().map_or(true, |len| len > 0)
        });
    if has_body && !covers_digest {
        return Err(AuthError::HttpSig(
            "a request with a body must cover content-digest".into(),
        ));
    }

    // Covering Content-Digest protects only the header string. The body it
    // names must be the body received; a body Envoy did not send counts as
    // empty, so a non-empty signed body fails closed.
    if covers_digest {
        if request
            .headers
            .iter()
            .any(|(n, v)| n == PARTIAL_BODY_HEADER && !v.trim().eq_ignore_ascii_case("false"))
        {
            return Err(AuthError::HttpSig("partial body".into()));
        }
        let digest = message
            .component_value(&Component::header("content-digest"))
            .map_err(invalid)?;
        if !wimsey_httpsig::verify_content_digest(&digest, request.body.unwrap_or_default()) {
            return Err(AuthError::HttpSig(
                "content-digest does not match the body".into(),
            ));
        }
    }
    Ok(verified)
}
