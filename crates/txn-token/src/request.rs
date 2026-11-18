//! Parsing a token request to a Transaction Token Service (§11.1).

use serde_json::{Map, Value};

use crate::claims::Scope;
use crate::error::TxnTokenError;

/// `grant_type` for RFC 8693 token exchange.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// `requested_token_type` and `issued_token_type` for a Transaction Token.
pub const TOKEN_TYPE_TXN_TOKEN: &str = "urn:ietf:params:oauth:token-type:txn_token";
/// Subject token type for a self-signed JWT (§11.2.1).
pub const TOKEN_TYPE_SELF_SIGNED: &str = "urn:ietf:params:oauth:token-type:self_signed";
/// Subject token type for unsigned JSON (§11.2.2).
pub const TOKEN_TYPE_UNSIGNED_JSON: &str = "urn:ietf:params:oauth:token-type:unsigned_json";
/// The RFC 8693 refresh token type, which §11.2 excludes.
pub const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";

const NAMES: [&str; 8] = [
    "grant_type",
    "requested_token_type",
    "audience",
    "scope",
    "subject_token",
    "subject_token_type",
    "request_context",
    "request_details",
];

/// A validated Transaction Token request.
///
/// This checks the shape of the request only. Authenticating the client,
/// validating `subject_token` and deciding the scope are the service's job
/// (§11.3).
#[derive(Debug, Clone, PartialEq)]
pub struct TokenRequest {
    /// The trust domain the token is for.
    pub audience: String,
    /// The requested scope.
    pub scope: Scope,
    /// The subject token.
    pub subject_token: String,
    /// The subject token's type URN.
    pub subject_token_type: String,
    /// `request_context`, becoming `rctx`.
    pub request_context: Option<Map<String, Value>>,
    /// `request_details`, becoming `tctx`.
    pub request_details: Option<Map<String, Value>>,
}

impl TokenRequest {
    /// Parses decoded form parameters.
    ///
    /// # Errors
    ///
    /// [`TxnTokenError::InvalidRequest`] if a required parameter is missing or
    /// repeated, `grant_type` or `requested_token_type` is wrong, the subject is
    /// a refresh token, or `request_context` / `request_details` is not a JSON
    /// object.
    pub fn from_form<'a, I>(params: I) -> Result<Self, TxnTokenError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut fields: [Option<&str>; 8] = [None; 8];
        for (name, value) in params {
            if let Some(i) = NAMES.iter().position(|n| *n == name)
                && fields[i].replace(value).is_some()
            {
                return Err(TxnTokenError::InvalidRequest("repeated parameter"));
            }
        }
        let [
            grant_type,
            requested_token_type,
            audience,
            scope,
            subject_token,
            subject_token_type,
            request_context,
            request_details,
        ] = fields;

        if grant_type != Some(GRANT_TYPE_TOKEN_EXCHANGE) {
            return Err(TxnTokenError::InvalidRequest("unsupported grant_type"));
        }
        if requested_token_type != Some(TOKEN_TYPE_TXN_TOKEN) {
            return Err(TxnTokenError::InvalidRequest(
                "requested_token_type must be txn_token",
            ));
        }
        let audience = required(audience, "missing audience")?;
        let scope = Scope::parse(required(scope, "missing scope")?);
        if scope.is_empty() {
            return Err(TxnTokenError::InvalidRequest("missing scope"));
        }
        let subject_token = required(subject_token, "missing subject_token")?;
        let subject_token_type = required(subject_token_type, "missing subject_token_type")?;
        if subject_token_type == TOKEN_TYPE_REFRESH_TOKEN {
            return Err(TxnTokenError::InvalidRequest(
                "refresh tokens cannot be subject tokens",
            ));
        }
        Ok(Self {
            audience: audience.to_owned(),
            scope,
            subject_token: subject_token.to_owned(),
            subject_token_type: subject_token_type.to_owned(),
            request_context: json_object(request_context, "request_context is not a JSON object")?,
            request_details: json_object(request_details, "request_details is not a JSON object")?,
        })
    }
}

fn required<'a>(value: Option<&'a str>, error: &'static str) -> Result<&'a str, TxnTokenError> {
    value
        .filter(|v| !v.is_empty())
        .ok_or(TxnTokenError::InvalidRequest(error))
}

fn json_object(
    value: Option<&str>,
    error: &'static str,
) -> Result<Option<Map<String, Value>>, TxnTokenError> {
    match value {
        None => Ok(None),
        Some(raw) => match serde_json::from_str(raw) {
            Ok(Value::Object(map)) => Ok(Some(map)),
            _ => Err(TxnTokenError::InvalidRequest(error)),
        },
    }
}
