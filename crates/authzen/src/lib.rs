//! OpenID AuthZEN Authorization API 1.0 client.
//!
//! [`HttpPdp`] posts an [`EvaluationRequest`] to a PDP's access evaluation
//! endpoint and returns a [`Decision`]. Every failure is an error, never an
//! allow: a transport error, a non-200 status, a body without a boolean
//! `decision`, or an `X-Request-ID` echo that does not match.
//!
//! AuthZEN does not say how to describe an agent acting for someone else.
//! [`EvaluationRequest::for_agent`] uses this convention: `subject` is the
//! agent, and `context.principal` is who it acts for.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The largest PDP response body read, in bytes.
pub const MAX_RESPONSE_LEN: usize = 1024 * 1024;

/// A subject or resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Entity type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Entity identifier.
    pub id: String,
    /// Additional attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Map<String, Value>>,
}

impl Entity {
    /// An entity with no properties.
    #[must_use]
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            properties: None,
        }
    }
}

/// The action being requested.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    /// Action name.
    pub name: String,
    /// Additional attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Map<String, Value>>,
}

impl Action {
    /// An action with no properties.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            properties: None,
        }
    }
}

/// An access evaluation request (§6.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// Who is asking.
    pub subject: Entity,
    /// What is being accessed.
    pub resource: Entity,
    /// What is being done.
    pub action: Action,
    /// Environment and other context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

impl EvaluationRequest {
    /// A request where `agent` acts for `principal`.
    ///
    /// The agent is the subject (`type: "agent"`). The principal goes into
    /// `context.principal`, unless the agent acts for itself.
    #[must_use]
    pub fn for_agent(
        agent: impl Into<String>,
        principal: Option<Entity>,
        resource: Entity,
        action: Action,
    ) -> Self {
        let mut context = Map::new();
        if let Some(principal) = principal {
            context.insert(
                "principal".into(),
                serde_json::to_value(principal).unwrap_or(Value::Null),
            );
        }
        Self {
            subject: Entity::new("agent", agent),
            resource,
            action,
            context: if context.is_empty() {
                None
            } else {
                Some(context)
            },
        }
    }

    /// Adds a context member, replacing any member with the same name.
    #[must_use]
    pub fn with_context(mut self, name: impl Into<String>, value: Value) -> Self {
        self.context
            .get_or_insert_with(Map::new)
            .insert(name.into(), value);
        self
    }
}

/// The PDP's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// The response `context`, if the PDP sent one.
    pub context: Option<Map<String, Value>>,
}

/// Why no decision could be obtained. Callers must treat every variant as deny.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PdpError {
    /// The PDP could not be reached, or did not answer in time.
    #[error("pdp unavailable: {0}")]
    Unavailable(String),
    /// The PDP answered with a status other than 200.
    #[error("pdp returned status {0}")]
    Status(u16),
    /// The body is too large, not JSON, or has no boolean `decision`.
    #[error("pdp response is not a valid evaluation response")]
    InvalidResponse,
    /// The PDP echoed a different `X-Request-ID`.
    #[error("pdp echoed a different request id")]
    RequestIdMismatch,
}

impl PdpError {
    /// Stable error code for audit records.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "pdp.unavailable",
            Self::Status(_) => "pdp.status",
            Self::InvalidResponse => "pdp.invalid_response",
            Self::RequestIdMismatch => "pdp.request_id_mismatch",
        }
    }
}

/// A policy decision point.
pub trait Pdp: Send + Sync {
    /// Evaluates `request`. `request_id` is sent as `X-Request-ID`.
    fn evaluate(
        &self,
        request: &EvaluationRequest,
        request_id: &str,
    ) -> impl Future<Output = Result<Decision, PdpError>> + Send;
}

/// A PDP reached over HTTP.
#[derive(Clone)]
pub struct HttpPdp {
    client: reqwest::Client,
    endpoint: String,
    bearer: Option<String>,
}

impl std::fmt::Debug for HttpPdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPdp")
            .field("endpoint", &self.endpoint)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl HttpPdp {
    /// A client for the access evaluation endpoint at `endpoint`, with a
    /// per-request `timeout`.
    ///
    /// # Errors
    ///
    /// [`PdpError::Unavailable`] if the HTTP client cannot be built.
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Result<Self, PdpError> {
        let client = client_builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| PdpError::Unavailable(e.to_string()))?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            bearer: None,
        })
    }

    /// Authenticates to the PDP with a bearer token.
    #[must_use]
    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    /// The access evaluation endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Deserialize)]
struct EvaluationResponse {
    decision: Value,
    #[serde(default)]
    context: Option<Map<String, Value>>,
}

impl Pdp for HttpPdp {
    async fn evaluate(
        &self,
        request: &EvaluationRequest,
        request_id: &str,
    ) -> Result<Decision, PdpError> {
        let mut http = self
            .client
            .post(&self.endpoint)
            .header("X-Request-ID", request_id)
            .json(request);
        if let Some(token) = &self.bearer {
            http = http.bearer_auth(token);
        }
        let response = http
            .send()
            .await
            .map_err(|e| PdpError::Unavailable(e.to_string()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(PdpError::Status(response.status().as_u16()));
        }
        if let Some(echo) = response.headers().get("x-request-id")
            && echo.as_bytes() != request_id.as_bytes()
        {
            return Err(PdpError::RequestIdMismatch);
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_LEN as u64)
        {
            return Err(PdpError::InvalidResponse);
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| PdpError::Unavailable(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_LEN {
                return Err(PdpError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        parse_response(&body)
    }
}

/// Parses an evaluation response body. `decision` must be a JSON boolean.
///
/// # Errors
///
/// [`PdpError::InvalidResponse`] otherwise.
pub fn parse_response(body: &[u8]) -> Result<Decision, PdpError> {
    if body.len() > MAX_RESPONSE_LEN {
        return Err(PdpError::InvalidResponse);
    }
    let parsed: EvaluationResponse =
        serde_json::from_slice(body).map_err(|_| PdpError::InvalidResponse)?;
    let Value::Bool(allowed) = parsed.decision else {
        return Err(PdpError::InvalidResponse);
    };
    Ok(Decision {
        allowed,
        context: parsed.context,
    })
}

/// Reads `access_evaluation_endpoint` from a PDP's metadata document (§9).
///
/// As in RFC 8414, the well-known suffix goes between the host and the path of
/// the PDP identifier: `https://pdp.example/tenant` is described at
/// `https://pdp.example/.well-known/authzen-configuration/tenant`. The
/// document's `policy_decision_point` must equal `pdp` exactly.
///
/// # Errors
///
/// [`PdpError::Unavailable`] or [`PdpError::Status`] if the document cannot be
/// fetched, [`PdpError::InvalidResponse`] if `pdp` is not a URL, the document
/// lacks the endpoint, or it names a different `policy_decision_point`.
pub async fn discover(pdp: &str, timeout: Duration) -> Result<String, PdpError> {
    let metadata_url = metadata_url(pdp).ok_or(PdpError::InvalidResponse)?;
    let client = client_builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| PdpError::Unavailable(e.to_string()))?;
    let response = client
        .get(metadata_url)
        .send()
        .await
        .map_err(|e| PdpError::Unavailable(e.to_string()))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(PdpError::Status(response.status().as_u16()));
    }
    let metadata: Value = response
        .json()
        .await
        .map_err(|_| PdpError::InvalidResponse)?;
    if metadata["policy_decision_point"].as_str() != Some(pdp) {
        return Err(PdpError::InvalidResponse);
    }
    metadata["access_evaluation_endpoint"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(PdpError::InvalidResponse)
}

/// The metadata URL for a PDP identifier, or `None` if it is not an http(s)
/// URL without query or fragment.
#[must_use]
pub fn metadata_url(pdp: &str) -> Option<String> {
    let url = reqwest::Url::parse(pdp).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let path = url.path().trim_end_matches('/');
    let mut origin = url.origin().ascii_serialization();
    origin.push_str("/.well-known/authzen-configuration");
    origin.push_str(path);
    Some(origin)
}

fn client_builder() -> reqwest::ClientBuilder {
    // reqwest is built without a bundled crypto provider. Install ring as the
    // process default unless the application already chose one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decision_must_be_boolean() {
        assert!(parse_response(br#"{"decision":true}"#).unwrap().allowed);
        assert!(!parse_response(br#"{"decision":false}"#).unwrap().allowed);
        for body in [
            &br#"{"decision":"true"}"#[..],
            br#"{"decision":1}"#,
            br"{}",
            b"not json",
        ] {
            assert!(matches!(
                parse_response(body),
                Err(PdpError::InvalidResponse)
            ));
        }
    }

    #[test]
    fn metadata_url_inserts_the_suffix_before_the_path() {
        assert_eq!(
            metadata_url("https://pdp.example").as_deref(),
            Some("https://pdp.example/.well-known/authzen-configuration")
        );
        assert_eq!(
            metadata_url("https://pdp.example/tenant1").as_deref(),
            Some("https://pdp.example/.well-known/authzen-configuration/tenant1")
        );
        assert_eq!(metadata_url("https://pdp.example/?a=b"), None);
        assert_eq!(metadata_url("ftp://pdp.example"), None);
    }

    #[test]
    fn agent_profile_puts_principal_in_context() {
        let request = EvaluationRequest::for_agent(
            "spiffe://td.example/agent-b",
            Some(Entity::new("user", "alice")),
            Entity::new("tool", "send_email"),
            Action::new("call"),
        )
        .with_context("chain_depth", json!(2));
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["subject"]["type"], "agent");
        assert_eq!(value["context"]["principal"]["id"], "alice");
        assert_eq!(value["context"]["chain_depth"], 2);
    }
}
