//! Envoy ext_authz v3 over gRPC.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use envoy_types::pb::google::protobuf::value::Kind;
use envoy_types::pb::google::protobuf::{Struct, Value as ProtoValue};
use tonic::{Request, Response, Status};
use visado_authzen::Pdp;

use crate::gate::{CheckInput, Gate, Outcome};

/// The ext_authz service. Serve it with
/// `envoy_types::ext_authz::v3::pb::AuthorizationServer::new(ExtAuthz::new(gate))`.
#[derive(Debug)]
pub struct ExtAuthz<P> {
    gate: Arc<Gate<P>>,
}

impl<P> ExtAuthz<P> {
    /// Wraps `gate`.
    pub fn new(gate: Gate<P>) -> Self {
        Self {
            gate: Arc::new(gate),
        }
    }
}

fn input_from(request: &CheckRequest) -> Option<CheckInput> {
    let http = request
        .attributes
        .as_ref()?
        .request
        .as_ref()?
        .http
        .as_ref()?;
    // With `encode_raw_headers`, Envoy sends `header_map` and leaves `headers`
    // empty. `header_map` also keeps repeated headers apart instead of joining
    // them with commas, so prefer it when present.
    let mut headers: Vec<(String, String)> = match &http.header_map {
        Some(map) if !map.headers.is_empty() => map
            .headers
            .iter()
            .map(|h| {
                let value = if h.raw_value.is_empty() {
                    h.value.clone()
                } else {
                    String::from_utf8_lossy(&h.raw_value).into_owned()
                };
                (h.key.to_ascii_lowercase(), value)
            })
            .collect(),
        _ => http
            .headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect(),
    };
    headers.sort();
    Some(CheckInput {
        method: http.method.clone(),
        scheme: http.scheme.clone(),
        authority: http.host.clone(),
        path: http.path.clone(),
        headers,
        body: if !http.body.is_empty() {
            Some(http.body.clone())
        } else if !http.raw_body.is_empty() {
            // A body that is not UTF-8 is replaced by a marker that is not
            // JSON, so a chain check denies it. Lossy decoding would let the
            // gate check different text from the bytes the upstream gets.
            Some(
                String::from_utf8(http.raw_body.clone())
                    .unwrap_or_else(|_| UNREADABLE_BODY.to_owned()),
            )
        } else {
            None
        },
    })
}

/// Stands in for a body that is not UTF-8.
const UNREADABLE_BODY: &str = "\u{FFFD}unreadable body";

fn denied_response(status: u16, code: &str, challenge: Option<&str>) -> CheckResponse {
    let mut denied = DeniedHttpResponseBuilder::new();
    denied
        .set_http_status(status_code(status))
        .add_header("content-type", "application/json", None, false)
        .set_body(format!(r#"{{"error":"{code}"}}"#));
    if let Some(challenge) = challenge {
        denied.add_header("www-authenticate", challenge, None, false);
    }
    let mut response = CheckResponse::new();
    response
        .set_status(Status::permission_denied(code.to_owned()))
        .set_http_response(denied);
    response
}

fn txn_metadata(txn: &str) -> Struct {
    let mut fields = HashMap::new();
    fields.insert(
        "txn".to_owned(),
        ProtoValue {
            kind: Some(Kind::StringValue(txn.to_owned())),
        },
    );
    Struct { fields }
}

fn status_code(status: u16) -> HttpStatusCode {
    match status {
        400 => HttpStatusCode::BadRequest,
        401 => HttpStatusCode::Unauthorized,
        403 => HttpStatusCode::Forbidden,
        503 => HttpStatusCode::ServiceUnavailable,
        _ => HttpStatusCode::InternalServerError,
    }
}

#[tonic::async_trait]
impl<P: Pdp + 'static> Authorization for ExtAuthz<P> {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        // Malformed requests are denied in the response, not as gRPC errors,
        // so Envoy's failure_mode_allow cannot turn them into an allow.
        let Some(input) = input_from(request.get_ref()) else {
            return Ok(Response::new(denied_response(
                400,
                "request.no_http_attributes",
                None,
            )));
        };
        let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return Ok(Response::new(denied_response(500, "internal.clock", None)));
        };
        let txn = uuid::Uuid::new_v4().to_string();

        let response = match self.gate.check(&input, elapsed.as_secs(), &txn).await {
            Outcome::Allow { txn, set, remove } => {
                let mut ok = OkHttpResponseBuilder::new();
                for (name, value) in set {
                    ok.add_header(
                        name,
                        value,
                        Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                        false,
                    );
                }
                for name in remove {
                    ok.remove_header(name);
                }
                let mut response = CheckResponse::new();
                response
                    .set_status(Status::ok("allowed"))
                    .set_dynamic_metadata(Some(txn_metadata(&txn)))
                    .set_http_response(ok);
                response
            }
            Outcome::Deny {
                status,
                code,
                challenge,
            } => denied_response(status, &code, challenge.as_deref()),
        };
        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests {
    use super::{UNREADABLE_BODY, input_from};
    use envoy_types::ext_authz::v3::pb::CheckRequest;
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request};

    #[test]
    fn a_body_that_is_not_utf8_is_not_decoded_lossily() {
        let mut raw =
            br#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/data/"#
                .to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(br#""}}}"#);
        let request = CheckRequest {
            attributes: Some(AttributeContext {
                request: Some(Request {
                    http: Some(HttpRequest {
                        method: "POST".into(),
                        raw_body: raw,
                        ..HttpRequest::default()
                    }),
                    ..Request::default()
                }),
                ..AttributeContext::default()
            }),
        };
        let input = input_from(&request).unwrap();
        assert_eq!(input.body.as_deref(), Some(UNREADABLE_BODY));
    }
}
