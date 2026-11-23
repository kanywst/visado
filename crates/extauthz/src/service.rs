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
use envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest;
use envoy_types::pb::google::protobuf::value::Kind;
use envoy_types::pb::google::protobuf::{Struct, Value as ProtoValue};
use tonic::{Request, Response, Status};
use visado_authzen::Pdp;
use visado_credentials::{AuthError, PROBLEM_SIGNATURE_INVALID};

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

/// The request as the gate sees it, or the reason code it is refused with.
fn input_from(request: &CheckRequest) -> Result<CheckInput, &'static str> {
    const NO_HTTP: &str = "request.no_http_attributes";
    let http = request
        .attributes
        .as_ref()
        .and_then(|a| a.request.as_ref())
        .and_then(|r| r.http.as_ref())
        .ok_or(NO_HTTP)?;
    // With `encode_raw_headers`, Envoy sends `header_map` and leaves `headers`
    // empty. `header_map` also keeps repeated headers apart instead of joining
    // them with commas, so prefer it when present.
    let mut headers = match &http.header_map {
        Some(map) if !map.headers.is_empty() => map
            .headers
            .iter()
            .map(|h| {
                let value = if h.raw_value.is_empty() {
                    text_value(&h.value)?
                } else {
                    // A value that is not UTF-8 is refused: decoding it
                    // lossily would turn different bytes into the same
                    // U+FFFD text, which a signature over the text could
                    // not tell apart.
                    String::from_utf8(h.raw_value.clone()).map_err(|_| INVALID_HEADER)?
                };
                Ok((h.key.to_ascii_lowercase(), value))
            })
            .collect::<Result<Vec<_>, &'static str>>()?,
        _ => http
            .headers
            .iter()
            .map(|(k, v)| Ok((k.to_ascii_lowercase(), text_value(v)?)))
            .collect::<Result<Vec<_>, &'static str>>()?,
    };
    // Group by name, keeping repeated fields in the order received: an HTTP
    // signature covers their values joined in that order.
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let body = if http.raw_body.is_empty() {
        http.body.as_bytes().to_vec()
    } else {
        http.raw_body.clone()
    };
    // Set by Envoy from its own TLS termination when the ext_authz filter has
    // `include_peer_certificate`. It is not a request header, so the client
    // cannot set it.
    let peer_certificate = request
        .attributes
        .as_ref()
        .and_then(|a| a.source.as_ref())
        .map(|source| source.certificate.as_str())
        .filter(|c| !c.is_empty())
        .map(ToOwned::to_owned);
    Ok(CheckInput {
        method: http.method.clone(),
        scheme: http.scheme.clone(),
        authority: http.host.clone(),
        path: http.path.clone(),
        headers,
        body: (!body.is_empty()).then_some(body),
        peer_certificate,
    })
}

/// What a refused request's audit record can name of it: the method and
/// target when the HTTP attributes are there, nothing else.
fn known_input(request: &CheckRequest) -> CheckInput {
    let http = request
        .attributes
        .as_ref()
        .and_then(|a| a.request.as_ref())
        .and_then(|r| r.http.as_ref());
    let field = |f: fn(&HttpRequest) -> &String| http.map(f).cloned().unwrap_or_default();
    CheckInput {
        method: field(|h| &h.method),
        scheme: field(|h| &h.scheme),
        authority: field(|h| &h.host),
        path: field(|h| &h.path),
        headers: Vec::new(),
        body: None,
        peer_certificate: None,
    }
}

/// The reason code for a header value that is not UTF-8.
const INVALID_HEADER: &str = "request.invalid_header";

/// A header value the proxy sent as text. A proxy that decodes values
/// lossily itself (agentgateway does) leaves U+FFFD in place of the bytes it
/// could not decode, so such a value is refused like one that is not UTF-8.
fn text_value(value: &str) -> Result<String, &'static str> {
    if value.contains('\u{FFFD}') {
        return Err(INVALID_HEADER);
    }
    Ok(value.to_owned())
}

fn denied_response(
    status: u16,
    code: &str,
    challenge: Option<&str>,
    headers: &[(String, String)],
) -> CheckResponse {
    let mut denied = DeniedHttpResponseBuilder::new();
    denied.set_http_status(status_code(status));
    if code == AuthError::HttpSig(String::new()).code() {
        // draft-ietf-wimse-http-signature: one RFC 9457 problem type for every
        // failed check on a signed request.
        denied
            .add_header("content-type", "application/problem+json", None, false)
            .set_body(format!(
                r#"{{"type":"{PROBLEM_SIGNATURE_INVALID}","status":{status},"error":"{code}"}}"#
            ));
    } else {
        denied
            .add_header("content-type", "application/json", None, false)
            .set_body(format!(r#"{{"error":"{code}"}}"#));
    }
    if let Some(challenge) = challenge {
        denied.add_header("www-authenticate", challenge, None, false);
    }
    for (name, value) in headers {
        denied.add_header(name, value, None, false);
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
        429 => HttpStatusCode::TooManyRequests,
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
        // A request visado can decode but refuses is denied in the response,
        // not as a gRPC error, so failure_mode_allow cannot turn it into an
        // allow. That does not cover a CheckRequest that fails to decode (a
        // string field that is not UTF-8, or a message over the 4 MiB gRPC
        // limit): tonic rejects it before this handler runs and the proxy
        // applies its failure mode, which must therefore deny. See "Proxy
        // settings" in docs/bindings.md.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        Ok(Response::new(self.respond(request.get_ref(), now).await))
    }
}

impl<P: Pdp + 'static> ExtAuthz<P> {
    /// The response to `request` at `now`, or `None` if the clock could not
    /// be read. Every request gets one audit record, the ones refused here
    /// before the gate decides included.
    async fn respond(&self, request: &CheckRequest, now: Option<u64>) -> CheckResponse {
        let txn = uuid::Uuid::new_v4().to_string();
        let input = match input_from(request) {
            Ok(input) => input,
            Err(code) => {
                let known = known_input(request);
                self.gate
                    .record_refusal(&known, now.unwrap_or(0), &txn, 400, code);
                return denied_response(400, code, None, &[]);
            }
        };
        let Some(now) = now else {
            const CLOCK: &str = "internal.clock";
            self.gate.record_refusal(&input, 0, &txn, 500, CLOCK);
            return denied_response(500, CLOCK, None, &[]);
        };

        match self.gate.check(&input, now, &txn).await {
            Outcome::Allow {
                txn,
                set,
                remove,
                response_headers,
            } => {
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
                for (name, value) in response_headers {
                    ok.add_response_header(
                        name,
                        value,
                        Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                        false,
                    );
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
                headers,
            } => denied_response(status, &code, challenge.as_deref(), &headers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExtAuthz, denied_response, input_from};
    use crate::recent::{Decision, RequestLog};
    use crate::{Gate, GateConfig};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use visado_authzen::{Decision as PdpDecision, EvaluationRequest, Pdp, PdpError};
    use visado_credentials::Authenticator;
    use visado_txn_token::Scope;
    use wimsey_jose::SigningKey;

    struct AllowPdp;

    impl Pdp for AllowPdp {
        #[allow(clippy::unused_async_trait_impl)]
        async fn evaluate(&self, _: &EvaluationRequest, _: &str) -> Result<PdpDecision, PdpError> {
            Ok(PdpDecision {
                allowed: true,
                context: None,
            })
        }
    }

    /// Without a clock the request is refused with `internal.clock`, and
    /// still gets its audit record (with `time` 0) and its log entry.
    #[tokio::test]
    async fn a_refusal_for_the_clock_is_recorded() {
        let log = Arc::new(RequestLog::new(8));
        let gate = Gate::new(
            GateConfig {
                trust_domain: "td.example".into(),
                signing_key: SigningKey::from_ed25519_seed(&[0x51; 32]).into(),
                kid: "txn-1".into(),
                txn_lifetime: 60,
                default_scope: Scope::parse("tools.call"),
                internal_callers: BTreeSet::new(),
                allowed_authorities: BTreeSet::from(["tools.td.example".to_owned()]),
                aat: None,
                asor: None,
                act: None,
                require_chain: false,
            },
            Authenticator::new(),
            AllowPdp,
        )
        .with_request_log(Arc::clone(&log));
        let service = ExtAuthz::new(gate);
        let request = CheckRequest {
            attributes: Some(AttributeContext {
                request: Some(Request {
                    http: Some(HttpRequest {
                        method: "GET".into(),
                        scheme: "https".into(),
                        host: "tools.td.example".into(),
                        path: "/tickets".into(),
                        ..HttpRequest::default()
                    }),
                    ..Request::default()
                }),
                ..AttributeContext::default()
            }),
        };
        let response = service.respond(&request, None).await;
        let Some(Http::DeniedResponse(denied)) = response.http_response else {
            panic!("not denied");
        };
        assert_eq!(denied.status.map(|s| s.code), Some(500));
        assert_eq!(service.gate.next_audit_seq(), 1, "one audit record");
        let entries = log.recent(8);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].time, 0);
        assert_eq!(entries[0].resource, "https://tools.td.example/tickets");
        assert_eq!(entries[0].code, "internal.clock");
        assert_eq!(entries[0].decision, Decision::Deny);
    }
    use envoy_types::ext_authz::v3::pb::CheckRequest;
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request};
    use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse as Http;

    #[test]
    fn a_body_that_is_not_utf8_is_kept_as_bytes() {
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
                        raw_body: raw.clone(),
                        ..HttpRequest::default()
                    }),
                    ..Request::default()
                }),
                ..AttributeContext::default()
            }),
        };
        let input = input_from(&request).unwrap();
        assert_eq!(input.body.as_deref(), Some(raw.as_slice()));
    }

    // agentgateway (v1.7) fills `headers` rather than `header_map`, includes
    // the pseudo-headers, drops `host` (it moves into the URI authority) and
    // sends the authority as `host`.
    #[test]
    fn an_agentgateway_check_request_maps_like_envoys() {
        let headers = [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", "tools.td.example"),
            (":path", "/mcp?x=1"),
            ("Workload-Identity-Token", "wit"),
            ("content-type", "application/json"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let request = CheckRequest {
            attributes: Some(AttributeContext {
                request: Some(Request {
                    http: Some(HttpRequest {
                        method: "POST".into(),
                        scheme: "http".into(),
                        host: "tools.td.example".into(),
                        path: "/mcp?x=1".into(),
                        headers,
                        raw_body: b"{}".to_vec(),
                        ..HttpRequest::default()
                    }),
                    ..Request::default()
                }),
                ..AttributeContext::default()
            }),
        };
        let input = input_from(&request).unwrap();
        assert_eq!(input.method, "POST");
        assert_eq!(input.scheme, "http");
        assert_eq!(input.authority, "tools.td.example");
        assert_eq!(input.path, "/mcp?x=1");
        assert_eq!(input.body.as_deref(), Some(b"{}".as_slice()));
        assert!(input.peer_certificate.is_none());
        assert!(
            input
                .headers
                .iter()
                .any(|(k, v)| k == "workload-identity-token" && v == "wit")
        );
    }

    #[test]
    fn a_failed_signed_request_is_a_problem_document() {
        let response = denied_response(400, "httpsig.invalid", None, &[]);
        let Some(Http::DeniedResponse(denied)) = response.http_response else {
            panic!("denied")
        };
        assert_eq!(denied.status.map(|s| s.code), Some(400));
        assert!(
            denied
                .body
                .contains(visado_credentials::PROBLEM_SIGNATURE_INVALID)
        );
        let content_type = denied
            .headers
            .iter()
            .filter_map(|h| h.header.as_ref())
            .find(|h| h.key == "content-type")
            .map(|h| h.value.as_str());
        assert_eq!(content_type, Some("application/problem+json"));
    }

    #[test]
    fn every_status_the_gate_denies_with_reaches_the_client() {
        for status in [400, 401, 403, 429, 500, 503] {
            let response = denied_response(status, "code", None, &[]);
            let Some(Http::DeniedResponse(denied)) = response.http_response else {
                panic!("denied")
            };
            assert_eq!(denied.status.map(|s| s.code), Some(i32::from(status)));
        }
    }

    #[test]
    fn repeated_headers_keep_their_order() {
        use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
        let header = |k: &str, v: &str| HeaderValue {
            key: k.into(),
            value: v.into(),
            ..HeaderValue::default()
        };
        let request = CheckRequest {
            attributes: Some(AttributeContext {
                request: Some(Request {
                    http: Some(HttpRequest {
                        header_map: Some(HeaderMap {
                            headers: vec![
                                header("x-b", "2"),
                                header("x-a", "z"),
                                header("x-a", "y"),
                            ],
                        }),
                        ..HttpRequest::default()
                    }),
                    ..Request::default()
                }),
                ..AttributeContext::default()
            }),
        };
        let input = input_from(&request).unwrap();
        let pairs: Vec<(&str, &str)> = input
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(pairs, [("x-a", "z"), ("x-a", "y"), ("x-b", "2")]);
    }
}
