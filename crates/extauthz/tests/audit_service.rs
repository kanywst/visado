//! Requests the ext_authz service refuses before the gate decides (no HTTP
//! attributes, a header value that is not text) get one audit record each,
//! chained with the gate's own, with what is known of the request.

#![allow(clippy::unused_async_trait_impl)]

mod support;

use std::collections::{BTreeSet, HashMap};

use envoy_types::ext_authz::v3::pb::{Authorization, CheckRequest};
use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request};
use visado_authzen::{Decision, EvaluationRequest, Pdp, PdpError};
use visado_credentials::Authenticator;
use visado_extauthz::audit::verify_chain;
use visado_extauthz::{ExtAuthz, Gate, GateConfig};
use visado_testkit::TRUST_DOMAIN;
use visado_txn_token::Scope;
use wimsey_jose::SigningKey;

struct AllowPdp;

impl Pdp for AllowPdp {
    async fn evaluate(&self, _: &EvaluationRequest, _: &str) -> Result<Decision, PdpError> {
        Ok(Decision {
            allowed: true,
            context: None,
        })
    }
}

fn service() -> ExtAuthz<AllowPdp> {
    ExtAuthz::new(Gate::new(
        GateConfig {
            trust_domain: TRUST_DOMAIN.into(),
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
    ))
}

fn http(http: HttpRequest) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(Request {
                http: Some(HttpRequest {
                    method: "GET".into(),
                    scheme: "https".into(),
                    host: "tools.td.example".into(),
                    path: "/tickets?q=1".into(),
                    ..http
                }),
                ..Request::default()
            }),
            ..AttributeContext::default()
        }),
    }
}

fn header_map(value: HeaderValue) -> HttpRequest {
    HttpRequest {
        header_map: Some(HeaderMap {
            headers: vec![HeaderValue {
                key: "x-note".into(),
                ..value
            }],
        }),
        ..HttpRequest::default()
    }
}

/// The denial status of `request`.
async fn status(service: &ExtAuthz<AllowPdp>, request: CheckRequest) -> i32 {
    let response = service
        .check(tonic::Request::new(request))
        .await
        .unwrap()
        .into_inner();
    match response.http_response {
        Some(
            envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse::DeniedResponse(
                d,
            ),
        ) => d.status.map_or(0, |s| s.code),
        other => panic!("not denied: {other:?}"),
    }
}

#[tokio::test]
async fn refusals_before_the_gate_are_recorded() {
    let capture = support::Capture::start();
    let service = service();

    let requests = [
        // No HTTP attributes at all.
        CheckRequest::default(),
        // A raw header value that is not UTF-8.
        http(header_map(HeaderValue {
            raw_value: vec![0xff, 0xfe],
            ..HeaderValue::default()
        })),
        // A text header value the proxy decoded lossily.
        http(header_map(HeaderValue {
            value: "a\u{FFFD}b".into(),
            ..HeaderValue::default()
        })),
        // The same in the `headers` map agentgateway fills.
        http(HttpRequest {
            headers: HashMap::from([("x-note".to_owned(), "a\u{FFFD}b".to_owned())]),
            ..HttpRequest::default()
        }),
    ];
    let count = requests.len();
    for request in requests {
        assert_eq!(status(&service, request).await, 400);
    }

    let records = capture.logs.records();
    assert_eq!(records.len(), count, "one record per refusal");
    assert_eq!(verify_chain(&records), Ok(()));
    let first = &records[0];
    assert_eq!(first.reason, "request.no_http_attributes");
    assert_eq!(first.resource, "");
    assert_eq!(first.action, "");
    for record in &records {
        assert_eq!(record.decision, "deny");
        assert_eq!(record.status, 400);
        assert_eq!(record.pdp, "not_asked");
        assert_eq!(record.remediation, "refused");
        assert_eq!(record.agent, "");
        assert!(record.time > 0);
        assert_ne!(record.id, "");
    }
    for record in &records[1..] {
        assert_eq!(record.reason, "request.invalid_header");
        assert_eq!(record.resource, "https://tools.td.example/tickets");
        assert_eq!(record.action, "GET");
    }
}
