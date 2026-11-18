//! Envoy ext_authz v3 over gRPC.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
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
    let mut headers: Vec<(String, String)> = http
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    headers.sort();
    Some(CheckInput {
        method: http.method.clone(),
        scheme: if http.scheme.is_empty() {
            "https".into()
        } else {
            http.scheme.clone()
        },
        authority: http.host.clone(),
        path: http.path.clone(),
        headers,
    })
}

fn status_code(status: u16) -> HttpStatusCode {
    match status {
        401 => HttpStatusCode::Unauthorized,
        403 => HttpStatusCode::Forbidden,
        _ => HttpStatusCode::InternalServerError,
    }
}

#[tonic::async_trait]
impl<P: Pdp + 'static> Authorization for ExtAuthz<P> {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let Some(input) = input_from(request.get_ref()) else {
            return Err(Status::invalid_argument("no HTTP request attributes"));
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("clock before epoch"))?
            .as_secs();
        let txn = uuid::Uuid::new_v4().to_string();

        let mut response = CheckResponse::new();
        match self.gate.check(&input, now, &txn).await {
            Outcome::Allow { set, remove, .. } => {
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
                response
                    .set_status(Status::ok("allowed"))
                    .set_http_response(ok);
            }
            Outcome::Deny {
                status,
                code,
                challenge,
            } => {
                let mut denied = DeniedHttpResponseBuilder::new();
                denied
                    .set_http_status(status_code(status))
                    .add_header("content-type", "application/json", None, false)
                    .set_body(format!(r#"{{"error":"{code}"}}"#));
                if let Some(challenge) = challenge {
                    denied.add_header("www-authenticate", challenge, None, false);
                }
                response
                    .set_status(Status::permission_denied(code))
                    .set_http_response(denied);
            }
        }
        Ok(Response::new(response))
    }
}
