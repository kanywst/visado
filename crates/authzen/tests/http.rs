//! `HttpPdp` against a local stand-in PDP.

use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::{Value, json};
use visado_authzen::{Action, Entity, EvaluationRequest, HttpPdp, Pdp, discover};

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn request() -> EvaluationRequest {
    EvaluationRequest::for_agent(
        "spiffe://td.example/agent",
        Some(Entity::new("user", "alice")),
        Entity::new("tool", "read_file"),
        Action::new("call"),
    )
}

async fn echo_decision(headers: HeaderMap, body: axum::Json<Value>) -> impl IntoResponse {
    let allowed = body["context"]["principal"]["id"] == "alice";
    let id = headers
        .get("x-request-id")
        .cloned()
        .unwrap_or_else(|| "missing".parse().unwrap());
    (
        [("x-request-id", id)],
        axum::Json(json!({ "decision": allowed })),
    )
}

#[tokio::test]
async fn allows_and_denies() {
    let base = serve(Router::new().route("/access/v1/evaluation", post(echo_decision))).await;
    let pdp = HttpPdp::new(
        format!("{base}/access/v1/evaluation"),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(pdp.evaluate(&request(), "r1").await.unwrap().allowed);

    let mut other = request();
    other.context = None;
    assert!(!pdp.evaluate(&other, "r2").await.unwrap().allowed);
}

#[tokio::test]
async fn every_failure_is_an_error() {
    let base = serve(
        Router::new()
            .route("/500", post(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
            .route(
                "/string",
                post(|| async { axum::Json(json!({ "decision": "true" })) }),
            )
            .route(
                "/wrong-id",
                post(|| async {
                    (
                        [("x-request-id", "other")],
                        axum::Json(json!({ "decision": true })),
                    )
                }),
            )
            .route(
                "/slow",
                post(|| async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    axum::Json(json!({ "decision": true }))
                }),
            ),
    )
    .await;
    for (path, code) in [
        ("/500", "pdp.status"),
        ("/string", "pdp.invalid_response"),
        ("/wrong-id", "pdp.request_id_mismatch"),
        ("/slow", "pdp.unavailable"),
    ] {
        let pdp = HttpPdp::new(format!("{base}{path}"), Duration::from_millis(300)).unwrap();
        let err = pdp.evaluate(&request(), "r").await.unwrap_err();
        assert_eq!(err.code(), code, "{path}");
    }
    let closed = HttpPdp::new("http://127.0.0.1:9/x", Duration::from_millis(300)).unwrap();
    assert_eq!(
        closed.evaluate(&request(), "r").await.unwrap_err().code(),
        "pdp.unavailable"
    );
}

#[tokio::test]
async fn discovers_a_tenant_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let pdp = format!("{origin}/tenant1");
    let doc = json!({
        "policy_decision_point": pdp,
        "access_evaluation_endpoint": format!("{pdp}/access/v1/evaluation"),
    });
    let router = Router::new().route(
        "/.well-known/authzen-configuration/tenant1",
        get(move || {
            let doc = doc.clone();
            async move { axum::Json(doc) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let endpoint = discover(&pdp, Duration::from_secs(2)).await.unwrap();
    assert_eq!(endpoint, format!("{pdp}/access/v1/evaluation"));
    let mismatch = discover(&format!("{pdp}/"), Duration::from_secs(2)).await;
    assert!(mismatch.is_err(), "the identifier must match exactly");
}

#[tokio::test]
async fn discovers_the_endpoint() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let doc = json!({
        "policy_decision_point": base,
        "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"),
    });
    let router = Router::new().route(
        "/.well-known/authzen-configuration",
        get(move || {
            let doc = doc.clone();
            async move { axum::Json(doc) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let endpoint = discover(&base, Duration::from_secs(2)).await.unwrap();
    assert_eq!(endpoint, format!("{base}/access/v1/evaluation"));
}
