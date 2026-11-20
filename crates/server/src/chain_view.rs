//! The chain view: recent decisions and their delegation chains, as JSON and
//! as one static page, on the HTTP listener.
//!
//! - `GET /chain`: the page (plain HTML, CSS and JS, embedded in the binary).
//! - `GET /api/requests?limit=N`: the most recent decisions, newest first.
//! - `GET /api/requests/{id}`: one decision, by the id the list gives.
//!
//! It shows caller and principal identities. Requests whose `Host` is not in
//! the allowed list get 421, so a page that rebinds its own name to the
//! loopback address cannot read the view through the visitor's browser.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;
use visado_extauthz::RequestLog;

const PAGE: &str = include_str!("../ui/chain.html");
const SCRIPT: &str = include_str!("../ui/chain.js");
const STYLE: &str = include_str!("../ui/chain.css");

/// Entries returned by the list when the request does not say.
const DEFAULT_LIMIT: usize = 100;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone)]
struct ViewState {
    log: Arc<RequestLog>,
    hosts: Arc<[String]>,
}

/// The chain view's routes, reading `log` and answering only `hosts`.
pub fn router(log: Arc<RequestLog>, hosts: Vec<String>) -> Router {
    let state = ViewState {
        log,
        hosts: hosts.into(),
    };
    Router::new()
        .route(
            "/chain",
            get(|| async { asset("text/html; charset=utf-8", PAGE) }),
        )
        .route(
            "/chain/chain.js",
            get(|| async { asset("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/chain/chain.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE) }),
        )
        .route("/api/requests", get(list))
        .route("/api/requests/{id}", get(one))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<usize>,
}

async fn list(State(state): State<ViewState>, Query(query): Query<ListQuery>) -> Response {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .min(state.log.capacity());
    axum::Json(json!({
        "capacity": state.log.capacity(),
        "requests": state.log.recent(limit),
    }))
    .into_response()
}

async fn one(State(state): State<ViewState>, Path(id): Path<String>) -> Response {
    match state.log.get(&id) {
        Some(summary) => axum::Json(summary).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": "not_found" })),
        )
            .into_response(),
    }
}

/// Answers only the allowed hosts, and marks every response as not to be
/// cached, framed or sniffed.
async fn guard(State(state): State<ViewState>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(axum::http::uri::Authority::as_str)
        })
        .map(host_name);
    let allowed = host.is_some_and(|h| state.hosts.iter().any(|a| a.eq_ignore_ascii_case(h)));
    let mut response = if allowed {
        next.run(request).await
    } else {
        (
            StatusCode::MISDIRECTED_REQUEST,
            axum::Json(json!({ "error": "host_not_allowed" })),
        )
            .into_response()
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// A `Host` value without its port. An IPv6 literal keeps its brackets.
fn host_name(value: &str) -> &str {
    if value.starts_with('[') {
        value.find(']').map_or(value, |end| &value[..=end])
    } else {
        value.split(':').next().unwrap_or(value)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use std::sync::Arc;

    use serde_json::Value;
    use visado_extauthz::RequestLog;
    use visado_extauthz::recent::{Decision, RequestSummary};

    use super::{host_name, router};

    fn summary(id: &str) -> RequestSummary {
        RequestSummary {
            id: id.into(),
            txn: Some(format!("txn-{id}")),
            time: 1_700_000_000,
            method: "GET".into(),
            resource: "https://tools.td.example/mcp".into(),
            caller: Some("spiffe://td.example/agent-a".into()),
            auth_method: Some("wit-wpt"),
            principal: Some("alice".into()),
            decision: Decision::Allow,
            status: 200,
            code: "ok".into(),
            pdp: None,
            chain: None,
        }
    }

    async fn serve(log: Arc<RequestLog>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(log, vec!["localhost".into(), "127.0.0.1".into()]);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// A blocking HTTP/1.1 GET: the status, the header block and the body.
    async fn get(addr: SocketAddr, path: &str, host: &str) -> (u16, String, String) {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut text = String::new();
            stream.read_to_string(&mut text).unwrap();
            let (head, body) = text.split_once("\r\n\r\n").unwrap();
            let status = head[9..12].parse().unwrap();
            (status, head.to_ascii_lowercase(), body.to_owned())
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn lists_and_finds_recent_decisions() {
        let log = Arc::new(RequestLog::new(4));
        for id in ["a", "b", "c"] {
            log.record(summary(id));
        }
        let addr = serve(log).await;

        let (status, head, body) = get(addr, "/api/requests?limit=2", "127.0.0.1:8080").await;
        assert_eq!(status, 200);
        assert!(head.contains("content-type: application/json"), "{head}");
        assert!(head.contains("cache-control: no-store"), "{head}");
        let list: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["capacity"], 4);
        let ids: Vec<&str> = list["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["c", "b"]);

        let (status, _, body) = get(addr, "/api/requests/b", "localhost").await;
        assert_eq!(status, 200);
        let one: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(one["txn"], "txn-b");
        assert_eq!(one["decision"], "allow");
        assert_eq!(one["auth_method"], "wit-wpt");

        let (status, _, body) = get(addr, "/api/requests/zzz", "localhost").await;
        assert_eq!(status, 404);
        assert!(body.contains("not_found"));
    }

    #[tokio::test]
    async fn the_limit_is_capped_by_the_capacity() {
        let log = Arc::new(RequestLog::new(2));
        for id in ["a", "b", "c"] {
            log.record(summary(id));
        }
        let addr = serve(log).await;
        let (_, _, body) = get(addr, "/api/requests?limit=1000", "localhost").await;
        let list: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["requests"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn serves_the_page_with_a_strict_policy() {
        let addr = serve(Arc::new(RequestLog::new(1))).await;
        for (path, kind) in [
            ("/chain", "text/html"),
            ("/chain/chain.js", "text/javascript"),
            ("/chain/chain.css", "text/css"),
        ] {
            let (status, head, _) = get(addr, path, "localhost:8080").await;
            assert_eq!(status, 200, "{path}");
            assert!(head.contains(&format!("content-type: {kind}")), "{head}");
            assert!(head.contains("content-security-policy: default-src 'none'"));
            assert!(head.contains("x-content-type-options: nosniff"));
        }
    }

    #[tokio::test]
    async fn other_hosts_are_refused() {
        let log = Arc::new(RequestLog::new(1));
        log.record(summary("a"));
        let addr = serve(log).await;
        for host in [
            "evil.example",
            "evil.example:8080",
            "localhost.evil.example",
        ] {
            let (status, _, body) = get(addr, "/api/requests", host).await;
            assert_eq!(status, 421, "{host}");
            assert!(!body.contains("alice"));
        }
    }

    #[test]
    fn host_names_drop_the_port() {
        assert_eq!(host_name("localhost:8080"), "localhost");
        assert_eq!(host_name("127.0.0.1"), "127.0.0.1");
        assert_eq!(host_name("[::1]:8080"), "[::1]");
        assert_eq!(host_name("[::1]"), "[::1]");
    }
}
