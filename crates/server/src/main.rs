//! The visado server.
//!
//! ```text
//! visado <config.toml>
//! visado --version
//! ```
//!
//! Serves Envoy ext_authz v3 over gRPC, and over HTTP `/healthz` and the
//! Transaction Token signing key at `/.well-known/jwks.json`. Audit events go
//! to stdout as JSON under the `visado::audit` target.

mod config;

use std::path::PathBuf;
use std::process::ExitCode;

use axum::Router;
use axum::routing::get;
use envoy_types::ext_authz::v3::pb::AuthorizationServer;
use serde_json::json;
use visado_authzen::HttpPdp;
use visado_extauthz::{ExtAuthz, Gate};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V")) {
        println!("visado {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let Some(path) = std::env::args_os()
        .nth(1)
        .or_else(|| std::env::var_os("VISADO_CONFIG"))
        .map(PathBuf::from)
    else {
        eprintln!("usage: visado <config.toml>");
        return ExitCode::from(2);
    };
    match run(&path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("visado: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(path: &std::path::Path) -> Result<(), String> {
    let loaded = config::Config::load(path)?;
    let mut pdp =
        HttpPdp::new(&loaded.pdp_endpoint, loaded.pdp_timeout).map_err(|e| e.to_string())?;
    if let Some(token) = loaded.pdp_bearer {
        pdp = pdp.with_bearer(token);
    }

    let mut jwk = serde_json::to_value(&loaded.public_jwk).map_err(|e| e.to_string())?;
    jwk["kid"] = json!(loaded.gate.kid);
    jwk["use"] = json!("sig");
    let jwks = json!({ "keys": [jwk] });
    let http = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/.well-known/jwks.json",
            get(move || {
                let jwks = jwks.clone();
                async move { axum::Json(jwks) }
            }),
        );
    // Bind both before serving, so a port in use fails startup instead of
    // leaving half the server running.
    let http_listener = tokio::net::TcpListener::bind(loaded.http_listen)
        .await
        .map_err(|e| format!("{}: {e}", loaded.http_listen))?;
    let grpc_listener = tokio::net::TcpListener::bind(loaded.grpc_listen)
        .await
        .map_err(|e| format!("{}: {e}", loaded.grpc_listen))?;

    let gate = Gate::new(loaded.gate, loaded.authenticator, pdp);
    let grpc = tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(ExtAuthz::new(gate)))
        .serve_with_incoming_shutdown(
            tonic::transport::server::TcpIncoming::from(grpc_listener),
            shutdown(),
        );
    let http = axum::serve(http_listener, http).with_graceful_shutdown(shutdown());

    tracing::info!(grpc = %loaded.grpc_listen, http = %loaded.http_listen, "visado listening");
    tokio::try_join!(
        async { grpc.await.map_err(|e| format!("grpc: {e}")) },
        async { http.await.map_err(|e| format!("http: {e}")) },
    )?;
    Ok(())
}

/// Resolves on SIGINT or SIGTERM.
async fn shutdown() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = interrupt.await;
            return;
        };
        tokio::select! {
            _ = interrupt => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}
