//! The visado server.
//!
//! ```text
//! visado <config.toml>
//! visado --version
//! ```
//!
//! Serves Envoy ext_authz v3 over gRPC, and over HTTP `/healthz` and the
//! Transaction Token signing key at `/.well-known/jwks.json`. Audit events go
//! to stdout as JSON under the `visado::audit` target. With `[chain_view]`
//! enabled, the HTTP listener also serves recent decisions at
//! `/api/requests` and a page that draws them at `/chain`.

mod chain_view;
mod config;
mod status;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use envoy_types::ext_authz::v3::pb::AuthorizationServer;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use serde_json::json;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use visado_authzen::HttpPdp;
use visado_extauthz::{ExtAuthz, Gate, RequestLog};

#[tokio::main]
async fn main() -> ExitCode {
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
    let tracer = init_tracing(loaded.telemetry.as_ref())?;
    let chains =
        loaded.gate.aat.is_some() || loaded.gate.asor.is_some() || loaded.gate.act.is_some();
    if loaded.dpop_nonce_keys == Some(config::NonceKeys::Generated) {
        tracing::info!(
            "DPoP nonces use a key made at startup: another replica or a restart rejects them, and clients retry once with a new nonce; set dpop.nonce_key_files to share a key"
        );
    }
    if chains && !loaded.gate.require_chain {
        tracing::warn!(
            "a delegation chain format is configured without required = true: requests without a chain skip the chain checks"
        );
    }
    let result = serve(loaded).await;
    if let Some(provider) = tracer {
        let _ = provider.shutdown();
    }
    result
}

/// JSON logs to stdout, plus OTLP traces when configured.
fn init_tracing(
    telemetry: Option<&config::TelemetryConfig>,
) -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>, String> {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let logs = tracing_subscriber::fmt::layer().json();
    let Some(telemetry) = telemetry else {
        tracing_subscriber::registry()
            .with(filter)
            .with(logs)
            .init();
        return Ok(None);
    };

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&telemetry.otlp_endpoint)
        .build()
        .map_err(|e| format!("otlp exporter: {e}"))?;
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(telemetry.service_name.clone())
                .build(),
        )
        .build();
    let tracer = provider.tracer("visado");
    tracing_subscriber::registry()
        .with(filter)
        .with(logs)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();
    Ok(Some(provider))
}

async fn serve(loaded: config::Loaded) -> Result<(), String> {
    if let Some(status) = loaded.asor_status {
        status.spawn()?;
    }
    let mut pdp =
        HttpPdp::new(&loaded.pdp_endpoint, loaded.pdp_timeout).map_err(|e| e.to_string())?;
    if let Some(token) = loaded.pdp_bearer {
        pdp = pdp.with_bearer(token);
    }
    if loaded.pdp_context_in_subject {
        pdp = pdp.with_context_in_subject();
    }

    let mut jwk = serde_json::to_value(&loaded.public_jwk).map_err(|e| e.to_string())?;
    jwk["kid"] = json!(loaded.gate.kid);
    jwk["use"] = json!("sig");
    let jwks = json!({ "keys": [jwk] });
    let mut http = Router::new()
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

    let mut gate = Gate::new(loaded.gate, loaded.authenticator, pdp);
    if let Some(view) = loaded.chain_view {
        let log = Arc::new(RequestLog::new(view.capacity));
        gate = gate.with_request_log(Arc::clone(&log));
        http = http.merge(chain_view::router(log, view.allowed_hosts));
        tracing::warn!(
            http = %loaded.http_listen,
            capacity = view.capacity,
            "chain view enabled at /chain: it shows caller and principal identities to anyone who can reach the HTTP listener"
        );
    }
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
