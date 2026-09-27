//! The `aiec-mcp` binary.
//!
//! Serves MCP over Streamable HTTP on a loopback address and refuses to start
//! if anything about its configuration would let a workload escape the local
//! cluster. Host commands are used here only to run the server itself.

use std::net::SocketAddr;
use std::sync::Arc;

use aiec_mcp::config::Config;
use aiec_mcp::server::AiecMcp;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

/// What the process needs to validate a request.
#[derive(Clone)]
struct AppState {
    server: Arc<AiecMcp>,
    token: Arc<zeroize::Zeroizing<String>>,
    bind: SocketAddr,
}

/// Rejects any request without the local bearer token.
///
/// Loopback is not an authorisation boundary, so this runs before routing: an
/// unauthenticated caller never reaches an MCP handler.
async fn require_auth(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    match presented {
        Some(token) if aiec_mcp::auth::token_matches(&state.token, token) => next.run(request).await,
        Some(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": { "code": "AUTH_FAILED", "message": "invalid MCP token" }
            })),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": { "code": "AUTH_FAILED", "message": "an Authorization: Bearer <token> header is required" }
            })),
        )
            .into_response(),
    }
}

/// Liveness plus local truthfulness, for an operator or a supervising script.
async fn health(State(state): State<AppState>) -> Response {
    let mut report = state.server.health_report().await;
    // The bind address is reported so an operator can confirm the server is not
    // reachable from the network.
    if let Some(object) = report.as_object_mut() {
        object.insert("bind".to_owned(), serde_json::json!(state.bind.to_string()));
        object.insert(
            "mcp_endpoint".to_owned(),
            serde_json::json!(format!("{}/mcp", state.bind)),
        );
    }
    let status = if report
        .get("ready")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        StatusCode::OK
    } else {
        // Not ready is still a live process, so this is 503 rather than a crash.
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report)).into_response()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config = Config::from_env()?;

    // Build the server before binding: a bad configuration must fail loudly
    // rather than start a listener that cannot reach anything local.
    let server = Arc::new(AiecMcp::new(&config)?);

    let state = AppState {
        server: server.clone(),
        token: config.token.clone(),
        bind: config.bind,
    };

    // Plain JSON replies: these tools answer in one round trip, and a simple
    // client should not have to parse an event stream to read a result.
    let mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    // The factory is called per request, so it must own the handle rather than
    // borrow it out of this function.
    let factory_server = server.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(factory_server.clone()),
        LocalSessionManager::default().into(),
        mcp_config,
    );

    // The token guards MCP traffic only. `/health` stays open so a supervisor
    // can probe it without holding a credential; it reports reachability and
    // nothing secret.
    let mcp_router = Router::new().nest_service("/mcp", mcp_service).layer(
        axum::middleware::from_fn_with_state(state.clone(), require_auth),
    );

    let app = Router::new()
        .merge(mcp_router)
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind: SocketAddr = config.bind;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        aiec_api = %config.endpoint.url,
        loopback = config.endpoint.is_loopback(),
        token_fingerprint = %aiec_mcp::auth::fingerprint(&config.token),
        "aiec-mcp listening"
    );
    println!("aiec-mcp listening on http://{bind}/mcp");
    println!("  control plane : {}", config.endpoint.url);
    println!(
        "  token file    : {}",
        aiec_mcp::auth::token_path().display()
    );
    println!("  token         : (read the file above; never printed in full)");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
