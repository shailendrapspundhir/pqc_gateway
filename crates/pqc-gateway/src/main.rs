use anyhow::Result;
use axum::middleware;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use pqc_proxy::config::GatewayConfig;
use pqc_proxy::middleware::{logging_middleware, request_id_middleware};
use pqc_proxy::proxy::{proxy_handler, ProxyState};
use serde_json::json;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
#[command(name = "pqc-gateway", about = "PQC-enabled API Gateway")]
struct Cli {
    /// Path to gateway configuration file
    #[arg(short, long, default_value = "config/gateway.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = GatewayConfig::from_file(&cli.config)?;

    // Initialize tracing
    init_tracing(&config.logging.level, &config.logging.format);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "Starting PQC Gateway"
    );

    let bind_addr = format!("{}:{}", config.server.bind_address, config.server.http_port);

    // Build proxy state
    let state = ProxyState::new(config);

    // Build router
    let app = Router::new()
        .route("/health", get(health_handler))
        .fallback(proxy_handler)
        .with_state(state)
        .layer(middleware::from_fn(logging_middleware))
        .layer(middleware::from_fn(request_id_middleware));

    // Start server
    let listener = TcpListener::bind(&bind_addr).await?;
    info!(address = %bind_addr, "Gateway listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Gateway shut down");
    Ok(())
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "pqc-gateway",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down..."),
        _ = terminate => info!("Received SIGTERM, shutting down..."),
    }
}

fn init_tracing(level: &str, format: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }
}