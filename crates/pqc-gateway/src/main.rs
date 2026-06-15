use anyhow::Result;
use axum::middleware;
use axum::response::Json;
use axum::routing::{any, get, post};
use axum::Router;
use clap::Parser;
use pqc_proxy::circuit_breaker;
use pqc_proxy::config::GatewayConfig;
use pqc_proxy::jwt_auth::{self, AuthState};
use pqc_proxy::middleware::{logging_middleware, request_id_middleware};
use pqc_proxy::proxy::{proxy_handler, ws_proxy_handler, ProxyState};
use pqc_tls::config::TlsConfig;
use pqc_tls::fips;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "pqc-gateway", about = "PQC-enabled API Gateway with TLS 1.3 + PQC support")]
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

    // Log signature mode from env and config
    let env_sig_mode = std::env::var("PQC_SIGNATURE_MODE").ok();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        env_signature_mode = ?env_sig_mode,
        config_default_signature_mode = %config.signatures.default_mode,
        auth_enabled = config.auth.enabled,
        cb_enabled = config.circuit_breaker.enabled,
        threshold_enabled = config.threshold.enabled,
        "Starting PQC Gateway"
    );

    // Build proxy state and router
    let tls_enabled = config.tls.enabled;
    let tls_file_config = config.tls.clone();
    let http_port = config.server.http_port;
    let auth_config = config.auth.clone();
    let cb_enabled = config.circuit_breaker.enabled;
    let cb_interval_ms = config.circuit_breaker.health_check_interval_ms;
    let state = ProxyState::new(config);

    // Set up auth state
    let auth_state = Arc::new(AuthState {
        key_manager: state.versioned_key_manager.clone(),
        issuer: auth_config.issuer.clone(),
        audience: auth_config.audience.clone(),
        public_paths: auth_config.public_paths.clone(),
    });

    // Clone for handlers
    let versioned_km = state.versioned_key_manager.clone();
    let cb_manager = state.circuit_breaker.clone();
    let auth_state_for_token = auth_state.clone();

    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route(
            "/.well-known/jwks.json",
            get({
                let km = versioned_km.clone();
                move || async move { Json(km.jwks()) }
            }),
        )
        .route(
            "/auth/token",
            post({
                let auth = auth_state_for_token.clone();
                move |body: Json<serde_json::Value>| async move {
                    let sub = body.get("sub").and_then(|v| v.as_str()).unwrap_or("anonymous");
                    let roles: Vec<String> = body
                        .get("roles")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    match jwt_auth::create_jwt(
                        &auth.key_manager,
                        sub,
                        &roles,
                        &auth.issuer,
                        &auth.audience,
                        3600,
                    ) {
                        Some(token) => Json(json!({
                            "token": token,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "algorithm": "ML-DSA-65",
                            "kid": auth.key_manager.current_kid(),
                        })),
                        None => Json(json!({ "error": "token generation failed" })),
                    }
                }
            }),
        )
        .route(
            "/auth/rotate-keys",
            post({
                let km = versioned_km.clone();
                move || async move {
                    let new_kid = km.rotate();
                    Json(json!({
                        "status": "rotated",
                        "new_kid": new_kid,
                        "total_keys": km.key_count(),
                    }))
                }
            }),
        )
        .route(
            "/admin/circuit-breakers",
            get({
                let cb = cb_manager.clone();
                move || async move {
                    let status = cb.get_status();
                    let entries: Vec<serde_json::Value> = status
                        .iter()
                        .map(|(upstream, s)| {
                            json!({
                                "upstream": upstream,
                                "state": s.state.to_string(),
                                "consecutive_failures": s.consecutive_failures,
                                "total_requests": s.total_requests,
                                "total_failures": s.total_failures,
                                "total_circuit_opens": s.total_circuit_opens,
                                "healthy": s.healthy,
                            })
                        })
                        .collect();
                    Json(json!({ "circuit_breakers": entries }))
                }
            }),
        )
        .route(
            "/admin/keys",
            get({
                let km = versioned_km.clone();
                move || async move {
                    let info: Vec<serde_json::Value> = km
                        .key_info()
                        .into_iter()
                        .map(|(kid, version, active)| {
                            json!({
                                "kid": kid,
                                "version": version,
                                "active": active,
                            })
                        })
                        .collect();
                    Json(json!({
                        "current_kid": km.current_kid(),
                        "total_keys": km.key_count(),
                        "keys": info,
                    }))
                }
            }),
        )
        .route("/ws/{*path}", any(ws_proxy_handler))
        .fallback(proxy_handler)
        .with_state(state);

    // Apply auth middleware if enabled
    if auth_config.enabled {
        app = app.layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            jwt_auth::jwt_auth_middleware,
        ));
    }

    app = app
        .layer(middleware::from_fn(logging_middleware))
        .layer(middleware::from_fn(request_id_middleware));

    // Spawn health check background task
    if cb_enabled {
        let cb_for_health = cb_manager.clone();
        let interval = Duration::from_millis(cb_interval_ms);
        tokio::spawn(async move {
            circuit_breaker::run_health_checks(cb_for_health, interval).await;
        });
        info!("Circuit breaker health checks started");
    }

    if tls_enabled {
        start_with_tls(app, &tls_file_config).await
    } else {
        start_plain(app, http_port).await
    }
}

/// Start the gateway with TLS (HTTPS) + optional plain HTTP redirect.
async fn start_with_tls(
    app: Router,
    tls_file_config: &pqc_proxy::config::TlsFileConfig,
) -> Result<()> {
    // Convert file-level config to pqc-tls config
    let tls_config = TlsConfig {
        enabled: true,
        cert_file: tls_file_config.cert_file.clone(),
        key_file: tls_file_config.key_file.clone(),
        min_version: tls_file_config.min_version.clone(),
        pqc_enabled: tls_file_config.pqc_enabled,
        https_port: tls_file_config.https_port,
        ca_file: tls_file_config.ca_file.clone(),
        signatures: Default::default(),
    };

    // Run FIPS compliance checks at startup
    fips::log_compliance_report(tls_config.pqc_enabled);

    // Build rustls server config
    let rustls_config = pqc_tls::provider::build_server_config(&tls_config)?;
    let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

    let bind_addr = format!("0.0.0.0:{}", tls_config.https_port);
    let listener = TcpListener::bind(&bind_addr).await?;

    info!(
        address = %bind_addr,
        pqc = tls_config.pqc_enabled,
        min_tls = %tls_config.min_version,
        "Gateway listening (HTTPS with TLS 1.3 + PQC)"
    );

    // Accept TLS connections in a loop
    let app = Arc::new(app);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = result?;
                let acceptor = acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // Log negotiated parameters
                            let (_, server_conn) = tls_stream.get_ref();
                            if let Some(neg_info) = pqc_tls::provider::NegotiatedInfo::from_server_connection(server_conn) {
                                info!(
                                    peer = %peer_addr,
                                    tls_version = neg_info.protocol_version,
                                    cipher = %neg_info.cipher_suite,
                                    key_exchange = %neg_info.key_exchange,
                                    "TLS handshake completed"
                                );
                            }

                            // Serve HTTP over TLS
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            let service = hyper_util::service::TowerToHyperService::new((*app).clone());
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(io, service)
                            .await
                            {
                                // Connection reset by peer is normal
                                if !e.to_string().contains("connection reset") {
                                    error!(peer = %peer_addr, error = %e, "Connection error");
                                }
                            }
                        }
                        Err(e) => {
                            // TLS handshake failures are common (port scanners, wrong TLS version)
                            info!(peer = %peer_addr, error = %e, "TLS handshake failed");
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                info!("Shutting down TLS server...");
                break;
            }
        }
    }

    info!("Gateway shut down");
    Ok(())
}

/// Start the gateway without TLS (plain HTTP).
async fn start_plain(app: Router, http_port: u16) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", http_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!(address = %bind_addr, "Gateway listening (plain HTTP — TLS disabled)");

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
        "tls": "supported",
        "pqc": "X25519MLKEM768",
        "fips": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "FIPS 186-5 (ECDSA)"],
        "features": {
            "jwt_auth": "ML-DSA-65",
            "key_rotation": "versioned JWKS",
            "circuit_breaker": "per-upstream",
            "body_integrity": "PQC signed",
            "websocket": "bidirectional tunnel",
            "threshold_signing": "Shamir SSS",
        },
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