use anyhow::Result;
use axum::middleware;
use axum::response::{IntoResponse, Json};
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
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

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

    // Log startup info
    let env_sig_mode = std::env::var("PQC_SIGNATURE_MODE").ok();
    let has_signing_key = std::env::var("GATEWAY_SIGNING_KEY").is_ok();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        env_signature_mode = ?env_sig_mode,
        signing_key_from_env = has_signing_key,
        config_default_signature_mode = %config.signatures.default_mode,
        auth_enabled = config.auth.enabled,
        cb_enabled = config.circuit_breaker.enabled,
        threshold_enabled = config.threshold.enabled,
        rate_limit_enabled = config.rate_limit.enabled,
        admin_enabled = config.admin.enabled,
        "Starting PQC Gateway"
    );

    // Install rustls crypto provider (needed for HTTPS upstream connector)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Build proxy state
    let tls_enabled = config.tls.enabled;
    let tls_file_config = config.tls.clone();
    let http_port = config.server.http_port;
    let drain_timeout = config.server.drain_timeout_seconds;
    let auth_config = config.auth.clone();
    let admin_config = config.admin.clone();
    let cb_enabled = config.circuit_breaker.enabled;
    let cb_interval_ms = config.circuit_breaker.health_check_interval_ms;
    let metrics_enabled = config.metrics.enabled;
    let state = ProxyState::new(config);

    // Set up auth state
    let auth_state = Arc::new(AuthState {
        key_manager: state.versioned_key_manager.clone(),
        issuer: auth_config.issuer.clone(),
        audience: auth_config.audience.clone(),
        public_paths: auth_config.public_paths.clone(),
    });

    let versioned_km = state.versioned_key_manager.clone();
    let metrics = state.metrics.clone();

    // ---- Build public proxy router (NO admin/auth endpoints) ----
    let mut app = Router::new()
        .route("/health", get({
            let m = metrics.clone();
            move || async move { health_handler(m.is_ready()).await }
        }))
        .route(
            "/.well-known/jwks.json",
            get({
                let km = versioned_km.clone();
                move || async move { Json(km.jwks()) }
            }),
        )
        .route("/ws/{*path}", any(ws_proxy_handler))
        .fallback(proxy_handler)
        .with_state(state.clone());

    // Readiness probe
    app = app.route("/ready", get({
        let m = metrics.clone();
        move || async move { readiness_handler(m.is_ready()).await }
    }));

    // Metrics endpoint on the public router (if enabled, read-only)
    if metrics_enabled {
        app = app.route("/metrics", get({
            let m = metrics.clone();
            move || async move {
                let body = m.render_prometheus();
                (
                    [(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    body,
                )
            }
        }));
    }

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

    // ---- Build admin router (separate listener, API-key protected) ----
    let admin_api_key = admin_config.effective_api_key();
    if admin_config.enabled {
        let admin_app = build_admin_router(
            state.clone(),
            auth_state.clone(),
            admin_api_key.clone(),
        );
        let admin_bind = format!("{}:{}", admin_config.bind_address, admin_config.port);
        tokio::spawn(async move {
            match TcpListener::bind(&admin_bind).await {
                Ok(listener) => {
                    info!(address = %admin_bind, "Admin listener started");
                    let _ = axum::serve(listener, admin_app)
                        .with_graceful_shutdown(shutdown_signal())
                        .await;
                }
                Err(e) => {
                    error!(error = %e, address = %admin_bind, "Failed to start admin listener");
                }
            }
        });
    }

    // Spawn health check background task
    if cb_enabled {
        let cb_for_health = state.circuit_breaker.clone();
        let interval = Duration::from_millis(cb_interval_ms);
        tokio::spawn(async move {
            circuit_breaker::run_health_checks(cb_for_health, interval).await;
        });
        info!("Circuit breaker health checks started");
    }

    // Spawn rate limiter cleanup task
    {
        let rl = state.rate_limiter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                rl.cleanup(Duration::from_secs(600));
            }
        });
    }

    if tls_enabled {
        start_with_tls(app, &tls_file_config, drain_timeout).await
    } else {
        start_plain(app, http_port).await
    }
}

/// Build the admin-only router with API key middleware.
fn build_admin_router(
    state: ProxyState,
    auth_state: Arc<AuthState>,
    api_key: Option<String>,
) -> Router {
    let versioned_km = state.versioned_key_manager.clone();
    let cb_manager = state.circuit_breaker.clone();
    let proxy_state = state.clone();
    let metrics = state.metrics.clone();
    let auth_for_token = auth_state.clone();

    let mut admin = Router::new()
        .route("/admin/health", get({
            let m = metrics.clone();
            move || async move { health_handler(m.is_ready()).await }
        }))
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
        .route(
            "/admin/metrics",
            get({
                let m = metrics.clone();
                move || async move { Json(m.to_json()) }
            }),
        )
        .route(
            "/admin/config",
            get({
                let ps = proxy_state.clone();
                move || async move {
                    let cfg = ps.config.load();
                    Json(json!({
                        "routes": cfg.routes.len(),
                        "rate_limit_enabled": cfg.rate_limit.enabled,
                        "circuit_breaker_enabled": cfg.circuit_breaker.enabled,
                        "auth_enabled": cfg.auth.enabled,
                    }))
                }
            }),
        )
        .route(
            "/admin/config/reload",
            post({
                let ps = proxy_state.clone();
                move |body: Json<serde_json::Value>| async move {
                    let json_str = serde_json::to_string(&*body).unwrap_or_default();
                    match GatewayConfig::from_json(&json_str) {
                        Ok(new_config) => {
                            let route_count = new_config.routes.len();
                            ps.reload_config(new_config);
                            Json(json!({
                                "status": "reloaded",
                                "routes": route_count,
                            }))
                        }
                        Err(e) => {
                            Json(json!({
                                "status": "error",
                                "error": e.to_string(),
                            }))
                        }
                    }
                }
            }),
        )
        .route(
            "/admin/routes",
            get({
                let ps = proxy_state.clone();
                move || async move {
                    let cfg = ps.config.load();
                    Json(json!({ "routes": cfg.routes }))
                }
            }),
        )
        .route(
            "/admin/routes/update",
            post({
                let ps = proxy_state.clone();
                move |body: Json<serde_json::Value>| async move {
                    // Accept {"routes": [...]} to update just routes
                    if let Some(routes_val) = body.get("routes") {
                        let routes_str = serde_json::to_string(routes_val).unwrap_or_default();
                        match serde_json::from_str::<Vec<pqc_proxy::config::RouteConfig>>(&routes_str) {
                            Ok(new_routes) => {
                                if new_routes.is_empty() {
                                    return Json(json!({"status": "error", "error": "empty routes"}));
                                }
                                let mut cfg: GatewayConfig = (*ps.config.load_full()).clone();
                                cfg.routes = new_routes;
                                let count = cfg.routes.len();
                                ps.reload_config(cfg);
                                Json(json!({"status": "updated", "routes": count}))
                            }
                            Err(e) => Json(json!({"status": "error", "error": e.to_string()})),
                        }
                    } else {
                        Json(json!({"status": "error", "error": "missing 'routes' field"}))
                    }
                }
            }),
        )
        // Auth token issuance + key rotation on admin listener
        .route(
            "/auth/token",
            post({
                let auth = auth_for_token.clone();
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
                        &auth.key_manager, sub, &roles,
                        &auth.issuer, &auth.audience, 3600,
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
        );

    // Apply API key middleware if configured
    if let Some(key) = api_key {
        admin = admin.layer(middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
            let expected = key.clone();
            async move {
                // Allow health checks without auth
                let path = req.uri().path().to_string();
                if path == "/admin/health" {
                    return next.run(req).await;
                }

                let provided = req.headers()
                    .get("x-api-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if provided == expected {
                    next.run(req).await
                } else {
                    warn!(path = %path, "Admin API key validation failed");
                    pqc_proxy::error::GatewayError::Unauthorized(
                        "invalid or missing API key".to_string()
                    ).into_response()
                }
            }
        }));
    }

    admin
}

/// Start the gateway with TLS (HTTPS) + graceful drain.
async fn start_with_tls(
    app: Router,
    tls_file_config: &pqc_proxy::config::TlsFileConfig,
    drain_timeout: u64,
) -> Result<()> {
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

    fips::log_compliance_report(tls_config.pqc_enabled);

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

    let app = Arc::new(app);
    // Use a watch channel to signal graceful shutdown to all connections
    let (shutdown_tx, _) = watch::channel(false);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    // Track in-flight connections for graceful drain
    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = result?;
                let acceptor = acceptor.clone();
                let app = app.clone();
                let mut shutdown_rx = shutdown_tx.subscribe();
                let conn_count = connection_count.clone();
                conn_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
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

                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            let service = hyper_util::service::TowerToHyperService::new((*app).clone());
                            let builder = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            );
                            let conn = builder.serve_connection(io, service);
                            tokio::pin!(conn);

                            // Graceful drain: wait for either connection completion or shutdown
                            loop {
                                tokio::select! {
                                    result = conn.as_mut() => {
                                        if let Err(e) = result {
                                            if !e.to_string().contains("connection reset") {
                                                error!(peer = %peer_addr, error = %e, "Connection error");
                                            }
                                        }
                                        break;
                                    }
                                    _ = shutdown_rx.changed() => {
                                        info!(peer = %peer_addr, "Draining TLS connection...");
                                        conn.as_mut().graceful_shutdown();
                                        // Continue polling until the connection finishes
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            info!(peer = %peer_addr, error = %e, "TLS handshake failed");
                        }
                    }
                    conn_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            _ = &mut shutdown => {
                info!("Shutting down TLS server — draining connections...");
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }

    // Wait for in-flight connections to drain (with timeout)
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(drain_timeout);
    while connection_count.load(std::sync::atomic::Ordering::Relaxed) > 0 {
        if tokio::time::Instant::now() > drain_deadline {
            let remaining = connection_count.load(std::sync::atomic::Ordering::Relaxed);
            warn!(remaining = remaining, "Drain timeout — forcing shutdown");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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

async fn health_handler(ready: bool) -> Json<serde_json::Value> {
    Json(json!({
        "status": if ready { "healthy" } else { "degraded" },
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
            "rate_limiting": "token-bucket",
            "hot_reload": "JSON API",
            "admin_listener": "separate port",
            "https_upstream": "TLS client",
            "load_balancing": "round-robin",
            "prometheus_metrics": "text exposition",
        },
    }))
}

async fn readiness_handler(ready: bool) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    if ready {
        (axum::http::StatusCode::OK, Json(json!({"ready": true})))
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ready": false})))
    }
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