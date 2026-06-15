use axum::body::Body;
use axum::extract::Request;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use hyper::header::{HeaderName, HeaderValue};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use pqc_tls::signature::{SignatureKeyManager, SignatureMode};
use pqc_tls::versioned_keys::VersionedKeyManager;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::body_integrity;
use crate::circuit_breaker::{CircuitBreakerConfig, CircuitBreakerManager, CircuitState};
use crate::config::GatewayConfig;
use crate::error::GatewayError;
use crate::router::RouteMatcher;
use crate::websocket;

#[derive(Clone)]
pub struct ProxyState {
    pub matcher: RouteMatcher,
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    pub config: Arc<GatewayConfig>,
    pub signature_key_manager: SignatureKeyManager,
    pub default_signature_mode: SignatureMode,
    /// Env-var override (read once at startup).
    pub env_signature_mode: Option<String>,
    /// Versioned key manager for JWKS and key rotation.
    pub versioned_key_manager: VersionedKeyManager,
    /// Circuit breaker manager for upstream health.
    pub circuit_breaker: CircuitBreakerManager,
}

impl ProxyState {
    pub fn new(config: GatewayConfig) -> Self {
        let matcher = RouteMatcher::new(&config.routes);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(32)
            .build_http();

        // Resolve global default signature mode from config
        let default_signature_mode = config
            .signatures
            .default_mode
            .parse::<SignatureMode>()
            .unwrap_or(SignatureMode::Classical);

        // Read env override once
        let env_signature_mode = std::env::var("PQC_SIGNATURE_MODE").ok();

        let signature_key_manager = SignatureKeyManager::generate();

        // Initialize versioned key manager (with optional threshold)
        let max_retained = config.threshold.max_retained_keys;
        let versioned_key_manager = if config.threshold.enabled {
            VersionedKeyManager::with_threshold(
                max_retained,
                config.threshold.threshold,
                config.threshold.total_shares,
            )
        } else {
            VersionedKeyManager::new(max_retained)
        };

        // Initialize circuit breaker
        let cb_config = CircuitBreakerConfig {
            failure_threshold: config.circuit_breaker.failure_threshold,
            recovery_timeout: Duration::from_millis(config.circuit_breaker.recovery_timeout_ms),
            health_check_interval: Duration::from_millis(
                config.circuit_breaker.health_check_interval_ms,
            ),
            health_check_path: config.circuit_breaker.health_check_path.clone(),
        };
        let circuit_breaker = CircuitBreakerManager::new(cb_config);

        // Register all upstreams with the circuit breaker
        for route in matcher.routes() {
            circuit_breaker.register_upstream(&route.upstream, None);
        }

        info!(
            route_count = config.routes.len(),
            default_sig_mode = %default_signature_mode,
            env_sig_override = ?env_signature_mode,
            sig_fingerprint = %signature_key_manager.fingerprint(),
            versioned_kid = %versioned_key_manager.current_kid(),
            cb_enabled = config.circuit_breaker.enabled,
            threshold_enabled = config.threshold.enabled,
            "Proxy initialized with routes, signatures, circuit breaker, and versioned keys"
        );
        for route in matcher.routes() {
            info!(
                id = %route.id,
                prefix = %route.path_prefix,
                upstream = %route.upstream,
                methods = ?route.methods,
                sig_mode = ?route.signature_mode,
                "  Route registered"
            );
        }

        Self {
            matcher,
            client,
            config: Arc::new(config),
            signature_key_manager,
            default_signature_mode,
            env_signature_mode,
            versioned_key_manager,
            circuit_breaker,
        }
    }
}

/// WebSocket-capable proxy handler, use with `any()` on WebSocket routes.
pub async fn ws_proxy_handler(
    state: axum::extract::State<ProxyState>,
    ws: WebSocketUpgrade,
    req: Request,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str();

    if let Some((route, _)) = state.matcher.match_route(&path, method) {
        let ws_url = websocket::build_upstream_ws_url(route, &path);
        info!(upstream_ws = %ws_url, "WebSocket upgrade → tunnel");
        return websocket::ws_upgrade_handler(ws, ws_url).await;
    }

    GatewayError::NoRouteMatch.into_response()
}

/// Standard proxy handler for non-WebSocket requests.
pub async fn proxy_handler(
    state: axum::extract::State<ProxyState>,
    mut req: Request,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // Match route
    let (route, upstream_path) = match state.matcher.match_route(&path, method.as_str()) {
        Some(result) => result,
        None => {
            warn!(path = %path, method = %method, "No route matched");
            return GatewayError::NoRouteMatch.into_response();
        }
    };

    let route_id = route.id.clone();
    let upstream_base = route.upstream.clone();
    let timeout_ms = route.timeout_ms;

    // ---- Circuit breaker check ----
    if state.config.circuit_breaker.enabled {
        if let Err(CircuitState::Open) = state.circuit_breaker.check_request(&upstream_base) {
            warn!(
                request_id = %request_id,
                route = %route_id,
                upstream = %upstream_base,
                "Circuit breaker open — upstream unavailable"
            );
            return GatewayError::UpstreamConnection(
                "circuit breaker open: upstream temporarily unavailable".to_string(),
            )
            .into_response();
        }
    }

    // Resolve effective signature mode for this route
    let effective_sig_mode = SignatureMode::resolve(
        state.env_signature_mode.as_deref(),
        route.signature_mode,
        state.default_signature_mode,
    );

    // Build upstream URI
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let upstream_uri = format!("{upstream_base}{upstream_path}{query}");

    info!(
        request_id = %request_id,
        route = %route_id,
        upstream = %upstream_uri,
        method = %method,
        "Proxying request"
    );

    // Rewrite the request URI
    let uri: hyper::Uri = match upstream_uri.parse() {
        Ok(uri) => uri,
        Err(e) => {
            error!(error = %e, "Failed to parse upstream URI");
            return GatewayError::Internal(format!("bad upstream URI: {e}")).into_response();
        }
    };
    *req.uri_mut() = uri;

    // Add forwarding headers
    let headers = req.headers_mut();
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        headers.insert(HeaderName::from_static("x-request-id"), val);
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("http"),
    );
    // Remove the host header so hyper sets the correct one for the upstream
    headers.remove(hyper::header::HOST);

    // Send request to upstream with timeout
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let result = tokio::time::timeout(timeout, state.client.request(req)).await;

    match result {
        Ok(Ok(response)) => {
            let status = response.status();

            // Record circuit breaker success/failure based on status
            if state.config.circuit_breaker.enabled {
                if status.is_server_error() {
                    state.circuit_breaker.record_failure(&upstream_base);
                } else {
                    state.circuit_breaker.record_success(&upstream_base);
                }
            }

            info!(
                request_id = %request_id,
                route = %route_id,
                status = %status,
                sig_mode = %effective_sig_mode,
                "Upstream response received"
            );

            // Convert hyper response to axum response
            let (mut parts, body) = response.into_parts();
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    error!(error = %e, "Failed to read upstream response body");
                    return GatewayError::UpstreamConnection(e.to_string()).into_response();
                }
            };

            // Apply PQC signature if mode is not Classical
            if let Some(sig_output) = state.signature_key_manager.sign(effective_sig_mode, &body_bytes) {
                if let Ok(v) = HeaderValue::from_str(&sig_output.algorithm) {
                    parts.headers.insert(
                        HeaderName::from_static("x-pqc-signature-algorithm"),
                        v,
                    );
                }
                if let Ok(v) = HeaderValue::from_str(&sig_output.pqc_signature) {
                    parts.headers.insert(
                        HeaderName::from_static("x-pqc-signature"),
                        v,
                    );
                }
                if let Some(ref classical) = sig_output.classical_signature {
                    if let Ok(v) = HeaderValue::from_str(classical) {
                        parts.headers.insert(
                            HeaderName::from_static("x-pqc-signature-classical"),
                            v,
                        );
                    }
                }
                if let Ok(v) = HeaderValue::from_str(&sig_output.content_digest) {
                    parts.headers.insert(
                        HeaderName::from_static("x-pqc-content-digest"),
                        v,
                    );
                }
                if let Ok(v) = HeaderValue::from_str(&sig_output.public_key_fingerprint) {
                    parts.headers.insert(
                        HeaderName::from_static("x-pqc-public-key-fingerprint"),
                        v,
                    );
                }
            }

            // Also sign with versioned key manager (ML-DSA-65 only)
            body_integrity::sign_response_body(
                &state.versioned_key_manager,
                &body_bytes,
                &mut parts.headers,
            );

            Response::from_parts(parts, Body::from(body_bytes))
        }
        Ok(Err(e)) => {
            // Record circuit breaker failure
            if state.config.circuit_breaker.enabled {
                state.circuit_breaker.record_failure(&upstream_base);
            }
            error!(
                request_id = %request_id,
                route = %route_id,
                error = %e,
                "Upstream connection failed"
            );
            GatewayError::UpstreamConnection(e.to_string()).into_response()
        }
        Err(_) => {
            // Record circuit breaker failure on timeout
            if state.config.circuit_breaker.enabled {
                state.circuit_breaker.record_failure(&upstream_base);
            }
            warn!(
                request_id = %request_id,
                route = %route_id,
                timeout_ms = timeout_ms,
                "Upstream request timed out"
            );
            GatewayError::UpstreamTimeout(format!("timeout after {timeout_ms}ms")).into_response()
        }
    }
}