use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
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
use crate::metrics::{GatewayMetrics, RequestTimer};
use crate::rate_limiter::{RateLimitKey, RateLimitResult, RateLimiter};
use crate::router::{LoadBalancer, RouteMatcher};
use crate::websocket;

/// HTTPS-capable connector type.
type HttpsConnector = hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

#[derive(Clone)]
pub struct ProxyState {
    /// Current route matcher — swapped on config reload.
    pub matcher: Arc<ArcSwap<RouteMatcher>>,
    /// HTTP client (plain).
    pub http_client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    /// HTTPS client.
    pub https_client: Client<HttpsConnector, Body>,
    /// Current config — swapped on reload.
    pub config: Arc<ArcSwap<GatewayConfig>>,
    pub signature_key_manager: SignatureKeyManager,
    pub default_signature_mode: SignatureMode,
    /// Env-var override (read once at startup).
    pub env_signature_mode: Option<String>,
    /// Versioned key manager for JWKS and key rotation.
    pub versioned_key_manager: VersionedKeyManager,
    /// Circuit breaker manager for upstream health.
    pub circuit_breaker: CircuitBreakerManager,
    /// Rate limiter.
    pub rate_limiter: RateLimiter,
    /// Metrics.
    pub metrics: GatewayMetrics,
    /// Load balancer.
    pub load_balancer: Arc<LoadBalancer>,
    /// Per-route mTLS clients (route_id → HTTPS client with client certs).
    pub mtls_clients: Arc<DashMap<String, Client<HttpsConnector, Body>>>,
}

impl ProxyState {
    pub fn new(config: GatewayConfig) -> Self {
        let matcher = RouteMatcher::new(&config.routes);
        let http_client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(32)
            .build_http();

        // Build HTTPS client
        let https_connector = build_https_connector();
        let https_client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(32)
            .build(https_connector);

        // Resolve global default signature mode from config
        let default_signature_mode = config
            .signatures
            .default_mode
            .parse::<SignatureMode>()
            .unwrap_or(SignatureMode::Classical);

        // Read env override once; support GATEWAY_SIGNING_KEY for signing key from env
        let env_signature_mode = std::env::var("PQC_SIGNATURE_MODE").ok();

        let signature_key_manager = if let Ok(seed_hex) = std::env::var("GATEWAY_SIGNING_KEY") {
            SignatureKeyManager::from_seed_hex(&seed_hex)
                .unwrap_or_else(|_| SignatureKeyManager::generate())
        } else {
            SignatureKeyManager::generate()
        };

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

        // Register all upstreams with the circuit breaker (including LB endpoints)
        for route in matcher.routes() {
            for upstream in &route.upstreams {
                circuit_breaker.register_upstream(upstream, None);
            }
        }

        // Rate limiter
        let rate_limiter = RateLimiter::new(
            config.rate_limit.default_requests,
            config.rate_limit.default_window_seconds,
        );

        let metrics = GatewayMetrics::new();

        // Build per-route mTLS clients
        let mtls_clients = Arc::new(DashMap::new());
        for route_cfg in &config.routes {
            if let Some(ref mtls) = route_cfg.mtls {
                if mtls.enabled {
                    match build_mtls_connector(mtls) {
                        Ok(connector) => {
                            let client = Client::builder(TokioExecutor::new())
                                .pool_idle_timeout(Duration::from_secs(30))
                                .pool_max_idle_per_host(32)
                                .build(connector);
                            mtls_clients.insert(route_cfg.id.clone(), client);
                            info!(route = %route_cfg.id, "mTLS client configured");
                        }
                        Err(e) => {
                            error!(route = %route_cfg.id, error = %e, "Failed to build mTLS client");
                        }
                    }
                }
            }
        }

        info!(
            route_count = config.routes.len(),
            default_sig_mode = %default_signature_mode,
            env_sig_override = ?env_signature_mode,
            sig_fingerprint = %signature_key_manager.fingerprint(),
            versioned_kid = %versioned_key_manager.current_kid(),
            cb_enabled = config.circuit_breaker.enabled,
            threshold_enabled = config.threshold.enabled,
            rate_limit_enabled = config.rate_limit.enabled,
            "Proxy initialized"
        );
        for route in matcher.routes() {
            info!(
                id = %route.id,
                prefix = %route.path_prefix,
                upstreams = ?route.upstreams,
                methods = ?route.methods,
                sig_mode = ?route.signature_mode,
                "  Route registered"
            );
        }

        Self {
            matcher: Arc::new(ArcSwap::from_pointee(matcher)),
            http_client,
            https_client,
            config: Arc::new(ArcSwap::from_pointee(config)),
            signature_key_manager,
            default_signature_mode,
            env_signature_mode,
            versioned_key_manager,
            circuit_breaker,
            rate_limiter,
            metrics,
            load_balancer: Arc::new(LoadBalancer::new()),
            mtls_clients,
        }
    }

    /// Reload config — swaps route matcher and config atomically.
    /// Existing connections continue using old routes until they complete.
    pub fn reload_config(&self, new_config: GatewayConfig) {
        let new_matcher = RouteMatcher::new(&new_config.routes);

        // Register any new upstreams with circuit breaker
        for route in new_matcher.routes() {
            for upstream in &route.upstreams {
                self.circuit_breaker.register_upstream(upstream, None);
            }
        }

        self.matcher.store(Arc::new(new_matcher));
        self.config.store(Arc::new(new_config));

        info!("Configuration reloaded — new routes active for next requests");
    }
}

fn build_https_connector() -> HttpsConnector {
    let roots = rustls::RootCertStore::empty();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build()
}

/// Build an HTTPS connector with client certificate authentication (mTLS).
fn build_mtls_connector(
    mtls_cfg: &crate::config::RouteMtlsConfig,
) -> Result<HttpsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();

    // Load custom CA if provided
    if let Some(ref ca_path) = mtls_cfg.ca_file {
        let ca_data = std::fs::read(ca_path)
            .map_err(|e| format!("failed to read CA file {ca_path}: {e}"))?;
        let ca_certs = rustls_pemfile::certs(&mut std::io::BufReader::new(&ca_data[..]))
            .filter_map(|c| c.ok())
            .collect::<Vec<_>>();
        for cert in ca_certs {
            roots.add(cert).map_err(|e| format!("failed to add CA cert: {e}"))?;
        }
    }

    let tls_config = if let (Some(ref cert_path), Some(ref key_path)) =
        (&mtls_cfg.client_cert_file, &mtls_cfg.client_key_file)
    {
        // Load client certificate chain
        let cert_data = std::fs::read(cert_path)
            .map_err(|e| format!("failed to read client cert {cert_path}: {e}"))?;
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_data[..]))
            .filter_map(|c| c.ok())
            .collect::<Vec<_>>();

        // Load client private key
        let key_data = std::fs::read(key_path)
            .map_err(|e| format!("failed to read client key {key_path}: {e}"))?;
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&key_data[..]))
            .map_err(|e| format!("failed to parse client key: {e}"))?
            .ok_or_else(|| "no private key found in client key file".to_string())?;

        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("mTLS client config error: {e}"))?
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    Ok(hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build())
}

/// WebSocket-capable proxy handler.
pub async fn ws_proxy_handler(
    state: axum::extract::State<ProxyState>,
    ws: WebSocketUpgrade,
    req: Request,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().as_str();

    let matcher = state.matcher.load();
    if let Some((route, _)) = matcher.match_route(&path, method) {
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
    let timer = RequestTimer::start();
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // Extract client IP for rate limiting
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Load current config snapshot
    let config = state.config.load();
    let matcher = state.matcher.load();

    // Match route
    let (route, upstream_path) = match matcher.match_route(&path, method.as_str()) {
        Some(result) => result,
        None => {
            warn!(path = %path, method = %method, "No route matched");
            return GatewayError::NoRouteMatch.into_response();
        }
    };

    let route_id = route.id.clone();
    let timeout_ms = route.timeout_ms;
    let route_upstreams = route.upstreams.clone();
    let route_sig_mode = route.signature_mode;
    let route_rate_limit = route.rate_limit;
    let route_max_body = route.max_request_body_bytes;
    let upstream_tls = route.upstream_tls;

    // ---- Request body size check ----
    let max_body = route_max_body.unwrap_or(config.server.max_request_body_bytes);
    if let Some(content_length) = req.headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if content_length > max_body {
            warn!(
                request_id = %request_id,
                content_length = content_length,
                max = max_body,
                "Request body too large"
            );
            return GatewayError::BodyTooLarge(max_body).into_response();
        }
    }

    // ---- Rate limiting ----
    if config.rate_limit.enabled {
        let key = RateLimitKey {
            route_id: route_id.clone(),
            client_ip: client_ip.clone(),
        };
        if let RateLimitResult::Limited { retry_after_secs } =
            state.rate_limiter.check(&key, route_rate_limit)
        {
            state.metrics.record_rate_limit_rejection();
            let mut resp = GatewayError::RateLimited.into_response();
            if let Ok(val) = HeaderValue::from_str(&format!("{}", retry_after_secs.ceil() as u64)) {
                resp.headers_mut().insert("retry-after", val);
            }
            return resp;
        }
    }

    // ---- Load-balance: pick upstream ----
    let upstream_base = state.load_balancer.next_upstream(&route_upstreams).to_string();

    // ---- Circuit breaker check ----
    if config.circuit_breaker.enabled {
        if let Err(CircuitState::Open) = state.circuit_breaker.check_request(&upstream_base) {
            state.metrics.record_circuit_breaker_rejection();
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
        route_sig_mode,
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
    let proto = if upstream_tls { "https" } else { "http" };
    if let Ok(val) = HeaderValue::from_str(proto) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), val);
    }
    headers.remove(hyper::header::HOST);

    // Send request to upstream with timeout
    // Use mTLS client if configured for this route, otherwise standard client
    let timeout = Duration::from_millis(timeout_ms);
    let result = if let Some(mtls_client) = state.mtls_clients.get(&route_id) {
        tokio::time::timeout(timeout, mtls_client.request(req)).await
    } else if upstream_tls {
        tokio::time::timeout(timeout, state.https_client.request(req)).await
    } else {
        tokio::time::timeout(timeout, state.http_client.request(req)).await
    };

    match result {
        Ok(Ok(response)) => {
            let status = response.status();

            // Record circuit breaker success/failure based on status
            if config.circuit_breaker.enabled {
                if status.is_server_error() {
                    state.circuit_breaker.record_failure(&upstream_base);
                } else {
                    state.circuit_breaker.record_success(&upstream_base);
                }
            }

            let duration_ms = timer.elapsed_ms();
            state.metrics.record_request(&route_id, method.as_str(), status.as_u16(), duration_ms);

            info!(
                request_id = %request_id,
                route = %route_id,
                status = %status,
                sig_mode = %effective_sig_mode,
                duration_ms = duration_ms,
                "Upstream response received"
            );

            // Convert hyper response to axum response
            let (mut parts, body) = response.into_parts();
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    error!(error = %e, "Failed to read upstream response body");
                    state.metrics.record_upstream_failure();
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
            if config.circuit_breaker.enabled {
                state.circuit_breaker.record_failure(&upstream_base);
            }
            state.metrics.record_upstream_failure();
            let duration_ms = timer.elapsed_ms();
            state.metrics.record_request(&route_id, method.as_str(), 502, duration_ms);
            error!(
                request_id = %request_id,
                route = %route_id,
                error = %e,
                "Upstream connection failed"
            );
            GatewayError::UpstreamConnection(e.to_string()).into_response()
        }
        Err(_) => {
            if config.circuit_breaker.enabled {
                state.circuit_breaker.record_failure(&upstream_base);
            }
            state.metrics.record_upstream_failure();
            let duration_ms = timer.elapsed_ms();
            state.metrics.record_request(&route_id, method.as_str(), 504, duration_ms);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_crypto() {
        INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn minimal_config() -> GatewayConfig {
        GatewayConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1".to_string(),
                http_port: 0,
                drain_timeout_seconds: 5,
                max_request_body_bytes: 1024,
            },
            logging: LoggingConfig {
                level: "error".to_string(),
                format: "pretty".to_string(),
            },
            tls: TlsFileConfig::default(),
            signatures: SignaturesConfig::default(),
            auth: AuthConfig::default(),
            admin: AdminConfig::default(),
            circuit_breaker: CircuitBreakerFileConfig { enabled: false, ..Default::default() },
            threshold: ThresholdConfig::default(),
            rate_limit: RateLimitConfig { enabled: true, default_requests: 100, default_window_seconds: 60 },
            metrics: MetricsConfig { enabled: true, path: "/metrics".to_string() },
            routes: vec![RouteConfig {
                id: "test".to_string(),
                path_prefix: "/api".to_string(),
                upstream: "http://127.0.0.1:19999".to_string(),
                upstreams: vec![],
                strip_prefix: false,
                methods: vec!["GET".to_string(), "POST".to_string()],
                timeout_ms: 5000,
                signature_mode: None,
                rate_limit: None,
                max_request_body_bytes: None,
                mtls: None,
                upstream_tls: false,
            }],
        }
    }

    #[test]
    fn test_proxy_state_new() {
        init_crypto();
        let state = ProxyState::new(minimal_config());
        assert_eq!(state.metrics.total_requests(), 0);
        assert!(state.metrics.is_ready());
    }

    #[test]
    fn test_proxy_state_reload_config() {
        init_crypto();
        let state = ProxyState::new(minimal_config());
        let matcher = state.matcher.load();
        assert_eq!(matcher.routes().len(), 1);

        // Reload with 2 routes
        let mut new_cfg = minimal_config();
        new_cfg.routes.push(RouteConfig {
            id: "second".to_string(),
            path_prefix: "/api/v2".to_string(),
            upstream: "http://127.0.0.1:19998".to_string(),
            upstreams: vec![],
            strip_prefix: false,
            methods: vec!["GET".to_string()],
            timeout_ms: 3000,
            signature_mode: None,
            rate_limit: None,
            max_request_body_bytes: None,
            mtls: None,
            upstream_tls: false,
        });
        state.reload_config(new_cfg);

        let matcher = state.matcher.load();
        assert_eq!(matcher.routes().len(), 2);
    }

    #[test]
    fn test_proxy_state_env_signing_key() {
        // Test that from_seed_hex works
        let km = SignatureKeyManager::generate();
        let seed = km.seed_hex();
        let km2 = SignatureKeyManager::from_seed_hex(&seed).unwrap();
        let data = b"test data";
        let sig = km2.sign(SignatureMode::MlDsaOnly, data).unwrap();
        assert!(km2.verify(data, &sig));
    }

    #[test]
    fn test_proxy_state_config_swap_atomicity() {
        init_crypto();
        let state = ProxyState::new(minimal_config());

        // Read config before reload
        let cfg_before = state.config.load();
        assert_eq!(cfg_before.routes.len(), 1);

        // Reload
        let mut new_cfg = minimal_config();
        new_cfg.routes.push(RouteConfig {
            id: "new-route".to_string(),
            path_prefix: "/new".to_string(),
            upstream: "http://127.0.0.1:19997".to_string(),
            upstreams: vec![],
            strip_prefix: false,
            methods: vec![],
            timeout_ms: 5000,
            signature_mode: None,
            rate_limit: None,
            max_request_body_bytes: None,
            mtls: None,
            upstream_tls: false,
        });
        state.reload_config(new_cfg);

        // Old reference still valid with old data
        assert_eq!(cfg_before.routes.len(), 1);
        // New load sees new data
        let cfg_after = state.config.load();
        assert_eq!(cfg_after.routes.len(), 2);
    }

    #[test]
    fn test_proxy_state_rate_limiter() {
        init_crypto();
        let state = ProxyState::new(minimal_config());
        let key = crate::rate_limiter::RateLimitKey {
            route_id: "test".to_string(),
            client_ip: "127.0.0.1".to_string(),
        };
        // Should be allowed within limits
        for _ in 0..100 {
            assert!(matches!(
                state.rate_limiter.check(&key, None),
                crate::rate_limiter::RateLimitResult::Allowed
            ));
        }
        // 101st should be blocked
        assert!(matches!(
            state.rate_limiter.check(&key, None),
            crate::rate_limiter::RateLimitResult::Limited { .. }
        ));
    }

    #[test]
    fn test_proxy_state_metrics_recording() {
        init_crypto();
        let state = ProxyState::new(minimal_config());
        state.metrics.record_request("test", "GET", 200, 10);
        state.metrics.record_request("test", "GET", 500, 5);
        state.metrics.record_upstream_failure();
        state.metrics.record_rate_limit_rejection();
        state.metrics.record_circuit_breaker_rejection();
        assert_eq!(state.metrics.total_requests(), 2);

        let prom = state.metrics.render_prometheus();
        assert!(prom.contains("gateway_requests_total"));
        assert!(prom.contains("gateway_upstream_failures_total 1"));
    }

    #[test]
    fn test_proxy_state_load_balancer() {
        init_crypto();
        let state = ProxyState::new(minimal_config());
        let upstreams = vec![
            "http://a:9001".to_string(),
            "http://b:9001".to_string(),
        ];
        let first = state.load_balancer.next_upstream(&upstreams);
        let second = state.load_balancer.next_upstream(&upstreams);
        assert_ne!(first, second);
    }

    #[test]
    fn test_config_from_json_full() {
        let json = serde_json::json!({
            "server": {"bind_address": "0.0.0.0", "http_port": 8080, "drain_timeout_seconds": 60, "max_request_body_bytes": 5242880},
            "logging": {"level": "debug", "format": "json"},
            "admin": {"enabled": true, "bind_address": "127.0.0.1", "port": 9090, "api_key": "secret-key"},
            "rate_limit": {"enabled": true, "default_requests": 500, "default_window_seconds": 30},
            "metrics": {"enabled": true, "path": "/metrics"},
            "routes": [
                {
                    "id": "svc1",
                    "path_prefix": "/api/v1",
                    "upstream": "http://localhost:9001",
                    "upstreams": ["http://localhost:9002", "http://localhost:9003"],
                    "methods": ["GET", "POST"],
                    "timeout_ms": 10000,
                    "rate_limit": {"requests": 50, "window_seconds": 10},
                    "max_request_body_bytes": 1048576,
                    "upstream_tls": false
                }
            ]
        });
        let cfg = GatewayConfig::from_json(&serde_json::to_string(&json).unwrap()).unwrap();
        assert_eq!(cfg.server.drain_timeout_seconds, 60);
        assert_eq!(cfg.server.max_request_body_bytes, 5242880);
        assert_eq!(cfg.admin.api_key, Some("secret-key".to_string()));
        assert!(cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.default_requests, 500);
        assert_eq!(cfg.routes[0].all_upstreams().len(), 3);
        assert_eq!(cfg.routes[0].rate_limit.as_ref().unwrap().requests, 50);
        assert_eq!(cfg.routes[0].max_request_body_bytes, Some(1048576));
    }

    #[test]
    fn test_config_validate_empty_upstream() {
        let json = serde_json::json!({
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{"id": "r1", "path_prefix": "/api", "upstream": ""}]
        });
        let result = GatewayConfig::from_json(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_empty_prefix() {
        let json = serde_json::json!({
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{"id": "r1", "path_prefix": "", "upstream": "http://localhost:9001"}]
        });
        let result = GatewayConfig::from_json(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = minimal_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2 = GatewayConfig::from_json(&json).unwrap();
        assert_eq!(cfg2.routes.len(), cfg.routes.len());
        assert_eq!(cfg2.server.http_port, cfg.server.http_port);
        assert_eq!(cfg2.rate_limit.enabled, cfg.rate_limit.enabled);
    }

    #[test]
    fn test_mtls_config_deserialization() {
        let json = serde_json::json!({
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{
                "id": "mtls-svc",
                "path_prefix": "/secure",
                "upstream": "https://secure.internal:443",
                "upstream_tls": true,
                "mtls": {
                    "enabled": true,
                    "ca_file": "/certs/ca.pem",
                    "client_cert_file": "/certs/client.pem",
                    "client_key_file": "/certs/client-key.pem"
                }
            }]
        });
        let cfg = GatewayConfig::from_json(&serde_json::to_string(&json).unwrap()).unwrap();
        let mtls = cfg.routes[0].mtls.as_ref().unwrap();
        assert!(mtls.enabled);
        assert_eq!(mtls.ca_file.as_deref(), Some("/certs/ca.pem"));
        assert_eq!(mtls.client_cert_file.as_deref(), Some("/certs/client.pem"));
        assert!(cfg.routes[0].upstream_tls);
    }

    #[test]
    fn test_signing_key_seed_roundtrip() {
        let km = SignatureKeyManager::generate();
        let seed = km.seed_hex();
        assert_eq!(seed.len(), 64); // 32 bytes = 64 hex chars
        let km2 = SignatureKeyManager::from_seed_hex(&seed).unwrap();
        // Both should produce valid signatures
        let data = b"roundtrip test";
        let sig1 = km.sign(SignatureMode::MlDsaOnly, data).unwrap();
        let sig2 = km2.sign(SignatureMode::MlDsaOnly, data).unwrap();
        assert!(km.verify(data, &sig1));
        assert!(km2.verify(data, &sig2));
        // Cross-verify: km2 should verify its own signature
        assert!(km2.verify(data, &sig2));
    }

    #[test]
    fn test_signing_key_invalid_hex() {
        assert!(SignatureKeyManager::from_seed_hex("not-valid-hex").is_err());
        assert!(SignatureKeyManager::from_seed_hex("").is_err());
        assert!(SignatureKeyManager::from_seed_hex("aabb").is_err()); // too short for ML-DSA seed
    }
}