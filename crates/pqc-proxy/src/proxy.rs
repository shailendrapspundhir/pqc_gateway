use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use hyper::header::{HeaderName, HeaderValue};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use pqc_tls::signature::{SignatureKeyManager, SignatureMode};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::config::GatewayConfig;
use crate::error::GatewayError;
use crate::router::RouteMatcher;

#[derive(Clone)]
pub struct ProxyState {
    pub matcher: RouteMatcher,
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    pub config: Arc<GatewayConfig>,
    pub signature_key_manager: SignatureKeyManager,
    pub default_signature_mode: SignatureMode,
    /// Env-var override (read once at startup).
    pub env_signature_mode: Option<String>,
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

        info!(
            route_count = config.routes.len(),
            default_sig_mode = %default_signature_mode,
            env_sig_override = ?env_signature_mode,
            sig_fingerprint = %signature_key_manager.fingerprint(),
            "Proxy initialized with routes and signature support"
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
        }
    }
}

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

            Response::from_parts(parts, Body::from(body_bytes))
        }
        Ok(Err(e)) => {
            error!(
                request_id = %request_id,
                route = %route_id,
                error = %e,
                "Upstream connection failed"
            );
            GatewayError::UpstreamConnection(e.to_string()).into_response()
        }
        Err(_) => {
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