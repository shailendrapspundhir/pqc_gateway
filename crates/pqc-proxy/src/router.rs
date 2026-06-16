use pqc_tls::signature::SignatureMode;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::RouteConfig;

#[derive(Debug, Clone)]
pub struct Route {
    pub id: String,
    pub path_prefix: String,
    /// All upstream URLs for load balancing.
    pub upstreams: Vec<String>,
    /// Primary upstream (first entry).
    pub upstream: String,
    pub strip_prefix: bool,
    pub methods: Vec<String>,
    pub timeout_ms: u64,
    /// Per-route signature mode override (None = use global default).
    pub signature_mode: Option<SignatureMode>,
    /// Per-route rate limit (requests, window_seconds).
    pub rate_limit: Option<(u32, u64)>,
    /// Per-route max request body size.
    pub max_request_body_bytes: Option<u64>,
    /// Whether upstream uses TLS.
    pub upstream_tls: bool,
}

impl From<&RouteConfig> for Route {
    fn from(cfg: &RouteConfig) -> Self {
        let signature_mode = cfg
            .signature_mode
            .as_deref()
            .and_then(|s| s.parse::<SignatureMode>().ok());
        let upstreams = cfg.all_upstreams();
        let rate_limit = cfg.rate_limit.as_ref().map(|rl| (rl.requests, rl.window_seconds));
        Self {
            id: cfg.id.clone(),
            path_prefix: cfg.path_prefix.clone(),
            upstream: upstreams[0].clone(),
            upstreams,
            strip_prefix: cfg.strip_prefix,
            methods: cfg.methods.iter().map(|m| m.to_uppercase()).collect(),
            timeout_ms: cfg.timeout_ms,
            signature_mode,
            rate_limit,
            max_request_body_bytes: cfg.max_request_body_bytes,
            upstream_tls: cfg.upstream_tls,
        }
    }
}

/// Round-robin load balancer for routes with multiple upstreams.
pub struct LoadBalancer {
    counter: AtomicUsize,
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self { counter: AtomicUsize::new(0) }
    }

    /// Pick the next upstream from the list using round-robin.
    pub fn next_upstream<'a>(&self, upstreams: &'a [String]) -> &'a str {
        if upstreams.len() <= 1 {
            return &upstreams[0];
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % upstreams.len();
        &upstreams[idx]
    }
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RouteMatcher {
    routes: Vec<Route>,
}

impl RouteMatcher {
    pub fn new(configs: &[RouteConfig]) -> Self {
        let mut routes: Vec<Route> = configs.iter().map(Route::from).collect();
        // Sort by prefix length descending so longer (more specific) prefixes match first.
        routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
        Self { routes }
    }

    /// Find the matching route for a given path and method.
    /// Returns the matched Route and the rewritten upstream path.
    pub fn match_route(&self, path: &str, method: &str) -> Option<(&Route, String)> {
        let method_upper = method.to_uppercase();

        for route in &self.routes {
            if path.starts_with(&route.path_prefix) || path == route.path_prefix.trim_end_matches('/') {
                // Check method
                if !route.methods.is_empty() && !route.methods.contains(&method_upper) {
                    continue;
                }

                let upstream_path = if route.strip_prefix {
                    let stripped = path.strip_prefix(&route.path_prefix).unwrap_or("");
                    if stripped.is_empty() || stripped.starts_with('/') {
                        stripped.to_string()
                    } else {
                        format!("/{stripped}")
                    }
                } else {
                    path.to_string()
                };

                return Some((route, upstream_path));
            }
        }
        None
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteConfig;

    fn make_route(id: &str, prefix: &str, upstream: &str, methods: &[&str]) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            path_prefix: prefix.to_string(),
            upstream: upstream.to_string(),
            upstreams: vec![],
            strip_prefix: false,
            methods: methods.iter().map(|s| s.to_string()).collect(),
            timeout_ms: 5000,
            signature_mode: None,
            rate_limit: None,
            max_request_body_bytes: None,
            mtls: None,
            upstream_tls: false,
        }
    }

    #[test]
    fn test_exact_prefix_match() {
        let routes = vec![make_route("r1", "/api/v1/items", "http://localhost:9001", &["GET", "POST"])];
        let matcher = RouteMatcher::new(&routes);

        let result = matcher.match_route("/api/v1/items", "GET");
        assert!(result.is_some());
        let (route, _) = result.unwrap();
        assert_eq!(route.id, "r1");
    }

    #[test]
    fn test_prefix_with_subpath() {
        let routes = vec![make_route("r1", "/api/v1/items", "http://localhost:9001", &["GET"])];
        let matcher = RouteMatcher::new(&routes);

        let result = matcher.match_route("/api/v1/items/123", "GET");
        assert!(result.is_some());
    }

    #[test]
    fn test_method_mismatch() {
        let routes = vec![make_route("r1", "/api/v1/items", "http://localhost:9001", &["GET"])];
        let matcher = RouteMatcher::new(&routes);

        let result = matcher.match_route("/api/v1/items", "DELETE");
        assert!(result.is_none());
    }

    #[test]
    fn test_no_match() {
        let routes = vec![make_route("r1", "/api/v1/items", "http://localhost:9001", &["GET"])];
        let matcher = RouteMatcher::new(&routes);

        let result = matcher.match_route("/unknown/path", "GET");
        assert!(result.is_none());
    }

    #[test]
    fn test_longer_prefix_wins() {
        let routes = vec![
            make_route("short", "/api", "http://short:9001", &["GET"]),
            make_route("long", "/api/v1/items", "http://long:9002", &["GET"]),
        ];
        let matcher = RouteMatcher::new(&routes);

        let (route, _) = matcher.match_route("/api/v1/items/42", "GET").unwrap();
        assert_eq!(route.id, "long");
    }

    #[test]
    fn test_strip_prefix() {
        let routes = vec![RouteConfig {
            id: "r1".to_string(),
            path_prefix: "/api/v1/items".to_string(),
            upstream: "http://localhost:9001".to_string(),
            upstreams: vec![],
            strip_prefix: true,
            methods: vec!["GET".to_string()],
            timeout_ms: 5000,
            signature_mode: None,
            rate_limit: None,
            max_request_body_bytes: None,
            mtls: None,
            upstream_tls: false,
        }];
        let matcher = RouteMatcher::new(&routes);

        let (_, upstream_path) = matcher.match_route("/api/v1/items/42", "GET").unwrap();
        assert_eq!(upstream_path, "/42");
    }

    #[test]
    fn test_route_with_signature_mode() {
        let mut cfg = make_route("r1", "/api/v1/items", "http://localhost:9001", &["GET"]);
        cfg.signature_mode = Some("hybrid".to_string());
        let routes = vec![cfg];
        let matcher = RouteMatcher::new(&routes);
        let (route, _) = matcher.match_route("/api/v1/items", "GET").unwrap();
        assert_eq!(route.signature_mode, Some(SignatureMode::Hybrid));
    }

    #[test]
    fn test_route_without_signature_mode() {
        let routes = vec![make_route("r1", "/api/v1/items", "http://localhost:9001", &["GET"])];
        let matcher = RouteMatcher::new(&routes);
        let (route, _) = matcher.match_route("/api/v1/items", "GET").unwrap();
        assert!(route.signature_mode.is_none());
    }

    #[test]
    fn test_load_balancer_round_robin() {
        let lb = LoadBalancer::new();
        let upstreams = vec![
            "http://a:9001".to_string(),
            "http://b:9001".to_string(),
            "http://c:9001".to_string(),
        ];
        assert_eq!(lb.next_upstream(&upstreams), "http://a:9001");
        assert_eq!(lb.next_upstream(&upstreams), "http://b:9001");
        assert_eq!(lb.next_upstream(&upstreams), "http://c:9001");
        assert_eq!(lb.next_upstream(&upstreams), "http://a:9001");
    }

    #[test]
    fn test_load_balancer_single() {
        let lb = LoadBalancer::new();
        let upstreams = vec!["http://only:9001".to_string()];
        assert_eq!(lb.next_upstream(&upstreams), "http://only:9001");
        assert_eq!(lb.next_upstream(&upstreams), "http://only:9001");
    }

    #[test]
    fn test_route_multiple_upstreams() {
        let mut cfg = make_route("r1", "/api", "http://a:9001", &["GET"]);
        cfg.upstreams = vec!["http://b:9001".to_string()];
        let routes = vec![cfg];
        let matcher = RouteMatcher::new(&routes);
        let (route, _) = matcher.match_route("/api/test", "GET").unwrap();
        assert_eq!(route.upstreams.len(), 2);
    }

    #[test]
    fn test_empty_methods_matches_any() {
        let routes = vec![make_route("r1", "/api", "http://localhost:9001", &[])];
        let matcher = RouteMatcher::new(&routes);
        assert!(matcher.match_route("/api/test", "GET").is_some());
        assert!(matcher.match_route("/api/test", "POST").is_some());
        assert!(matcher.match_route("/api/test", "DELETE").is_some());
    }

    #[test]
    fn test_case_insensitive_method() {
        let routes = vec![make_route("r1", "/api", "http://localhost:9001", &["get"])];
        let matcher = RouteMatcher::new(&routes);
        assert!(matcher.match_route("/api", "GET").is_some());
        assert!(matcher.match_route("/api", "get").is_some());
    }

    #[test]
    fn test_route_upstream_path_no_strip() {
        let routes = vec![make_route("r1", "/api/v1", "http://localhost:9001", &["GET"])];
        let matcher = RouteMatcher::new(&routes);
        let (_, path) = matcher.match_route("/api/v1/items/42", "GET").unwrap();
        assert_eq!(path, "/api/v1/items/42");
    }

    #[test]
    fn test_route_rate_limit_from_config() {
        let mut cfg = make_route("r1", "/api", "http://localhost:9001", &["GET"]);
        cfg.rate_limit = Some(crate::config::RouteRateLimit { requests: 10, window_seconds: 30 });
        let routes = vec![cfg];
        let matcher = RouteMatcher::new(&routes);
        let (route, _) = matcher.match_route("/api", "GET").unwrap();
        assert_eq!(route.rate_limit, Some((10, 30)));
    }

    #[test]
    fn test_route_max_body_bytes() {
        let mut cfg = make_route("r1", "/api", "http://localhost:9001", &["POST"]);
        cfg.max_request_body_bytes = Some(4096);
        let routes = vec![cfg];
        let matcher = RouteMatcher::new(&routes);
        let (route, _) = matcher.match_route("/api/upload", "POST").unwrap();
        assert_eq!(route.max_request_body_bytes, Some(4096));
    }

    #[test]
    fn test_route_upstream_tls_flag() {
        let mut cfg = make_route("r1", "/api", "https://secure:443", &["GET"]);
        cfg.upstream_tls = true;
        let routes = vec![cfg];
        let matcher = RouteMatcher::new(&routes);
        let (route, _) = matcher.match_route("/api", "GET").unwrap();
        assert!(route.upstream_tls);
    }

    #[test]
    fn test_matcher_routes_accessor() {
        let routes = vec![
            make_route("r1", "/a", "http://a:9001", &["GET"]),
            make_route("r2", "/b", "http://b:9001", &["POST"]),
        ];
        let matcher = RouteMatcher::new(&routes);
        assert_eq!(matcher.routes().len(), 2);
    }

    #[test]
    fn test_load_balancer_wraps_around() {
        let lb = LoadBalancer::new();
        let upstreams = vec!["http://a:9001".to_string(), "http://b:9001".to_string()];
        // Go around multiple times
        for i in 0..10 {
            let expected = if i % 2 == 0 { "http://a:9001" } else { "http://b:9001" };
            assert_eq!(lb.next_upstream(&upstreams), expected);
        }
    }

    #[test]
    fn test_load_balancer_default() {
        let lb = LoadBalancer::default();
        let upstreams = vec!["http://only:9001".to_string()];
        assert_eq!(lb.next_upstream(&upstreams), "http://only:9001");
    }
}