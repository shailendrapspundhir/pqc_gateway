use pqc_tls::signature::SignatureMode;

use crate::config::RouteConfig;

#[derive(Debug, Clone)]
pub struct Route {
    pub id: String,
    pub path_prefix: String,
    pub upstream: String,
    pub strip_prefix: bool,
    pub methods: Vec<String>,
    pub timeout_ms: u64,
    /// Per-route signature mode override (None = use global default).
    pub signature_mode: Option<SignatureMode>,
}

impl From<&RouteConfig> for Route {
    fn from(cfg: &RouteConfig) -> Self {
        let signature_mode = cfg
            .signature_mode
            .as_deref()
            .and_then(|s| s.parse::<SignatureMode>().ok());
        Self {
            id: cfg.id.clone(),
            path_prefix: cfg.path_prefix.clone(),
            upstream: cfg.upstream.clone(),
            strip_prefix: cfg.strip_prefix,
            methods: cfg.methods.iter().map(|m| m.to_uppercase()).collect(),
            timeout_ms: cfg.timeout_ms,
            signature_mode,
        }
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
            strip_prefix: false,
            methods: methods.iter().map(|s| s.to_string()).collect(),
            timeout_ms: 5000,
            signature_mode: None,
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
            strip_prefix: true,
            methods: vec!["GET".to_string()],
            timeout_ms: 5000,
            signature_mode: None,
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
}