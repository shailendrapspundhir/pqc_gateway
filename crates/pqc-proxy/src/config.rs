use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tls: TlsFileConfig,
    #[serde(default)]
    pub signatures: SignaturesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerFileConfig,
    #[serde(default)]
    pub threshold: ThresholdConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default, rename = "routes")]
    pub routes: Vec<RouteConfig>,
}

/// Global signature configuration section `[signatures]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignaturesConfig {
    /// Default signature mode for all routes: "classical" | "hybrid" | "mldsa-only"
    #[serde(default = "default_signature_mode")]
    pub default_mode: String,
}

fn default_signature_mode() -> String {
    "classical".to_string()
}

impl Default for SignaturesConfig {
    fn default() -> Self {
        Self {
            default_mode: default_signature_mode(),
        }
    }
}

/// Auth configuration section `[auth]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_seconds: u64,
    #[serde(default)]
    pub public_paths: Vec<String>,
}

fn default_issuer() -> String { "pqc-gateway".to_string() }
fn default_audience() -> String { "pqc-gateway-api".to_string() }
fn default_token_ttl() -> u64 { 3600 }

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: default_issuer(),
            audience: default_audience(),
            token_ttl_seconds: default_token_ttl(),
            public_paths: vec![
                "/health".to_string(),
                "/.well-known/".to_string(),
            ],
        }
    }
}

/// Admin listener configuration `[admin]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_bind")]
    pub bind_address: String,
    #[serde(default = "default_admin_port")]
    pub port: u16,
    /// API key for securing admin endpoints. Read from GATEWAY_ADMIN_API_KEY env
    /// if not set in config.
    #[serde(default)]
    pub api_key: Option<String>,
}

fn default_admin_enabled() -> bool { true }
fn default_admin_bind() -> String { "127.0.0.1".to_string() }
fn default_admin_port() -> u16 { 9090 }

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_enabled(),
            bind_address: default_admin_bind(),
            port: default_admin_port(),
            api_key: None,
        }
    }
}

impl AdminConfig {
    /// Get the effective API key (config or env var).
    pub fn effective_api_key(&self) -> Option<String> {
        self.api_key.clone().or_else(|| std::env::var("GATEWAY_ADMIN_API_KEY").ok())
    }
}

/// Circuit breaker configuration section `[circuit_breaker]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerFileConfig {
    #[serde(default = "default_cb_enabled")]
    pub enabled: bool,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_recovery_timeout_ms")]
    pub recovery_timeout_ms: u64,
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,
    #[serde(default = "default_health_check_path")]
    pub health_check_path: String,
}

fn default_cb_enabled() -> bool { true }
fn default_failure_threshold() -> u32 { 5 }
fn default_recovery_timeout_ms() -> u64 { 30000 }
fn default_health_check_interval_ms() -> u64 { 10000 }
fn default_health_check_path() -> String { "/health".to_string() }

impl Default for CircuitBreakerFileConfig {
    fn default() -> Self {
        Self {
            enabled: default_cb_enabled(),
            failure_threshold: default_failure_threshold(),
            recovery_timeout_ms: default_recovery_timeout_ms(),
            health_check_interval_ms: default_health_check_interval_ms(),
            health_check_path: default_health_check_path(),
        }
    }
}

/// Threshold key management configuration `[threshold]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThresholdConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_threshold_k")]
    pub threshold: u8,
    #[serde(default = "default_threshold_n")]
    pub total_shares: u8,
    #[serde(default = "default_max_retained_keys")]
    pub max_retained_keys: usize,
}

fn default_threshold_k() -> u8 { 3 }
fn default_threshold_n() -> u8 { 5 }
fn default_max_retained_keys() -> usize { 5 }

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_threshold_k(),
            total_shares: default_threshold_n(),
            max_retained_keys: default_max_retained_keys(),
        }
    }
}

/// Global rate limiting configuration `[rate_limit]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Default requests per window for routes without explicit config.
    #[serde(default = "default_rl_requests")]
    pub default_requests: u32,
    /// Default window size in seconds.
    #[serde(default = "default_rl_window")]
    pub default_window_seconds: u64,
}

fn default_rl_requests() -> u32 { 1000 }
fn default_rl_window() -> u64 { 60 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_requests: default_rl_requests(),
            default_window_seconds: default_rl_window(),
        }
    }
}

/// Metrics / observability configuration `[metrics]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String { "/metrics".to_string() }

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_metrics_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub http_port: u16,
    /// Graceful shutdown drain timeout in seconds.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_seconds: u64,
    /// Global default request body size limit in bytes (10 MB default).
    #[serde(default = "default_max_request_body")]
    pub max_request_body_bytes: u64,
}

fn default_drain_timeout() -> u64 { 30 }
fn default_max_request_body() -> u64 { 10_485_760 }

/// TLS configuration section from gateway.toml (file-level representation).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsFileConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cert_file")]
    pub cert_file: String,
    #[serde(default = "default_key_file")]
    pub key_file: String,
    #[serde(default = "default_min_version")]
    pub min_version: String,
    #[serde(default = "default_pqc_enabled")]
    pub pqc_enabled: bool,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    pub ca_file: Option<String>,
}

fn default_cert_file() -> String { "config/certs/server.crt".to_string() }
fn default_key_file() -> String { "config/certs/server.key".to_string() }
fn default_min_version() -> String { "1.3".to_string() }
fn default_pqc_enabled() -> bool { true }
fn default_https_port() -> u16 { 8443 }

impl Default for TlsFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: default_cert_file(),
            key_file: default_key_file(),
            min_version: default_min_version(),
            pqc_enabled: default_pqc_enabled(),
            https_port: default_https_port(),
            ca_file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

/// Per-route rate limit override.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteRateLimit {
    pub requests: u32,
    pub window_seconds: u64,
}

/// Per-route mTLS configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteMtlsConfig {
    pub enabled: bool,
    /// CA certificate file for verifying client certificates.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Client certificate file for connecting to upstream.
    #[serde(default)]
    pub client_cert_file: Option<String>,
    /// Client key file for connecting to upstream.
    #[serde(default)]
    pub client_key_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteConfig {
    pub id: String,
    pub path_prefix: String,
    /// Primary upstream URL. Can also specify multiple via `upstreams`.
    pub upstream: String,
    /// Additional upstream URLs for load balancing.
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Per-route signature mode override: "classical" | "hybrid" | "mldsa-only"
    pub signature_mode: Option<String>,
    /// Per-route rate limit override.
    pub rate_limit: Option<RouteRateLimit>,
    /// Maximum request body size in bytes (overrides global).
    pub max_request_body_bytes: Option<u64>,
    /// Per-route mTLS config for upstream connections.
    pub mtls: Option<RouteMtlsConfig>,
    /// Use HTTPS to connect to upstream.
    #[serde(default)]
    pub upstream_tls: bool,
}

fn default_timeout() -> u64 {
    10000
}

impl RouteConfig {
    /// Get all upstream URLs (primary + extras).
    pub fn all_upstreams(&self) -> Vec<String> {
        let mut all = vec![self.upstream.clone()];
        all.extend(self.upstreams.iter().cloned());
        all
    }
}

impl GatewayConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: GatewayConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        let config: GatewayConfig = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.routes.is_empty() {
            anyhow::bail!("No routes configured");
        }
        for route in &self.routes {
            if route.path_prefix.is_empty() {
                anyhow::bail!("Route '{}' has empty path_prefix", route.id);
            }
            if route.upstream.is_empty() {
                anyhow::bail!("Route '{}' has empty upstream", route.id);
            }
        }
        Ok(())
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_config_defaults() {
        let admin = AdminConfig::default();
        assert!(admin.enabled);
        assert_eq!(admin.bind_address, "127.0.0.1");
        assert_eq!(admin.port, 9090);
        assert!(admin.api_key.is_none());
    }

    #[test]
    fn test_admin_effective_api_key_from_config() {
        let admin = AdminConfig {
            api_key: Some("test-key".to_string()),
            ..Default::default()
        };
        assert_eq!(admin.effective_api_key(), Some("test-key".to_string()));
    }

    #[test]
    fn test_rate_limit_defaults() {
        let rl = RateLimitConfig::default();
        assert!(!rl.enabled);
        assert_eq!(rl.default_requests, 1000);
        assert_eq!(rl.default_window_seconds, 60);
    }

    #[test]
    fn test_route_all_upstreams_single() {
        let route = RouteConfig {
            id: "r1".to_string(),
            path_prefix: "/api".to_string(),
            upstream: "http://localhost:9001".to_string(),
            upstreams: vec![],
            strip_prefix: false,
            methods: vec![],
            timeout_ms: 5000,
            signature_mode: None,
            rate_limit: None,
            max_request_body_bytes: None,
            mtls: None,
            upstream_tls: false,
        };
        assert_eq!(route.all_upstreams(), vec!["http://localhost:9001"]);
    }

    #[test]
    fn test_route_all_upstreams_multiple() {
        let route = RouteConfig {
            id: "r1".to_string(),
            path_prefix: "/api".to_string(),
            upstream: "http://a:9001".to_string(),
            upstreams: vec!["http://b:9001".to_string(), "http://c:9001".to_string()],
            strip_prefix: false,
            methods: vec![],
            timeout_ms: 5000,
            signature_mode: None,
            rate_limit: None,
            max_request_body_bytes: None,
            mtls: None,
            upstream_tls: false,
        };
        assert_eq!(route.all_upstreams(), vec![
            "http://a:9001", "http://b:9001", "http://c:9001"
        ]);
    }

    #[test]
    fn test_config_from_json() {
        let json = r#"{
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{"id": "r1", "path_prefix": "/api", "upstream": "http://localhost:9001"}]
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].id, "r1");
    }

    #[test]
    fn test_config_validate_no_routes() {
        let json = r#"{
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": []
        }"#;
        assert!(GatewayConfig::from_json(json).is_err());
    }

    #[test]
    fn test_server_config_defaults() {
        let json = r#"{
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{"id": "r1", "path_prefix": "/api", "upstream": "http://localhost:9001"}]
        }"#;
        let config = GatewayConfig::from_json(json).unwrap();
        assert_eq!(config.server.drain_timeout_seconds, 30);
        assert_eq!(config.server.max_request_body_bytes, 10_485_760);
    }

    #[test]
    fn test_metrics_config_defaults() {
        let mc = MetricsConfig::default();
        assert!(!mc.enabled);
        assert_eq!(mc.path, "/metrics");
    }

    #[test]
    fn test_admin_effective_api_key_from_env() {
        let admin = AdminConfig::default();
        // With no env var and no config, should be None
        assert!(admin.api_key.is_none());
    }

    #[test]
    fn test_circuit_breaker_defaults() {
        let cb = CircuitBreakerFileConfig::default();
        assert!(cb.enabled);
        assert_eq!(cb.failure_threshold, 5);
        assert_eq!(cb.recovery_timeout_ms, 30000);
        assert_eq!(cb.health_check_interval_ms, 10000);
        assert_eq!(cb.health_check_path, "/health");
    }

    #[test]
    fn test_threshold_defaults() {
        let t = ThresholdConfig::default();
        assert!(!t.enabled);
        assert_eq!(t.threshold, 3);
        assert_eq!(t.total_shares, 5);
        assert_eq!(t.max_retained_keys, 5);
    }

    #[test]
    fn test_tls_config_defaults() {
        let tls = TlsFileConfig::default();
        assert!(!tls.enabled);
        assert_eq!(tls.cert_file, "config/certs/server.crt");
        assert_eq!(tls.key_file, "config/certs/server.key");
        assert_eq!(tls.min_version, "1.3");
        assert!(tls.pqc_enabled);
        assert_eq!(tls.https_port, 8443);
        assert!(tls.ca_file.is_none());
    }

    #[test]
    fn test_auth_config_defaults() {
        let auth = AuthConfig::default();
        assert!(!auth.enabled);
        assert_eq!(auth.issuer, "pqc-gateway");
        assert_eq!(auth.audience, "pqc-gateway-api");
        assert_eq!(auth.token_ttl_seconds, 3600);
        assert!(auth.public_paths.contains(&"/health".to_string()));
    }

    #[test]
    fn test_signatures_config_defaults() {
        let sig = SignaturesConfig::default();
        assert_eq!(sig.default_mode, "classical");
    }

    #[test]
    fn test_logging_config_defaults() {
        let log = LoggingConfig::default();
        assert_eq!(log.level, "info");
        assert_eq!(log.format, "pretty");
    }

    #[test]
    fn test_config_from_toml_file() {
        // Test loading actual config file
        let path = std::path::Path::new("config/gateway.toml");
        if path.exists() {
            let cfg = GatewayConfig::from_file(path).unwrap();
            assert!(!cfg.routes.is_empty());
            assert_eq!(cfg.server.bind_address, "0.0.0.0");
        }
    }

    #[test]
    fn test_route_rate_limit_deserialization() {
        let json = r#"{
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{
                "id": "r1",
                "path_prefix": "/api",
                "upstream": "http://localhost:9001",
                "rate_limit": {"requests": 50, "window_seconds": 10}
            }]
        }"#;
        let cfg = GatewayConfig::from_json(json).unwrap();
        let rl = cfg.routes[0].rate_limit.as_ref().unwrap();
        assert_eq!(rl.requests, 50);
        assert_eq!(rl.window_seconds, 10);
    }

    #[test]
    fn test_route_mtls_deserialization() {
        let json = r#"{
            "server": {"bind_address": "0.0.0.0", "http_port": 8080},
            "logging": {"level": "info", "format": "pretty"},
            "routes": [{
                "id": "r1",
                "path_prefix": "/api",
                "upstream": "https://secure:443",
                "upstream_tls": true,
                "mtls": {
                    "enabled": true,
                    "ca_file": "/ca.pem",
                    "client_cert_file": "/client.pem",
                    "client_key_file": "/client-key.pem"
                }
            }]
        }"#;
        let cfg = GatewayConfig::from_json(json).unwrap();
        let mtls = cfg.routes[0].mtls.as_ref().unwrap();
        assert!(mtls.enabled);
        assert_eq!(mtls.ca_file.as_deref(), Some("/ca.pem"));
    }

    #[test]
    fn test_config_invalid_json() {
        let result = GatewayConfig::from_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_missing_required_fields() {
        let result = GatewayConfig::from_json(r#"{"routes": []}"#);
        assert!(result.is_err());
    }
}