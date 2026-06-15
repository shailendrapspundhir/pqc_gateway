use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
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
    pub circuit_breaker: CircuitBreakerFileConfig,
    #[serde(default)]
    pub threshold: ThresholdConfig,
    #[serde(default, rename = "routes")]
    pub routes: Vec<RouteConfig>,
}

/// Global signature configuration section `[signatures]`.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
                "/auth/".to_string(),
                "/.well-known/".to_string(),
            ],
        }
    }
}

/// Circuit breaker configuration section `[circuit_breaker]`.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub http_port: u16,
}

/// TLS configuration section from gateway.toml (file-level representation).
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    pub path_prefix: String,
    pub upstream: String,
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Per-route signature mode override: "classical" | "hybrid" | "mldsa-only"
    pub signature_mode: Option<String>,
}

fn default_timeout() -> u64 {
    10000
}

impl GatewayConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: GatewayConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
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