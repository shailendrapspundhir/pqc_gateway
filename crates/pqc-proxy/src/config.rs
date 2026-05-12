use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tls: TlsFileConfig,
    #[serde(default, rename = "routes")]
    pub routes: Vec<RouteConfig>,
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