use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    #[serde(default, rename = "routes")]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub http_port: u16,
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