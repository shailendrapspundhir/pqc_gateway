use serde::Deserialize;

/// TLS configuration section from gateway.toml.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Path to PEM-encoded server certificate chain.
    #[serde(default = "default_cert_file")]
    pub cert_file: String,
    /// Path to PEM-encoded private key.
    #[serde(default = "default_key_file")]
    pub key_file: String,
    /// Minimum TLS version. Only "1.3" is recommended for PQC.
    #[serde(default = "default_min_version")]
    pub min_version: String,
    /// Enable PQC hybrid key exchange (X25519 + ML-KEM-768).
    #[serde(default = "default_pqc_enabled")]
    pub pqc_enabled: bool,
    /// HTTPS listen port.
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    /// Optional CA certificate for client verification.
    pub ca_file: Option<String>,
}

fn default_cert_file() -> String {
    "config/certs/server.crt".to_string()
}

fn default_key_file() -> String {
    "config/certs/server.key".to_string()
}

fn default_min_version() -> String {
    "1.3".to_string()
}

fn default_pqc_enabled() -> bool {
    true
}

fn default_https_port() -> u16 {
    8443
}

impl Default for TlsConfig {
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

impl TlsConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.cert_file.is_empty() {
            anyhow::bail!("TLS enabled but cert_file is empty");
        }
        if self.key_file.is_empty() {
            anyhow::bail!("TLS enabled but key_file is empty");
        }
        let cert_path = std::path::Path::new(&self.cert_file);
        if !cert_path.exists() {
            anyhow::bail!("TLS cert file not found: {}", self.cert_file);
        }
        let key_path = std::path::Path::new(&self.key_file);
        if !key_path.exists() {
            anyhow::bail!("TLS key file not found: {}", self.key_file);
        }
        match self.min_version.as_str() {
            "1.2" | "1.3" => {}
            other => anyhow::bail!("Unsupported TLS min_version: {other}"),
        }
        Ok(())
    }
}