//! TLS CryptoProvider setup with PQC hybrid key exchange.
//!
//! Configures rustls with the aws-lc-rs provider which supports:
//! - X25519MLKEM768: Hybrid post-quantum key exchange (FIPS 203 compliant)
//! - X25519: Classical ECDH fallback
//! - ECDSA P-256/P-384: Server certificate signatures
//! - Ed25519: Alternative signature scheme

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::CertificateDer;
use tracing::info;

use crate::certs;
use crate::config::TlsConfig;

/// Builds a rustls CryptoProvider with PQC hybrid key exchange support.
///
/// Key exchange preference order (when pqc_enabled):
///   1. X25519MLKEM768 — Hybrid PQC (ML-KEM-768 + X25519)
///   2. X25519 — Classical ECDH fallback
///   3. SECP256R1 — NIST P-256 fallback
///   4. SECP384R1 — NIST P-384 fallback
pub fn build_crypto_provider(pqc_enabled: bool) -> CryptoProvider {
    let base = rustls::crypto::aws_lc_rs::default_provider();

    if pqc_enabled {
        let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ];
        info!(
            groups = ?kx_groups.iter().map(|g| format!("{:?}", g.name())).collect::<Vec<_>>(),
            "PQC hybrid key exchange enabled"
        );
        CryptoProvider {
            kx_groups,
            ..base
        }
    } else {
        info!("Classical-only key exchange (PQC disabled)");
        CryptoProvider {
            kx_groups: vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
                rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
            ],
            ..base
        }
    }
}

/// Builds a complete rustls ServerConfig for the gateway.
pub fn build_server_config(tls_config: &TlsConfig) -> anyhow::Result<ServerConfig> {
    tls_config.validate()?;

    let provider = build_crypto_provider(tls_config.pqc_enabled);

    let cert_chain = certs::load_certificates(&tls_config.cert_file)?;
    let private_key = certs::load_private_key(&tls_config.key_file)?;

    let builder = ServerConfig::builder_with_provider(Arc::new(provider));

    // Enforce TLS version
    let builder = match tls_config.min_version.as_str() {
        "1.3" => builder.with_protocol_versions(&[&rustls::version::TLS13])?,
        "1.2" => builder.with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ])?,
        _ => anyhow::bail!("Unsupported TLS min_version"),
    };

    // Client auth
    let config = if let Some(ca_file) = &tls_config.ca_file {
        let ca_certs = certs::load_certificates(ca_file)?;
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, private_key)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?
    };

    info!(
        min_version = %tls_config.min_version,
        pqc = tls_config.pqc_enabled,
        cert = %tls_config.cert_file,
        "TLS server configuration built"
    );

    Ok(config)
}

/// Builds a rustls ClientConfig for connecting to TLS-enabled upstreams.
pub fn build_client_config(
    pqc_enabled: bool,
    ca_certs: Option<Vec<CertificateDer<'static>>>,
) -> anyhow::Result<rustls::ClientConfig> {
    let provider = build_crypto_provider(pqc_enabled);

    let mut root_store = RootCertStore::empty();
    if let Some(certs) = ca_certs {
        for cert in certs {
            root_store.add(cert)?;
        }
    }

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

/// Extracts info about which key exchange and cipher were negotiated on a TLS connection.
pub struct NegotiatedInfo {
    pub protocol_version: &'static str,
    pub cipher_suite: String,
    pub key_exchange: String,
}

impl NegotiatedInfo {
    pub fn from_server_connection(conn: &rustls::ServerConnection) -> Option<Self> {
        let protocol_version = match conn.protocol_version()? {
            rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
            rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
            _ => "unknown",
        };
        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "unknown".to_string());
        let key_exchange = conn
            .negotiated_key_exchange_group()
            .map(|kx| format!("{:?}", kx.name()))
            .unwrap_or_else(|| "unknown".to_string());

        Some(Self {
            protocol_version,
            cipher_suite,
            key_exchange,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_provider_has_mlkem() {
        let provider = build_crypto_provider(true);
        let group_names: Vec<_> = provider
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        // ML-KEM-768 hybrid should be first
        assert!(
            group_names[0].contains("MLKEM") || group_names[0].contains("mlkem"),
            "First KX group should be ML-KEM hybrid, got: {:?}",
            group_names
        );
    }

    #[test]
    fn test_classical_provider_no_mlkem() {
        let provider = build_crypto_provider(false);
        let group_names: Vec<_> = provider
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        assert!(
            !group_names[0].contains("MLKEM"),
            "Classical provider should not lead with ML-KEM"
        );
    }
}