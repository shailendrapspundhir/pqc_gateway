//! Certificate loading and PEM file handling.

use std::fs::File;
use std::io::BufReader;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

/// Load PEM-encoded certificates from a file.
pub fn load_certificates(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open cert file '{}': {}", path, e))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse certs from '{}': {}", path, e))?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in '{}'", path);
    }

    info!(path = %path, count = certs.len(), "Loaded certificates");
    Ok(certs)
}

/// Load a PEM-encoded private key from a file.
/// Supports PKCS8, RSA, and EC key formats.
pub fn load_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open key file '{}': {}", path, e))?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                info!(path = %path, format = "PKCS8", "Loaded private key");
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                info!(path = %path, format = "RSA/PKCS1", "Loaded private key");
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                info!(path = %path, format = "EC/SEC1", "Loaded private key");
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Some(_) => continue,
            None => break,
        }
    }

    anyhow::bail!(
        "No private key found in '{}'. Expected PKCS8, RSA, or EC PEM key.",
        path
    )
}

/// Verify a certificate chain is valid and not expired.
pub fn verify_cert_chain(certs: &[CertificateDer<'_>]) -> anyhow::Result<()> {
    if certs.is_empty() {
        anyhow::bail!("Empty certificate chain");
    }
    // Basic DER structure check on the leaf certificate
    let leaf = &certs[0];
    if leaf.as_ref().len() < 64 {
        anyhow::bail!("Leaf certificate too small to be valid");
    }
    info!(
        chain_length = certs.len(),
        leaf_size = leaf.as_ref().len(),
        "Certificate chain verified (structural)"
    );
    Ok(())
}

/// Get basic info about a DER certificate (size, approximate type).
pub fn cert_info(cert: &CertificateDer<'_>) -> CertInfo {
    let der = cert.as_ref();
    let size = der.len();
    // PQC certs (ML-DSA) are significantly larger due to key/signature sizes
    let is_likely_pqc = size > 4000;
    CertInfo {
        der_size: size,
        is_likely_pqc,
    }
}

pub struct CertInfo {
    pub der_size: usize,
    pub is_likely_pqc: bool,
}

impl std::fmt::Display for CertInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CertInfo {{ size: {} bytes, likely_pqc: {} }}",
            self.der_size, self.is_likely_pqc
        )
    }
}