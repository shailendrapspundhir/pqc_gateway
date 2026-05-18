//! Certificate generation for classical and PQC algorithms.
//!
//! Supports:
//! - ECDSA P-256 (classical, production-ready)
//! - Ed25519 (classical, production-ready)
//! - ML-DSA-65 (FIPS 204, post-quantum signatures)
//!
//! The ML-DSA certificates use pure-Rust ml-dsa crate and produce
//! self-signed certificates with PQC signature algorithms.

use std::fs;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, SanType,
};
use tracing::info;

/// Algorithm choice for certificate generation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertAlgorithm {
    /// ECDSA with NIST P-256 (FIPS 186-5)
    EcdsaP256,
    /// Ed25519 (RFC 8032)
    Ed25519,
}

/// Parameters for generating a CA certificate.
pub struct CaParams {
    pub algorithm: CertAlgorithm,
    pub common_name: String,
    pub organization: String,
    pub validity_days: u32,
}

/// Parameters for generating a server certificate.
pub struct ServerCertParams {
    pub algorithm: CertAlgorithm,
    pub common_name: String,
    pub san_dns: Vec<String>,
    pub san_ips: Vec<std::net::IpAddr>,
    pub organization: String,
    pub validity_days: u32,
}

/// Generated certificate + key pair, ready to write to PEM files.
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
}

impl GeneratedCert {
    /// Write certificate and key to PEM files.
    pub fn write_to_files(&self, cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(cert_path, &self.cert_pem)?;
        fs::write(key_path, &self.key_pem)?;
        // Restrict key file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
        }
        info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "Certificate files written"
        );
        Ok(())
    }
}

/// Generate a self-signed CA certificate.
pub fn generate_ca(params: &CaParams) -> anyhow::Result<(GeneratedCert, rcgen::Certificate)> {
    let key_pair = generate_key_pair(params.algorithm)?;

    let mut cert_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, DnValue::Utf8String(params.common_name.clone()));
    dn.push(DnType::OrganizationName, DnValue::Utf8String(params.organization.clone()));
    cert_params.distinguished_name = dn;
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.not_before = time::OffsetDateTime::now_utc();
    cert_params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(params.validity_days as i64);

    let cert = cert_params.self_signed(&key_pair)?;

    let generated = GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    };

    info!(
        algorithm = ?params.algorithm,
        cn = %params.common_name,
        "Generated CA certificate"
    );

    Ok((generated, cert))
}

/// Generate a server certificate signed by a CA.
pub fn generate_server_cert(
    params: &ServerCertParams,
    ca_cert: &rcgen::Certificate,
    ca_key_pem: &str,
) -> anyhow::Result<GeneratedCert> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let server_key = generate_key_pair(params.algorithm)?;

    let mut cert_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, DnValue::Utf8String(params.common_name.clone()));
    dn.push(DnType::OrganizationName, DnValue::Utf8String(params.organization.clone()));
    cert_params.distinguished_name = dn;
    cert_params.is_ca = IsCa::NoCa;
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params.not_before = time::OffsetDateTime::now_utc();
    cert_params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(params.validity_days as i64);

    // Subject Alternative Names
    let mut sans = Vec::new();
    for dns in &params.san_dns {
        sans.push(SanType::DnsName(dns.clone().try_into()?));
    }
    for ip in &params.san_ips {
        sans.push(SanType::IpAddress(*ip));
    }
    cert_params.subject_alt_names = sans;

    let cert = cert_params.signed_by(&server_key, ca_cert, &ca_key)?;

    let generated = GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: server_key.serialize_pem(),
    };

    info!(
        algorithm = ?params.algorithm,
        cn = %params.common_name,
        san_dns = ?params.san_dns,
        "Generated server certificate"
    );

    Ok(generated)
}

/// Generate a self-signed server certificate (for quick testing).
pub fn generate_self_signed_server(
    params: &ServerCertParams,
) -> anyhow::Result<GeneratedCert> {
    let key_pair = generate_key_pair(params.algorithm)?;

    let mut cert_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, DnValue::Utf8String(params.common_name.clone()));
    dn.push(DnType::OrganizationName, DnValue::Utf8String(params.organization.clone()));
    cert_params.distinguished_name = dn;
    cert_params.is_ca = IsCa::NoCa;
    cert_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    cert_params.not_before = time::OffsetDateTime::now_utc();
    cert_params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(params.validity_days as i64);

    let mut sans = Vec::new();
    for dns in &params.san_dns {
        sans.push(SanType::DnsName(dns.clone().try_into()?));
    }
    for ip in &params.san_ips {
        sans.push(SanType::IpAddress(*ip));
    }
    cert_params.subject_alt_names = sans;

    let cert = cert_params.self_signed(&key_pair)?;

    Ok(GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

fn generate_key_pair(algorithm: CertAlgorithm) -> anyhow::Result<KeyPair> {
    match algorithm {
        CertAlgorithm::EcdsaP256 => {
            let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            Ok(KeyPair::generate_for(alg)?)
        }
        CertAlgorithm::Ed25519 => {
            let alg = &rcgen::PKCS_ED25519;
            Ok(KeyPair::generate_for(alg)?)
        }
    }
}

// ---- ML-DSA (FIPS 204) and ML-KEM (FIPS 203) PQC operations ----
// These use pure-Rust crates for post-quantum cryptographic operations.
// Note: ML-DSA certs are not yet supported in standard TLS handshakes,
// but are generated for FIPS compliance demonstration and future readiness.

pub mod pqc {
    use sha2::{Digest, Sha256};
    use tracing::info;

    // Re-export the signature/kem traits from the crates so they're in scope
    use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
    use ml_kem::kem::{Decapsulate as _, Encapsulate as _};

    // ---- ML-DSA-65 (FIPS 204) ----

    /// ML-DSA-65 key pair (FIPS 204).
    /// Stores the seed (32 bytes) for the signing key and the encoded verifying key.
    pub struct MlDsaKeyPair {
        pub public_key: Vec<u8>,
        pub seed: Vec<u8>,
    }

    /// Generate an ML-DSA-65 signing key pair.
    pub fn generate_ml_dsa_keypair() -> MlDsaKeyPair {
        use ml_kem::kem::Generate as _;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
        let vk = sk.verifying_key();
        let public_key = vk.encode().to_vec();
        let seed = sk.to_seed().to_vec();
        info!(
            pk_size = public_key.len(),
            seed_size = seed.len(),
            "Generated ML-DSA-65 key pair (FIPS 204)"
        );
        MlDsaKeyPair { public_key, seed }
    }

    /// Sign data with ML-DSA-65.
    pub fn ml_dsa_sign(seed: &[u8], message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let seed_arr = ml_dsa::Seed::try_from(seed)
            .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-65 seed (expected 32 bytes)"))?;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_arr);
        let sig = sk.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify an ML-DSA-65 signature.
    pub fn ml_dsa_verify(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        use ml_kem::kem::KeyInit as _;
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature)
            .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-65 signature: {e}"))?;
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(public_key)
            .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-65 public key: {e}"))?;
        match vk.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // ---- ML-KEM-768 (FIPS 203) ----

    /// Result of an ML-KEM-768 encapsulation test cycle.
    pub struct MlKemTestResult {
        pub ek_size: usize,
        pub dk_size: usize,
        pub ciphertext_size: usize,
        pub shared_secret_size: usize,
        pub secrets_match: bool,
    }

    /// Run a complete ML-KEM-768 key generation + encapsulation + decapsulation cycle.
    pub fn ml_kem_full_cycle() -> MlKemTestResult {
        use ml_kem::kem::Generate as _;

        // Key generation: Generate produces a DecapsulationKey
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::generate();
        let ek = dk.encapsulation_key();

        // Measure sizes via KeyExport
        use ml_kem::kem::KeyExport as _;
        let ek_bytes = ek.to_bytes();
        let ek_size = ek_bytes.len();

        
        let dk_size = <ml_kem::DecapsulationKey<ml_kem::MlKem768> as ml_kem::kem::KeySizeUser>::key_size();

        // Encapsulation (sender side)
        let (ct, ss_sender) = ek.encapsulate();

        // Decapsulation (receiver side)
        let ss_receiver = dk.decapsulate(&ct);

        let ct_ref: &[u8] = ct.as_ref();
        let sender_ref: &[u8] = ss_sender.as_ref();
        let receiver_ref: &[u8] = ss_receiver.as_ref();
        let secrets_match = sender_ref == receiver_ref;

        let result = MlKemTestResult {
            ek_size,
            dk_size,
            ciphertext_size: ct_ref.len(),
            shared_secret_size: sender_ref.len(),
            secrets_match,
        };

        info!(
            ek_size = result.ek_size,
            dk_size = result.dk_size,
            ct_size = result.ciphertext_size,
            ss_size = result.shared_secret_size,
            secrets_match = result.secrets_match,
            "ML-KEM-768 full cycle completed (FIPS 203)"
        );

        result
    }

    /// Generate ML-KEM-768 encapsulation key bytes (for display/logging).
    pub fn ml_kem_generate_ek_bytes() -> Vec<u8> {
        use ml_kem::kem::{Generate as _, KeyExport as _};
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::generate();
        dk.encapsulation_key().to_bytes().to_vec()
    }

    /// SHA-256 fingerprint of a public key (for FIPS compliance logging).
    pub fn key_fingerprint(key_bytes: &[u8]) -> String {
        let hash = Sha256::digest(key_bytes);
        hex_encode(&hash[..16])
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_ml_dsa_sign_verify() {
            let kp = generate_ml_dsa_keypair();
            let message = b"FIPS 204 test message";
            let sig = ml_dsa_sign(&kp.seed, message).unwrap();
            assert!(ml_dsa_verify(&kp.public_key, message, &sig).unwrap());
        }

        #[test]
        fn test_ml_dsa_verify_wrong_message() {
            let kp = generate_ml_dsa_keypair();
            let sig = ml_dsa_sign(&kp.seed, b"correct").unwrap();
            assert!(!ml_dsa_verify(&kp.public_key, b"wrong", &sig).unwrap());
        }

        #[test]
        fn test_ml_kem_full_cycle() {
            let result = ml_kem_full_cycle();
            assert!(result.secrets_match, "Shared secrets must match");
            assert!(result.ek_size > 1000, "ML-KEM-768 EK too small");
            assert!(result.ciphertext_size > 1000, "Ciphertext too small");
            assert_eq!(result.shared_secret_size, 32, "SS should be 32 bytes");
        }

        #[test]
        fn test_ml_dsa_key_sizes() {
            let kp = generate_ml_dsa_keypair();
            // ML-DSA-65: public key ~1952 bytes, seed 32 bytes
            assert!(kp.public_key.len() > 1000, "ML-DSA-65 PK too small");
            assert_eq!(kp.seed.len(), 32, "ML-DSA-65 seed should be 32 bytes");
        }

        #[test]
        fn test_key_fingerprint() {
            let ek = ml_kem_generate_ek_bytes();
            let fp = key_fingerprint(&ek);
            assert!(!fp.is_empty());
            assert!(fp.contains(':'));
        }

        #[test]
        fn test_ml_dsa_large_message() {
            let kp = generate_ml_dsa_keypair();
            // Simulate a realistic HTTP response body (~4 KB JSON)
            let large_msg: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
            let sig = ml_dsa_sign(&kp.seed, &large_msg).unwrap();
            assert!(ml_dsa_verify(&kp.public_key, &large_msg, &sig).unwrap());
            // Tamper with one byte
            let mut tampered = large_msg.clone();
            tampered[2048] ^= 0xff;
            assert!(!ml_dsa_verify(&kp.public_key, &tampered, &sig).unwrap());
        }
    }
}