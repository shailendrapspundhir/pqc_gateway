//! Multi-algorithm certificate chain validation and trust store manager.
//!
//! Supports hybrid certificate chains mixing ECDSA-P256, Ed25519, and ML-DSA-65
//! algorithms. Includes:
//! - Hybrid cert chain validation (e.g. ECDSA-P256 -> Ed25519 -> ML-DSA-65)
//! - Certificate trust store with revocation checks
//! - Certificate pinning
//! - Certificate expiry rotation with pre-expiry warnings
//! - Full chain-of-trust validation

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::certgen::pqc;
use crate::signature::hex_encode;

// ---------------------------------------------------------------------------
// Algorithm Types
// ---------------------------------------------------------------------------

/// Cryptographic algorithm used by a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainCertAlgorithm {
    EcdsaP256,
    Ed25519,
    MlDsa65,
}

impl std::fmt::Display for ChainCertAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcdsaP256 => write!(f, "ECDSA-P256"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
        }
    }
}

// ---------------------------------------------------------------------------
// Managed Certificate
// ---------------------------------------------------------------------------

/// A certificate with full metadata for chain validation.
#[derive(Debug, Clone)]
pub struct ManagedCertificate {
    pub subject: String,
    pub issuer: String,
    /// Algorithm of this certificate's own key pair.
    pub algorithm: ChainCertAlgorithm,
    /// Raw public key bytes.
    pub public_key: Vec<u8>,
    /// Signature over the TBS data, produced by the issuer's key.
    pub signature: Vec<u8>,
    /// Algorithm the issuer used to sign this certificate.
    pub issuer_algorithm: ChainCertAlgorithm,
    /// Not-before (unix timestamp seconds).
    pub not_before: u64,
    /// Not-after (unix timestamp seconds).
    pub not_after: u64,
    pub is_ca: bool,
    /// SHA-256 fingerprint of the public key (hex).
    pub fingerprint: String,
    /// Unique serial number.
    pub serial: String,
}

impl ManagedCertificate {
    /// Compute the To-Be-Signed (TBS) bytes from the certificate fields.
    /// The issuer signs these bytes when creating the certificate.
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.subject.as_bytes());
        data.push(0);
        data.extend_from_slice(self.issuer.as_bytes());
        data.push(0);
        data.extend_from_slice(&self.not_before.to_le_bytes());
        data.extend_from_slice(&self.not_after.to_le_bytes());
        data.extend_from_slice(&self.public_key);
        data.push(self.is_ca as u8);
        data.extend_from_slice(self.serial.as_bytes());
        data
    }

    /// Check if the certificate is currently valid (time-wise).
    pub fn is_time_valid(&self) -> bool {
        let now = current_unix_timestamp();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if the certificate is self-signed.
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }

    /// Days until expiry. Returns 0 if already expired.
    pub fn days_until_expiry(&self) -> u64 {
        let now = current_unix_timestamp();
        if now >= self.not_after {
            return 0;
        }
        (self.not_after - now) / 86400
    }
}

// ---------------------------------------------------------------------------
// Certificate + Key Pair (for building chains in tests / key management)
// ---------------------------------------------------------------------------

/// A certificate paired with its private key material.
#[derive(Debug, Clone)]
pub struct CertKeyPair {
    pub cert: ManagedCertificate,
    /// Private key bytes (ECDSA: 32-byte scalar, Ed25519: 32-byte seed, ML-DSA: 32-byte seed).
    pub private_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Chain Validation Errors & Result
// ---------------------------------------------------------------------------

/// Errors that can occur during chain validation.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainValidationError {
    EmptyChain,
    ExpiredCertificate { subject: String, expired_at: u64 },
    NotYetValid { subject: String, valid_from: u64 },
    UntrustedRoot { subject: String },
    RevokedCertificate { subject: String, serial: String },
    PinningViolation { subject: String, fingerprint: String },
    SignatureVerificationFailed { subject: String, issuer: String },
    ChainBroken { expected_issuer: String, got_subject: String },
    NonCaSignedChild { subject: String },
}

impl std::fmt::Display for ChainValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "Empty certificate chain"),
            Self::ExpiredCertificate { subject, expired_at } => {
                write!(f, "Certificate '{subject}' expired at timestamp {expired_at}")
            }
            Self::NotYetValid { subject, valid_from } => {
                write!(f, "Certificate '{subject}' not valid until timestamp {valid_from}")
            }
            Self::UntrustedRoot { subject } => {
                write!(f, "Root certificate '{subject}' not in trust store")
            }
            Self::RevokedCertificate { subject, serial } => {
                write!(f, "Certificate '{subject}' (serial {serial}) is revoked")
            }
            Self::PinningViolation { subject, fingerprint } => {
                write!(f, "Certificate '{subject}' fingerprint {fingerprint} not pinned")
            }
            Self::SignatureVerificationFailed { subject, issuer } => {
                write!(f, "Signature on '{subject}' by '{issuer}' failed verification")
            }
            Self::ChainBroken { expected_issuer, got_subject } => {
                write!(f, "Chain broken: expected issuer '{expected_issuer}', got '{got_subject}'")
            }
            Self::NonCaSignedChild { subject } => {
                write!(f, "Non-CA certificate '{subject}' signed a child certificate")
            }
        }
    }
}

/// Full result of chain validation.
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    pub valid: bool,
    pub errors: Vec<ChainValidationError>,
    pub warnings: Vec<String>,
    pub chain_length: usize,
    pub algorithms_used: Vec<ChainCertAlgorithm>,
}

// ---------------------------------------------------------------------------
// Trust Store
// ---------------------------------------------------------------------------

/// Certificate trust store with revocation list, pinning, and expiry management.
pub struct TrustStore {
    /// Trusted root certificates keyed by fingerprint.
    trusted_roots: HashMap<String, ManagedCertificate>,
    /// Set of revoked certificate serial numbers.
    revoked_serials: HashSet<String>,
    /// Pinning: subject -> set of allowed fingerprints.
    pinned_fingerprints: HashMap<String, HashSet<String>>,
    /// Days before expiry to issue a warning.
    expiry_warning_days: u32,
}

impl TrustStore {
    /// Create a new empty trust store.
    pub fn new(expiry_warning_days: u32) -> Self {
        Self {
            trusted_roots: HashMap::new(),
            revoked_serials: HashSet::new(),
            pinned_fingerprints: HashMap::new(),
            expiry_warning_days,
        }
    }

    /// Add a trusted root certificate.
    pub fn add_trusted_root(&mut self, cert: ManagedCertificate) {
        info!(subject = %cert.subject, fingerprint = %cert.fingerprint, "Added trusted root");
        self.trusted_roots.insert(cert.fingerprint.clone(), cert);
    }

    /// Remove a trusted root by fingerprint.
    pub fn remove_trusted_root(&mut self, fingerprint: &str) -> bool {
        self.trusted_roots.remove(fingerprint).is_some()
    }

    /// Mark a certificate serial as revoked.
    pub fn revoke_certificate(&mut self, serial: &str) {
        info!(serial = %serial, "Certificate revoked");
        self.revoked_serials.insert(serial.to_string());
    }

    /// Remove revocation for a serial.
    pub fn unrevoke_certificate(&mut self, serial: &str) {
        self.revoked_serials.remove(serial);
    }

    /// Check if a serial is revoked.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked_serials.contains(serial)
    }

    /// Pin a certificate fingerprint for a subject.
    pub fn pin_certificate(&mut self, subject: &str, fingerprint: &str) {
        self.pinned_fingerprints
            .entry(subject.to_string())
            .or_default()
            .insert(fingerprint.to_string());
    }

    /// Remove a pinned fingerprint for a subject.
    pub fn unpin_certificate(&mut self, subject: &str, fingerprint: &str) {
        if let Some(pins) = self.pinned_fingerprints.get_mut(subject) {
            pins.remove(fingerprint);
            if pins.is_empty() {
                self.pinned_fingerprints.remove(subject);
            }
        }
    }

    /// Number of trusted roots.
    pub fn trusted_root_count(&self) -> usize {
        self.trusted_roots.len()
    }

    /// Check expiry warnings for a certificate.
    pub fn check_expiry_warnings(&self, cert: &ManagedCertificate) -> Vec<String> {
        let mut warnings = Vec::new();
        let days = cert.days_until_expiry();
        if days == 0 {
            warnings.push(format!(
                "Certificate '{}' has EXPIRED (expired at {})",
                cert.subject, cert.not_after
            ));
        } else if days <= self.expiry_warning_days as u64 {
            warnings.push(format!(
                "Certificate '{}' expires in {} days — consider rotation",
                cert.subject, days
            ));
        }
        warnings
    }

    /// Validate a certificate chain from leaf (index 0) to root (last index).
    ///
    /// The chain must be ordered: `[leaf, intermediate..., root]`.
    /// The root certificate must be present in the trust store.
    pub fn validate_chain(&self, chain: &[ManagedCertificate]) -> ChainValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut algorithms_used = Vec::new();

        if chain.is_empty() {
            return ChainValidationResult {
                valid: false,
                errors: vec![ChainValidationError::EmptyChain],
                warnings,
                chain_length: 0,
                algorithms_used,
            };
        }

        let now = current_unix_timestamp();

        for (i, cert) in chain.iter().enumerate() {
            // Track algorithms
            if !algorithms_used.contains(&cert.algorithm) {
                algorithms_used.push(cert.algorithm);
            }

            // Check time validity
            if now < cert.not_before {
                errors.push(ChainValidationError::NotYetValid {
                    subject: cert.subject.clone(),
                    valid_from: cert.not_before,
                });
            }
            if now > cert.not_after {
                errors.push(ChainValidationError::ExpiredCertificate {
                    subject: cert.subject.clone(),
                    expired_at: cert.not_after,
                });
            }

            // Check revocation
            if self.is_revoked(&cert.serial) {
                errors.push(ChainValidationError::RevokedCertificate {
                    subject: cert.subject.clone(),
                    serial: cert.serial.clone(),
                });
            }

            // Check pinning
            if let Some(pins) = self.pinned_fingerprints.get(&cert.subject) {
                if !pins.contains(&cert.fingerprint) {
                    errors.push(ChainValidationError::PinningViolation {
                        subject: cert.subject.clone(),
                        fingerprint: cert.fingerprint.clone(),
                    });
                }
            }

            // Expiry warnings
            warnings.extend(self.check_expiry_warnings(cert));

            // Chain linkage and signature verification (skip for root / last cert)
            if i + 1 < chain.len() {
                let issuer_cert = &chain[i + 1];

                // Check chain linkage
                if cert.issuer != issuer_cert.subject {
                    errors.push(ChainValidationError::ChainBroken {
                        expected_issuer: cert.issuer.clone(),
                        got_subject: issuer_cert.subject.clone(),
                    });
                }

                // Issuer must be a CA (except for self-signed leaf)
                if !issuer_cert.is_ca {
                    errors.push(ChainValidationError::NonCaSignedChild {
                        subject: issuer_cert.subject.clone(),
                    });
                }

                // Verify signature
                let tbs = cert.tbs_bytes();
                if !verify_signature(
                    cert.issuer_algorithm,
                    &issuer_cert.public_key,
                    &tbs,
                    &cert.signature,
                ) {
                    errors.push(ChainValidationError::SignatureVerificationFailed {
                        subject: cert.subject.clone(),
                        issuer: issuer_cert.subject.clone(),
                    });
                }
            }
        }

        // The root (last cert) must be self-signed and trusted
        let root = &chain[chain.len() - 1];
        if root.is_self_signed() {
            // Verify root self-signature
            let tbs = root.tbs_bytes();
            if !verify_signature(root.issuer_algorithm, &root.public_key, &tbs, &root.signature) {
                errors.push(ChainValidationError::SignatureVerificationFailed {
                    subject: root.subject.clone(),
                    issuer: root.issuer.clone(),
                });
            }
            // Must be in trust store
            if !self.trusted_roots.contains_key(&root.fingerprint) {
                errors.push(ChainValidationError::UntrustedRoot {
                    subject: root.subject.clone(),
                });
            }
        } else {
            // Non-self-signed root must be in trust store
            if !self.trusted_roots.contains_key(&root.fingerprint) {
                errors.push(ChainValidationError::UntrustedRoot {
                    subject: root.subject.clone(),
                });
            }
        }

        let valid = errors.is_empty();
        if valid {
            info!(
                chain_length = chain.len(),
                algorithms = ?algorithms_used,
                "Certificate chain validated successfully"
            );
        } else {
            warn!(
                chain_length = chain.len(),
                error_count = errors.len(),
                "Certificate chain validation failed"
            );
        }

        ChainValidationResult {
            valid,
            errors,
            warnings,
            chain_length: chain.len(),
            algorithms_used,
        }
    }
}

// ---------------------------------------------------------------------------
// Signature Verification (multi-algorithm)
// ---------------------------------------------------------------------------

/// Verify a signature using the specified algorithm.
pub fn verify_signature(
    algorithm: ChainCertAlgorithm,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        ChainCertAlgorithm::EcdsaP256 => verify_ecdsa_p256(public_key, data, signature),
        ChainCertAlgorithm::Ed25519 => verify_ed25519(public_key, data, signature),
        ChainCertAlgorithm::MlDsa65 => verify_mldsa65(public_key, data, signature),
    }
}

fn verify_ecdsa_p256(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    let vk = match p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match p256::ecdsa::DerSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(data, &sig).is_ok()
}

fn verify_ed25519(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier as _;
    let pk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match ed25519_dalek::Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(data, &sig).is_ok()
}

fn verify_mldsa65(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    pqc::ml_dsa_verify(public_key, data, signature).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Certificate Generation Helpers
// ---------------------------------------------------------------------------

/// Generate a serial number.
fn generate_serial() -> String {
    let mut buf = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// Compute SHA-256 fingerprint of a public key.
fn compute_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    hash[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Sign data with the specified algorithm using the given private key.
fn sign_data(algorithm: ChainCertAlgorithm, private_key: &[u8], data: &[u8]) -> Vec<u8> {
    match algorithm {
        ChainCertAlgorithm::EcdsaP256 => {
            use p256::ecdsa::signature::Signer as _;
            let sk = p256::ecdsa::SigningKey::from_slice(private_key)
                .expect("valid ECDSA-P256 key");
            let sig: p256::ecdsa::DerSignature = sk.sign(data);
            sig.to_bytes().to_vec()
        }
        ChainCertAlgorithm::Ed25519 => {
            use ed25519_dalek::Signer as _;
            let sk_bytes: [u8; 32] = private_key.try_into().expect("Ed25519 key must be 32 bytes");
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            let sig = sk.sign(data);
            sig.to_bytes().to_vec()
        }
        ChainCertAlgorithm::MlDsa65 => {
            pqc::ml_dsa_sign(private_key, data).expect("ML-DSA-65 signing failed")
        }
    }
}

use rand_core::RngCore;

/// Create a self-signed root CA certificate.
pub fn create_root_ca(
    subject: &str,
    algorithm: ChainCertAlgorithm,
    validity_days: u64,
) -> CertKeyPair {
    let now = current_unix_timestamp();
    let not_after = now + validity_days * 86400;
    let serial = generate_serial();

    let (public_key, private_key) = generate_keypair(algorithm);
    let fingerprint = compute_fingerprint(&public_key);

    let mut cert = ManagedCertificate {
        subject: subject.to_string(),
        issuer: subject.to_string(),
        algorithm,
        public_key,
        signature: Vec::new(),
        issuer_algorithm: algorithm,
        not_before: now,
        not_after,
        is_ca: true,
        fingerprint,
        serial,
    };

    let tbs = cert.tbs_bytes();
    cert.signature = sign_data(algorithm, &private_key, &tbs);

    CertKeyPair {
        cert,
        private_key,
    }
}

/// Create a certificate signed by an issuer.
pub fn create_signed_cert(
    subject: &str,
    algorithm: ChainCertAlgorithm,
    issuer_kp: &CertKeyPair,
    validity_days: u64,
    is_ca: bool,
) -> CertKeyPair {
    let now = current_unix_timestamp();
    let not_after = now + validity_days * 86400;
    let serial = generate_serial();

    let (public_key, private_key) = generate_keypair(algorithm);
    let fingerprint = compute_fingerprint(&public_key);

    let mut cert = ManagedCertificate {
        subject: subject.to_string(),
        issuer: issuer_kp.cert.subject.clone(),
        algorithm,
        public_key,
        signature: Vec::new(),
        issuer_algorithm: issuer_kp.cert.algorithm,
        not_before: now,
        not_after,
        is_ca,
        fingerprint,
        serial,
    };

    let tbs = cert.tbs_bytes();
    cert.signature = sign_data(issuer_kp.cert.algorithm, &issuer_kp.private_key, &tbs);

    CertKeyPair {
        cert,
        private_key,
    }
}

/// Create a certificate with explicit timing for testing near-expiry / expired certs.
pub fn create_cert_with_timing(
    subject: &str,
    algorithm: ChainCertAlgorithm,
    issuer_kp: &CertKeyPair,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
) -> CertKeyPair {
    let serial = generate_serial();
    let (public_key, private_key) = generate_keypair(algorithm);
    let fingerprint = compute_fingerprint(&public_key);

    let mut cert = ManagedCertificate {
        subject: subject.to_string(),
        issuer: issuer_kp.cert.subject.clone(),
        algorithm,
        public_key,
        signature: Vec::new(),
        issuer_algorithm: issuer_kp.cert.algorithm,
        not_before,
        not_after,
        is_ca,
        fingerprint,
        serial,
    };

    let tbs = cert.tbs_bytes();
    cert.signature = sign_data(issuer_kp.cert.algorithm, &issuer_kp.private_key, &tbs);

    CertKeyPair {
        cert,
        private_key,
    }
}

fn generate_keypair(algorithm: ChainCertAlgorithm) -> (Vec<u8>, Vec<u8>) {
    match algorithm {
        ChainCertAlgorithm::EcdsaP256 => {
            let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
            let vk = p256::ecdsa::VerifyingKey::from(&sk);
            let pk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            let sk_bytes = sk.to_bytes().to_vec();
            (pk_bytes, sk_bytes)
        }
        ChainCertAlgorithm::Ed25519 => {
            let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            let vk = sk.verifying_key();
            let pk_bytes = vk.to_bytes().to_vec();
            let sk_bytes = sk.to_bytes().to_vec();
            (pk_bytes, sk_bytes)
        }
        ChainCertAlgorithm::MlDsa65 => {
            let kp = pqc::generate_ml_dsa_keypair();
            (kp.public_key, kp.seed)
        }
    }
}

/// Build a complete hybrid test chain: ECDSA-P256 Root -> Ed25519 Intermediate -> ML-DSA-65 Leaf.
pub fn build_hybrid_test_chain() -> (Vec<ManagedCertificate>, TrustStore) {
    let root_kp = create_root_ca("PQC Root CA (ECDSA-P256)", ChainCertAlgorithm::EcdsaP256, 3650);
    let intermediate_kp = create_signed_cert(
        "PQC Intermediate CA (Ed25519)",
        ChainCertAlgorithm::Ed25519,
        &root_kp,
        1825,
        true,
    );
    let leaf_kp = create_signed_cert(
        "PQC Leaf Server (ML-DSA-65)",
        ChainCertAlgorithm::MlDsa65,
        &intermediate_kp,
        365,
        false,
    );

    let chain = vec![leaf_kp.cert, intermediate_kp.cert, root_kp.cert.clone()];

    let mut store = TrustStore::new(30);
    store.add_trusted_root(root_kp.cert);

    (chain, store)
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_chain_ecdsa_ed25519_mldsa() {
        let (chain, store) = build_hybrid_test_chain();
        let result = store.validate_chain(&chain);
        assert!(result.valid, "Hybrid chain should be valid: {:?}", result.errors);
        assert_eq!(result.chain_length, 3);
        assert!(result.algorithms_used.contains(&ChainCertAlgorithm::EcdsaP256));
        assert!(result.algorithms_used.contains(&ChainCertAlgorithm::Ed25519));
        assert!(result.algorithms_used.contains(&ChainCertAlgorithm::MlDsa65));
    }

    #[test]
    fn test_single_algorithm_ecdsa_chain() {
        let root_kp = create_root_ca("ECDSA Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let leaf_kp = create_signed_cert(
            "ECDSA Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(result.valid, "ECDSA-only chain should be valid: {:?}", result.errors);
        assert_eq!(result.chain_length, 2);
    }

    #[test]
    fn test_single_algorithm_ed25519_chain() {
        let root_kp = create_root_ca("Ed25519 Root", ChainCertAlgorithm::Ed25519, 3650);
        let leaf_kp = create_signed_cert(
            "Ed25519 Leaf",
            ChainCertAlgorithm::Ed25519,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(result.valid, "Ed25519-only chain should be valid: {:?}", result.errors);
    }

    #[test]
    fn test_single_algorithm_mldsa_chain() {
        let root_kp = create_root_ca("MLDSA Root", ChainCertAlgorithm::MlDsa65, 3650);
        let leaf_kp = create_signed_cert(
            "MLDSA Leaf",
            ChainCertAlgorithm::MlDsa65,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(result.valid, "ML-DSA-only chain should be valid: {:?}", result.errors);
    }

    #[test]
    fn test_empty_chain_rejected() {
        let store = TrustStore::new(30);
        let result = store.validate_chain(&[]);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::EmptyChain)));
    }

    #[test]
    fn test_untrusted_root_rejected() {
        let root_kp = create_root_ca("Untrusted Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let leaf_kp = create_signed_cert(
            "Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert, root_kp.cert]; // root NOT in trust store
        let store = TrustStore::new(30);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::UntrustedRoot { .. })));
    }

    #[test]
    fn test_revoked_cert_rejected() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let leaf_kp = create_signed_cert(
            "Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert.clone(), root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);
        store.revoke_certificate(&leaf_kp.cert.serial);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::RevokedCertificate { .. })));
    }

    #[test]
    fn test_pinning_success() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let leaf_kp = create_signed_cert(
            "Pinned Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert.clone(), root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);
        store.pin_certificate("Pinned Leaf", &leaf_kp.cert.fingerprint);

        let result = store.validate_chain(&chain);
        assert!(result.valid, "Pinned cert should pass: {:?}", result.errors);
    }

    #[test]
    fn test_pinning_violation_rejected() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let leaf_kp = create_signed_cert(
            "Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);
        // Pin to a wrong fingerprint
        store.pin_certificate("Leaf", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff");

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::PinningViolation { .. })));
    }

    #[test]
    fn test_expired_cert_rejected() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let now = current_unix_timestamp();
        let expired_kp = create_cert_with_timing(
            "Expired Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            now - 200 * 86400,
            now - 100 * 86400, // expired 100 days ago
            false,
        );
        let chain = vec![expired_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::ExpiredCertificate { .. })));
    }

    #[test]
    fn test_not_yet_valid_rejected() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let now = current_unix_timestamp();
        let future_kp = create_cert_with_timing(
            "Future Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            now + 100 * 86400, // valid in 100 days
            now + 200 * 86400,
            false,
        );
        let chain = vec![future_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::NotYetValid { .. })));
    }

    #[test]
    fn test_expiry_warning() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let now = current_unix_timestamp();
        let near_expiry_kp = create_cert_with_timing(
            "Near Expiry Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            now - 86400,
            now + 10 * 86400, // expires in 10 days
            false,
        );
        let store = TrustStore::new(30);
        let warnings = store.check_expiry_warnings(&near_expiry_kp.cert);
        assert!(!warnings.is_empty(), "Should have expiry warning");
        assert!(warnings[0].contains("expires in"), "Warning: {}", warnings[0]);
    }

    #[test]
    fn test_chain_broken_issuer_mismatch() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let other_root_kp = create_root_ca("Other Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let leaf_kp = create_signed_cert(
            "Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        // Chain has leaf signed by root_kp but we put other_root_kp as the issuer cert
        let chain = vec![leaf_kp.cert, other_root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(other_root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        // Should fail with both chain broken and signature verification failed
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::ChainBroken { .. })));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        let mut leaf_kp = create_signed_cert(
            "Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false,
        );
        // Tamper with the signature
        if let Some(byte) = leaf_kp.cert.signature.last_mut() {
            *byte ^= 0xFF;
        }
        let chain = vec![leaf_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::SignatureVerificationFailed { .. })));
    }

    #[test]
    fn test_trust_store_add_remove() {
        let mut store = TrustStore::new(30);
        assert_eq!(store.trusted_root_count(), 0);

        let root = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 365);
        let fp = root.cert.fingerprint.clone();
        store.add_trusted_root(root.cert);
        assert_eq!(store.trusted_root_count(), 1);

        assert!(store.remove_trusted_root(&fp));
        assert_eq!(store.trusted_root_count(), 0);
        assert!(!store.remove_trusted_root(&fp)); // already removed
    }

    #[test]
    fn test_revoke_unrevoke() {
        let mut store = TrustStore::new(30);
        assert!(!store.is_revoked("serial-1"));
        store.revoke_certificate("serial-1");
        assert!(store.is_revoked("serial-1"));
        store.unrevoke_certificate("serial-1");
        assert!(!store.is_revoked("serial-1"));
    }

    #[test]
    fn test_self_signed_root_only() {
        let root_kp = create_root_ca("Self-Signed Root", ChainCertAlgorithm::MlDsa65, 3650);
        let chain = vec![root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(result.valid, "Single self-signed root should be valid: {:?}", result.errors);
        assert_eq!(result.chain_length, 1);
    }

    #[test]
    fn test_long_hybrid_chain_4_levels() {
        let root = create_root_ca("L4 Root (ECDSA)", ChainCertAlgorithm::EcdsaP256, 3650);
        let inter1 = create_signed_cert(
            "L4 Inter1 (Ed25519)",
            ChainCertAlgorithm::Ed25519,
            &root,
            1825,
            true,
        );
        let inter2 = create_signed_cert(
            "L4 Inter2 (MLDSA)",
            ChainCertAlgorithm::MlDsa65,
            &inter1,
            1000,
            true,
        );
        let leaf = create_signed_cert(
            "L4 Leaf (ECDSA)",
            ChainCertAlgorithm::EcdsaP256,
            &inter2,
            365,
            false,
        );
        let chain = vec![leaf.cert, inter2.cert, inter1.cert, root.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root.cert);

        let result = store.validate_chain(&chain);
        assert!(result.valid, "4-level hybrid chain should be valid: {:?}", result.errors);
        assert_eq!(result.chain_length, 4);
    }

    #[test]
    fn test_non_ca_signing_child_rejected() {
        let root_kp = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 3650);
        // Create a non-CA intermediate
        let non_ca_kp = create_signed_cert(
            "Non-CA Inter",
            ChainCertAlgorithm::EcdsaP256,
            &root_kp,
            365,
            false, // NOT a CA
        );
        let leaf_kp = create_signed_cert(
            "Leaf",
            ChainCertAlgorithm::EcdsaP256,
            &non_ca_kp,
            365,
            false,
        );
        let chain = vec![leaf_kp.cert, non_ca_kp.cert, root_kp.cert.clone()];
        let mut store = TrustStore::new(30);
        store.add_trusted_root(root_kp.cert);

        let result = store.validate_chain(&chain);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| matches!(e, ChainValidationError::NonCaSignedChild { .. })));
    }

    #[test]
    fn test_pin_unpin() {
        let mut store = TrustStore::new(30);
        store.pin_certificate("Server", "fp:aa:bb");
        assert!(store.pinned_fingerprints.contains_key("Server"));
        store.unpin_certificate("Server", "fp:aa:bb");
        assert!(!store.pinned_fingerprints.contains_key("Server"));
    }

    #[test]
    fn test_cert_days_until_expiry() {
        let root = create_root_ca("Root", ChainCertAlgorithm::EcdsaP256, 365);
        let days = root.cert.days_until_expiry();
        assert!(days >= 364 && days <= 365, "Days until expiry: {days}");
    }

    #[test]
    fn test_cert_fingerprint_unique() {
        let kp1 = create_root_ca("Root1", ChainCertAlgorithm::EcdsaP256, 365);
        let kp2 = create_root_ca("Root2", ChainCertAlgorithm::EcdsaP256, 365);
        assert_ne!(kp1.cert.fingerprint, kp2.cert.fingerprint);
    }
}