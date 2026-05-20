//! Shamir's Secret Sharing and threshold signatures.
//!
//! Implements:
//! - Threshold key splitting for master keys (SSS over GF(256))
//! - Distributed signature generation (multiple parties sign)
//! - Quorum-based key recovery
//! - Stateful threshold key manager with recovery codes

use rand_core::RngCore;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::certgen::pqc;
use crate::signature::hex_encode;

// ---------------------------------------------------------------------------
// GF(256) Arithmetic — field used by Shamir's Secret Sharing
// ---------------------------------------------------------------------------

/// Multiply two elements in GF(256) using the AES irreducible polynomial
/// x^8 + x^4 + x^3 + x + 1 (0x11B).
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B; // reduction modulo x^8+x^4+x^3+x+1
        }
        b >>= 1;
    }
    result
}

/// Raise to a power in GF(256).
fn gf256_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256): a^{-1} = a^{254} by Fermat's little theorem.
fn gf256_inv(a: u8) -> u8 {
    assert!(a != 0, "Cannot invert 0 in GF(256)");
    gf256_pow(a, 254)
}

/// Evaluate a polynomial at x in GF(256).
/// `coeffs[0]` is the constant term (the secret).
fn gf256_poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    let mut x_power = 1u8;
    for &c in coeffs {
        result ^= gf256_mul(c, x_power);
        x_power = gf256_mul(x_power, x);
    }
    result
}

/// Lagrange interpolation at x=0 in GF(256).
/// `points` is a slice of (x, y) pairs.
fn gf256_lagrange_interpolate_zero(points: &[(u8, u8)]) -> u8 {
    let mut result = 0u8;
    for i in 0..points.len() {
        let (x_i, y_i) = points[i];
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for j in 0..points.len() {
            if i == j {
                continue;
            }
            let (x_j, _) = points[j];
            // In GF(2^8), subtraction = XOR, and 0 - x_j = x_j
            numerator = gf256_mul(numerator, x_j);
            denominator = gf256_mul(denominator, x_i ^ x_j);
        }
        let lagrange_coeff = gf256_mul(numerator, gf256_inv(denominator));
        result ^= gf256_mul(y_i, lagrange_coeff);
    }
    result
}

// ---------------------------------------------------------------------------
// Share Types
// ---------------------------------------------------------------------------

/// A single share from Shamir's Secret Sharing.
#[derive(Debug, Clone, PartialEq)]
pub struct Share {
    /// Share index (1-based, must be non-zero in GF(256)).
    pub id: u8,
    /// Share data (one byte per byte of the original secret).
    pub data: Vec<u8>,
}

/// Configuration for a secret sharing scheme.
#[derive(Debug, Clone, Copy)]
pub struct SharingConfig {
    /// Minimum number of shares needed to reconstruct (threshold).
    pub threshold: u8,
    /// Total number of shares to generate.
    pub total_shares: u8,
}

impl SharingConfig {
    pub fn new(threshold: u8, total_shares: u8) -> Self {
        assert!(threshold >= 2, "Threshold must be at least 2");
        assert!(total_shares >= threshold, "Total shares must be >= threshold");
        // GF(256) supports share IDs 1..=255; enforced by the u8 type.
        Self {
            threshold,
            total_shares,
        }
    }
}

// ---------------------------------------------------------------------------
// Shamir's Secret Sharing — Core Operations
// ---------------------------------------------------------------------------

/// Split a secret into shares using Shamir's Secret Sharing over GF(256).
///
/// Each byte of the secret is independently split using a random polynomial
/// of degree `threshold - 1`, with the secret byte as the constant term.
pub fn split_secret(secret: &[u8], config: SharingConfig) -> Vec<Share> {
    assert!(!secret.is_empty(), "Secret must not be empty");

    let mut shares: Vec<Share> = (1..=config.total_shares)
        .map(|id| Share {
            id,
            data: Vec::with_capacity(secret.len()),
        })
        .collect();

    // For each byte of the secret, create a random polynomial and evaluate
    for &secret_byte in secret {
        // Polynomial coefficients: [secret_byte, random_1, ..., random_{t-1}]
        let mut coeffs = vec![secret_byte];
        let mut rand_bytes = vec![0u8; (config.threshold - 1) as usize];
        rand_core::OsRng.fill_bytes(&mut rand_bytes);
        coeffs.extend_from_slice(&rand_bytes);

        // Evaluate polynomial at each share's x-coordinate (1, 2, ..., n)
        for share in shares.iter_mut() {
            let y = gf256_poly_eval(&coeffs, share.id);
            share.data.push(y);
        }
    }

    info!(
        secret_len = secret.len(),
        threshold = config.threshold,
        total_shares = config.total_shares,
        "Secret split into shares"
    );

    shares
}

/// Reconstruct a secret from `threshold` or more shares.
///
/// Returns the reconstructed secret bytes. Providing fewer than `threshold`
/// shares yields incorrect output (by design — no error, just wrong data).
pub fn reconstruct_secret(shares: &[Share]) -> Vec<u8> {
    assert!(!shares.is_empty(), "Need at least one share");
    let secret_len = shares[0].data.len();
    assert!(
        shares.iter().all(|s| s.data.len() == secret_len),
        "All shares must have the same data length"
    );

    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let points: Vec<(u8, u8)> = shares
            .iter()
            .map(|s| (s.id, s.data[byte_idx]))
            .collect();
        let reconstructed_byte = gf256_lagrange_interpolate_zero(&points);
        secret.push(reconstructed_byte);
    }

    info!(
        shares_used = shares.len(),
        secret_len = secret.len(),
        "Secret reconstructed from shares"
    );

    secret
}

// ---------------------------------------------------------------------------
// Distributed Signature Generation
// ---------------------------------------------------------------------------

/// A party in the distributed signature scheme.
/// Each party holds one share of the ML-DSA-65 seed.
#[derive(Debug, Clone)]
pub struct SigningParty {
    pub party_id: u8,
    pub share: Share,
    pub public_key: Vec<u8>,
}

/// Result of a distributed (multi-party) signing operation.
#[derive(Debug, Clone)]
pub struct DistributedSignatureResult {
    pub signature: Vec<u8>,
    pub message_hash: String,
    pub parties_involved: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Set up distributed signing by splitting an ML-DSA-65 seed among parties.
/// Returns the parties and the public key.
pub fn setup_distributed_signing(
    config: SharingConfig,
) -> (Vec<SigningParty>, Vec<u8>) {
    let kp = pqc::generate_ml_dsa_keypair();
    let shares = split_secret(&kp.seed, config);

    let parties: Vec<SigningParty> = shares
        .into_iter()
        .map(|share| SigningParty {
            party_id: share.id,
            share,
            public_key: kp.public_key.clone(),
        })
        .collect();

    info!(
        party_count = parties.len(),
        "Distributed signing parties created"
    );

    (parties, kp.public_key)
}

/// Perform distributed signing: a quorum of parties contribute their shares
/// to reconstruct the signing key and sign the message.
///
/// The reconstructed key is used only transiently and is immediately dropped.
pub fn distributed_sign(
    parties: &[&SigningParty],
    message: &[u8],
) -> anyhow::Result<DistributedSignatureResult> {
    assert!(!parties.is_empty(), "Need at least one party to sign");

    // Collect shares from participating parties
    let shares: Vec<Share> = parties.iter().map(|p| p.share.clone()).collect();
    let party_ids: Vec<u8> = parties.iter().map(|p| p.party_id).collect();

    // Reconstruct the seed from shares
    let seed = reconstruct_secret(&shares);

    // Sign with the reconstructed seed
    let signature = pqc::ml_dsa_sign(&seed, message)?;
    let message_hash = hex_encode(&Sha256::digest(message));

    info!(
        parties = ?party_ids,
        message_len = message.len(),
        sig_len = signature.len(),
        "Distributed signature generated"
    );

    Ok(DistributedSignatureResult {
        signature,
        message_hash,
        parties_involved: party_ids,
        public_key: parties[0].public_key.clone(),
    })
}

/// Verify a distributed signature against a public key.
pub fn verify_distributed_signature(
    result: &DistributedSignatureResult,
    message: &[u8],
) -> bool {
    pqc::ml_dsa_verify(&result.public_key, message, &result.signature).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Quorum Key Recovery
// ---------------------------------------------------------------------------

/// Configuration for quorum-based key recovery.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    pub sharing_config: SharingConfig,
    /// Human-readable recovery codes (hex-encoded share data).
    pub recovery_codes: Vec<String>,
}

/// Generate recovery codes from shares.
pub fn generate_recovery_codes(shares: &[Share]) -> Vec<String> {
    shares
        .iter()
        .map(|s| {
            let id_hex = format!("{:02x}", s.id);
            let data_hex = hex_encode(&s.data);
            format!("{id_hex}-{data_hex}")
        })
        .collect()
}

/// Parse a recovery code back into a share.
pub fn parse_recovery_code(code: &str) -> anyhow::Result<Share> {
    let parts: Vec<&str> = code.splitn(2, '-').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid recovery code format (expected 'id-data')");
    }
    let id = u8::from_str_radix(parts[0], 16)
        .map_err(|e| anyhow::anyhow!("Invalid share ID in recovery code: {e}"))?;
    let data: Vec<u8> = (0..parts[1].len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&parts[1][i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex in recovery code: {e}"))
        })
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(Share { id, data })
}

/// Recover a secret from recovery codes.
pub fn recover_from_codes(codes: &[&str]) -> anyhow::Result<Vec<u8>> {
    let shares: Vec<Share> = codes
        .iter()
        .map(|c| parse_recovery_code(c))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(reconstruct_secret(&shares))
}

// ---------------------------------------------------------------------------
// Threshold Key Manager — Stateful
// ---------------------------------------------------------------------------

/// Stateful manager for threshold key operations.
pub struct ThresholdKeyManager {
    /// ML-DSA-65 public key.
    public_key: Vec<u8>,
    /// Active shares distributed to parties.
    distributed_shares: Vec<Share>,
    /// Threshold configuration.
    config: SharingConfig,
    /// Recovery codes (hex-encoded shares).
    recovery_codes: Vec<String>,
    /// Fingerprint of the public key.
    fingerprint: String,
    /// Number of signatures generated.
    signature_count: u64,
}

impl ThresholdKeyManager {
    /// Create a new threshold key manager.
    /// Generates a fresh ML-DSA-65 keypair, splits the seed into shares.
    pub fn new(config: SharingConfig) -> Self {
        let kp = pqc::generate_ml_dsa_keypair();
        let shares = split_secret(&kp.seed, config);
        let recovery_codes = generate_recovery_codes(&shares);
        let fingerprint = hex_encode(&Sha256::digest(&kp.public_key)[..16]);

        info!(
            threshold = config.threshold,
            total_shares = config.total_shares,
            fingerprint = %fingerprint,
            "Threshold key manager initialized"
        );

        Self {
            public_key: kp.public_key,
            distributed_shares: shares,
            config,
            recovery_codes,
            fingerprint,
            signature_count: 0,
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the key fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Get the threshold configuration.
    pub fn config(&self) -> SharingConfig {
        self.config
    }

    /// Get the recovery codes (should be stored securely offline).
    pub fn recovery_codes(&self) -> &[String] {
        &self.recovery_codes
    }

    /// Get a specific share by ID.
    pub fn get_share(&self, id: u8) -> Option<&Share> {
        self.distributed_shares.iter().find(|s| s.id == id)
    }

    /// Sign a message using a quorum of shares (by share IDs).
    /// Returns None if insufficient shares.
    pub fn sign_with_quorum(
        &mut self,
        share_ids: &[u8],
        message: &[u8],
    ) -> Option<Vec<u8>> {
        if share_ids.len() < self.config.threshold as usize {
            warn!(
                provided = share_ids.len(),
                required = self.config.threshold,
                "Insufficient shares for quorum signing"
            );
            return None;
        }

        let shares: Vec<Share> = share_ids
            .iter()
            .filter_map(|&id| self.get_share(id).cloned())
            .collect();

        if shares.len() < self.config.threshold as usize {
            warn!("Some share IDs not found");
            return None;
        }

        let seed = reconstruct_secret(&shares);
        match pqc::ml_dsa_sign(&seed, message) {
            Ok(sig) => {
                self.signature_count += 1;
                info!(
                    sig_count = self.signature_count,
                    quorum_size = shares.len(),
                    "Quorum signature generated"
                );
                Some(sig)
            }
            Err(e) => {
                warn!(error = %e, "Quorum signing failed");
                None
            }
        }
    }

    /// Verify a signature against this manager's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        pqc::ml_dsa_verify(&self.public_key, message, signature).unwrap_or(false)
    }

    /// Recover the signing capability from recovery codes.
    /// Returns a new manager with the same key material.
    pub fn recover_from_codes(
        codes: &[&str],
        config: SharingConfig,
    ) -> anyhow::Result<Self> {
        let shares: Vec<Share> = codes
            .iter()
            .map(|c| parse_recovery_code(c))
            .collect::<Result<Vec<_>, _>>()?;

        let seed = reconstruct_secret(&shares);

        // Regenerate the keypair from the recovered seed
        let seed_arr = ml_dsa::Seed::try_from(seed.as_slice())
            .map_err(|_| anyhow::anyhow!("Invalid recovered seed length"))?;
        use ml_dsa::signature::Keypair as _;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_arr);
        let vk = sk.verifying_key();
        let public_key = vk.encode().to_vec();

        // Re-split with new randomness
        let new_shares = split_secret(&seed, config);
        let recovery_codes = generate_recovery_codes(&new_shares);
        let fingerprint = hex_encode(&Sha256::digest(&public_key)[..16]);

        info!(
            fingerprint = %fingerprint,
            "Key manager recovered from recovery codes"
        );

        Ok(Self {
            public_key,
            distributed_shares: new_shares,
            config,
            recovery_codes,
            fingerprint,
            signature_count: 0,
        })
    }

    /// Number of signatures generated so far.
    pub fn signature_count(&self) -> u64 {
        self.signature_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- GF(256) arithmetic tests --

    #[test]
    fn test_gf256_mul_identity() {
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 1), a, "a*1 should equal a for a={a}");
        }
    }

    #[test]
    fn test_gf256_mul_zero() {
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 0), 0, "a*0 should be 0 for a={a}");
        }
    }

    #[test]
    fn test_gf256_mul_commutativity() {
        for a in [1u8, 2, 3, 17, 100, 200, 255] {
            for b in [1u8, 2, 3, 42, 128, 254, 255] {
                assert_eq!(
                    gf256_mul(a, b),
                    gf256_mul(b, a),
                    "Commutativity failed for a={a}, b={b}"
                );
            }
        }
    }

    #[test]
    fn test_gf256_inverse() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a * a^-1 should be 1 for a={a}");
        }
    }

    // -- Secret Sharing tests --

    #[test]
    fn test_split_reconstruct_basic() {
        let secret = b"hello";
        let config = SharingConfig::new(3, 5);
        let shares = split_secret(secret, config);
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold shares
        let reconstructed = reconstruct_secret(&shares[0..3]);
        assert_eq!(reconstructed, secret, "Reconstruction with 3 of 5 should work");
    }

    #[test]
    fn test_split_reconstruct_all_shares() {
        let secret = b"full reconstruction";
        let config = SharingConfig::new(3, 5);
        let shares = split_secret(secret, config);

        let reconstructed = reconstruct_secret(&shares);
        assert_eq!(reconstructed, secret, "Reconstruction with all shares should work");
    }

    #[test]
    fn test_split_reconstruct_mldsa_seed() {
        let kp = pqc::generate_ml_dsa_keypair();
        assert_eq!(kp.seed.len(), 32);

        let config = SharingConfig::new(3, 5);
        let shares = split_secret(&kp.seed, config);

        // Reconstruct using shares 2, 4, 5
        let subset = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let reconstructed = reconstruct_secret(&subset);
        assert_eq!(reconstructed, kp.seed, "ML-DSA seed should reconstruct perfectly");

        // Verify the reconstructed seed can sign
        let message = b"threshold test message";
        let sig = pqc::ml_dsa_sign(&reconstructed, message).unwrap();
        assert!(pqc::ml_dsa_verify(&kp.public_key, message, &sig).unwrap());
    }

    #[test]
    fn test_insufficient_shares_wrong_result() {
        let secret = b"secret data";
        let config = SharingConfig::new(3, 5);
        let shares = split_secret(secret, config);

        // Only 2 shares (below threshold of 3) — result should differ
        let reconstructed = reconstruct_secret(&shares[0..2]);
        assert_ne!(
            reconstructed, secret,
            "Reconstruction with fewer than threshold shares should yield wrong result"
        );
    }

    #[test]
    fn test_different_share_combinations() {
        let secret = b"any subset works";
        let config = SharingConfig::new(3, 5);
        let shares = split_secret(secret, config);

        // Try all C(5,3) = 10 combinations
        let combos = vec![
            vec![0, 1, 2], vec![0, 1, 3], vec![0, 1, 4],
            vec![0, 2, 3], vec![0, 2, 4], vec![0, 3, 4],
            vec![1, 2, 3], vec![1, 2, 4], vec![1, 3, 4],
            vec![2, 3, 4],
        ];
        for combo in combos {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            let reconstructed = reconstruct_secret(&subset);
            assert_eq!(
                reconstructed, secret,
                "Failed for combination {:?}",
                combo
            );
        }
    }

    #[test]
    fn test_threshold_2_of_3() {
        let secret = b"minimal threshold";
        let config = SharingConfig::new(2, 3);
        let shares = split_secret(secret, config);
        assert_eq!(shares.len(), 3);

        for i in 0..3 {
            for j in (i + 1)..3 {
                let subset = vec![shares[i].clone(), shares[j].clone()];
                let reconstructed = reconstruct_secret(&subset);
                assert_eq!(reconstructed, secret, "Failed for pair ({i}, {j})");
            }
        }
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = &[42u8];
        let config = SharingConfig::new(2, 3);
        let shares = split_secret(secret, config);
        let reconstructed = reconstruct_secret(&shares[0..2]);
        assert_eq!(reconstructed, secret);
    }

    // -- Distributed Signing tests --

    #[test]
    fn test_distributed_signing() {
        let config = SharingConfig::new(3, 5);
        let (parties, public_key) = setup_distributed_signing(config);
        assert_eq!(parties.len(), 5);

        let message = b"distributed signature test message";
        let quorum: Vec<&SigningParty> = parties[0..3].iter().collect();
        let result = distributed_sign(&quorum, message).unwrap();

        assert!(verify_distributed_signature(&result, message));
        assert!(!verify_distributed_signature(&result, b"wrong message"));
        assert_eq!(result.parties_involved, vec![1, 2, 3]);
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn test_distributed_signing_different_quorum() {
        let config = SharingConfig::new(3, 5);
        let (parties, _) = setup_distributed_signing(config);

        let message = b"another test";
        // Use parties 2, 4, 5
        let quorum: Vec<&SigningParty> = vec![&parties[1], &parties[3], &parties[4]];
        let result = distributed_sign(&quorum, message).unwrap();

        assert!(verify_distributed_signature(&result, message));
    }

    // -- Recovery Code tests --

    #[test]
    fn test_recovery_codes_roundtrip() {
        let secret = b"recover me";
        let config = SharingConfig::new(3, 5);
        let shares = split_secret(secret, config);

        let codes = generate_recovery_codes(&shares);
        assert_eq!(codes.len(), 5);

        // Parse codes back and reconstruct
        let parsed: Vec<Share> = codes[0..3]
            .iter()
            .map(|c| parse_recovery_code(c).unwrap())
            .collect();
        let reconstructed = reconstruct_secret(&parsed);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_recover_from_codes() {
        let secret = b"code recovery";
        let config = SharingConfig::new(2, 4);
        let shares = split_secret(secret, config);
        let codes = generate_recovery_codes(&shares);

        let code_refs: Vec<&str> = codes[1..3].iter().map(|s| s.as_str()).collect();
        let recovered = recover_from_codes(&code_refs).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_invalid_recovery_code() {
        assert!(parse_recovery_code("invalid").is_err());
        assert!(parse_recovery_code("zz-aabb").is_err());
    }

    // -- Threshold Key Manager tests --

    #[test]
    fn test_threshold_key_manager_lifecycle() {
        let config = SharingConfig::new(3, 5);
        let mut manager = ThresholdKeyManager::new(config);

        assert_eq!(manager.signature_count(), 0);
        assert!(!manager.fingerprint().is_empty());
        assert_eq!(manager.recovery_codes().len(), 5);

        let message = b"manager signing test";

        // Sign with quorum of 3
        let sig = manager.sign_with_quorum(&[1, 2, 3], message).unwrap();
        assert!(manager.verify(message, &sig));
        assert_eq!(manager.signature_count(), 1);

        // Sign again with different quorum
        let sig2 = manager.sign_with_quorum(&[2, 4, 5], message).unwrap();
        assert!(manager.verify(message, &sig2));
        assert_eq!(manager.signature_count(), 2);
    }

    #[test]
    fn test_threshold_key_manager_insufficient_quorum() {
        let config = SharingConfig::new(3, 5);
        let mut manager = ThresholdKeyManager::new(config);

        // Only 2 shares — below threshold of 3
        let result = manager.sign_with_quorum(&[1, 2], b"test");
        assert!(result.is_none(), "Should fail with insufficient quorum");
    }

    #[test]
    fn test_threshold_key_manager_recovery() {
        let config = SharingConfig::new(3, 5);
        let original_manager = ThresholdKeyManager::new(config);

        let message = b"recovery test message";

        // Get recovery codes
        let codes = original_manager.recovery_codes().to_vec();
        let code_refs: Vec<&str> = codes[0..3].iter().map(|s| s.as_str()).collect();

        // Recover the manager
        let mut recovered = ThresholdKeyManager::recover_from_codes(&code_refs, config).unwrap();
        assert_eq!(recovered.public_key(), original_manager.public_key());

        // Sign with the recovered manager
        let sig = recovered.sign_with_quorum(&[1, 2, 3], message).unwrap();
        assert!(recovered.verify(message, &sig));

        // Verify with original public key
        assert!(
            pqc::ml_dsa_verify(original_manager.public_key(), message, &sig).unwrap()
        );
    }

    #[test]
    fn test_threshold_key_manager_get_share() {
        let config = SharingConfig::new(2, 3);
        let manager = ThresholdKeyManager::new(config);

        assert!(manager.get_share(1).is_some());
        assert!(manager.get_share(2).is_some());
        assert!(manager.get_share(3).is_some());
        assert!(manager.get_share(4).is_none());
    }

    #[test]
    fn test_large_secret_split() {
        // Test with a larger secret (256 bytes)
        let mut secret = vec![0u8; 256];
        rand_core::OsRng.fill_bytes(&mut secret);

        let config = SharingConfig::new(5, 10);
        let shares = split_secret(&secret, config);
        assert_eq!(shares.len(), 10);

        let reconstructed = reconstruct_secret(&shares[3..8]);
        assert_eq!(reconstructed, secret);
    }
}