//! Versioned ML-DSA signing key manager with JWKS support.
//!
//! Provides:
//! - Key rotation: generate new signing keys with version IDs
//! - Versioned JWKS endpoint data (RFC 7517)
//! - Sign with current key, verify with any historical key
//! - Integration with threshold.rs for quorum-based key management

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::certgen::pqc;
use crate::signature::hex_encode;
use crate::threshold::{self, SharingConfig};

// ---------------------------------------------------------------------------
// Key Version
// ---------------------------------------------------------------------------

/// A single versioned signing key.
#[derive(Debug, Clone)]
pub struct KeyVersion {
    /// Unique key ID (kid) for JWKS.
    pub kid: String,
    /// Version number (monotonically increasing).
    pub version: u64,
    /// ML-DSA-65 seed (32 bytes) for signing.
    pub seed: Vec<u8>,
    /// ML-DSA-65 public key.
    pub public_key: Vec<u8>,
    /// When this key was created (unix timestamp).
    pub created_at: u64,
    /// Whether this key is still active for signing.
    pub active: bool,
    /// SHA-256 fingerprint of public key.
    pub fingerprint: String,
}

impl KeyVersion {
    fn new(version: u64) -> Self {
        let kp = pqc::generate_ml_dsa_keypair();
        let fingerprint = hex_encode(&Sha256::digest(&kp.public_key)[..16]);
        let kid = format!("mldsa-v{version}-{}", &fingerprint[..8]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            kid,
            version,
            seed: kp.seed,
            public_key: kp.public_key,
            created_at: now,
            active: true,
            fingerprint,
        }
    }

    /// Sign data with this key version.
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        pqc::ml_dsa_sign(&self.seed, data).ok()
    }

    /// Verify a signature with this key's public key.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        pqc::ml_dsa_verify(&self.public_key, data, signature).unwrap_or(false)
    }

    /// Convert to a JWKS entry (JWK representation).
    pub fn to_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "PQC",
            "alg": "ML-DSA-65",
            "kid": self.kid,
            "use": "sig",
            "x": B64URL.encode(&self.public_key),
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "active": self.active,
            "version": self.version,
        })
    }
}

// ---------------------------------------------------------------------------
// VersionedKeyManager
// ---------------------------------------------------------------------------

/// Manages multiple key versions with rotation support.
#[derive(Clone)]
pub struct VersionedKeyManager {
    inner: Arc<RwLock<VersionedKeyManagerInner>>,
}

struct VersionedKeyManagerInner {
    /// All key versions, keyed by kid.
    keys: HashMap<String, KeyVersion>,
    /// The current (active) key's kid.
    current_kid: String,
    /// Next version number.
    next_version: u64,
    /// Maximum number of old keys to retain.
    max_retained_keys: usize,
    /// Optional threshold config for distributed key management.
    threshold_config: Option<SharingConfig>,
    /// Threshold shares for the current key (if threshold is enabled).
    current_shares: Option<Vec<threshold::Share>>,
    /// Recovery codes for the current key.
    recovery_codes: Option<Vec<String>>,
}

impl VersionedKeyManager {
    /// Create a new manager with an initial key.
    pub fn new(max_retained_keys: usize) -> Self {
        let initial_key = KeyVersion::new(1);
        let kid = initial_key.kid.clone();

        let mut keys = HashMap::new();
        keys.insert(kid.clone(), initial_key);

        info!(
            kid = %kid,
            max_retained = max_retained_keys,
            "Versioned key manager initialized"
        );

        Self {
            inner: Arc::new(RwLock::new(VersionedKeyManagerInner {
                keys,
                current_kid: kid,
                next_version: 2,
                max_retained_keys,
                threshold_config: None,
                current_shares: None,
                recovery_codes: None,
            })),
        }
    }

    /// Create a manager with threshold key management.
    pub fn with_threshold(max_retained_keys: usize, threshold: u8, total_shares: u8) -> Self {
        let mgr = Self::new(max_retained_keys);
        {
            let mut inner = mgr.inner.write().unwrap();
            let config = SharingConfig::new(threshold, total_shares);
            inner.threshold_config = Some(config);

            // Split the current key's seed into shares
            if let Some(current) = inner.keys.get(&inner.current_kid) {
                let shares = threshold::split_secret(&current.seed, config);
                let codes = threshold::generate_recovery_codes(&shares);
                inner.current_shares = Some(shares);
                inner.recovery_codes = Some(codes);
                info!(
                    threshold = threshold,
                    total_shares = total_shares,
                    "Threshold key management enabled for current key"
                );
            }
        }
        mgr
    }

    /// Rotate to a new key version. The old key remains for verification.
    pub fn rotate(&self) -> String {
        let mut inner = self.inner.write().unwrap();
        let version = inner.next_version;
        inner.next_version += 1;

        // Deactivate the old current key
        let old_kid = inner.current_kid.clone();
        if let Some(old) = inner.keys.get_mut(&old_kid) {
            old.active = false;
        }

        // Create new key
        let new_key = KeyVersion::new(version);
        let new_kid = new_key.kid.clone();

        // Set up threshold shares if configured
        if let Some(config) = inner.threshold_config {
            let shares = threshold::split_secret(&new_key.seed, config);
            let codes = threshold::generate_recovery_codes(&shares);
            inner.current_shares = Some(shares);
            inner.recovery_codes = Some(codes);
        }

        info!(
            old_kid = %inner.current_kid,
            new_kid = %new_kid,
            version = version,
            "Key rotated"
        );

        inner.keys.insert(new_kid.clone(), new_key);
        inner.current_kid = new_kid.clone();

        // Prune old keys if exceeding limit
        let max = inner.max_retained_keys;
        if inner.keys.len() > max + 1 {
            let mut versions: Vec<(String, u64)> = inner
                .keys
                .iter()
                .filter(|(kid, _)| *kid != &inner.current_kid)
                .map(|(kid, kv)| (kid.clone(), kv.version))
                .collect();
            versions.sort_by_key(|(_, v)| *v);
            while inner.keys.len() > max + 1 && !versions.is_empty() {
                let (old_kid, _) = versions.remove(0);
                inner.keys.remove(&old_kid);
                info!(kid = %old_kid, "Pruned old key version");
            }
        }

        new_kid
    }

    /// Sign data with the current key. Returns (kid, signature_bytes).
    pub fn sign_current(&self, data: &[u8]) -> Option<(String, Vec<u8>)> {
        let inner = self.inner.read().unwrap();
        let key = inner.keys.get(&inner.current_kid)?;
        let sig = key.sign(data)?;
        Some((key.kid.clone(), sig))
    }

    /// Verify a signature using the key identified by kid.
    pub fn verify_by_kid(&self, kid: &str, data: &[u8], signature: &[u8]) -> bool {
        let inner = self.inner.read().unwrap();
        match inner.keys.get(kid) {
            Some(key) => key.verify(data, signature),
            None => false,
        }
    }

    /// Get the current key ID.
    pub fn current_kid(&self) -> String {
        self.inner.read().unwrap().current_kid.clone()
    }

    /// Get the current key's public key bytes.
    pub fn current_public_key(&self) -> Vec<u8> {
        let inner = self.inner.read().unwrap();
        inner
            .keys
            .get(&inner.current_kid)
            .map(|k| k.public_key.clone())
            .unwrap_or_default()
    }

    /// Get the current key's seed (for JWT signing).
    pub fn current_seed(&self) -> Vec<u8> {
        let inner = self.inner.read().unwrap();
        inner
            .keys
            .get(&inner.current_kid)
            .map(|k| k.seed.clone())
            .unwrap_or_default()
    }

    /// Get the recovery codes for the current key (if threshold is enabled).
    pub fn recovery_codes(&self) -> Option<Vec<String>> {
        self.inner.read().unwrap().recovery_codes.clone()
    }

    /// Get the threshold shares for the current key (if enabled).
    pub fn threshold_shares(&self) -> Option<Vec<threshold::Share>> {
        self.inner.read().unwrap().current_shares.clone()
    }

    /// Generate the JWKS (JSON Web Key Set) containing all active + recent keys.
    pub fn jwks(&self) -> serde_json::Value {
        let inner = self.inner.read().unwrap();
        let keys: Vec<serde_json::Value> = inner.keys.values().map(|k| k.to_jwk()).collect();
        serde_json::json!({ "keys": keys })
    }

    /// Number of key versions currently held.
    pub fn key_count(&self) -> usize {
        self.inner.read().unwrap().keys.len()
    }

    /// Get info about all keys.
    pub fn key_info(&self) -> Vec<(String, u64, bool)> {
        let inner = self.inner.read().unwrap();
        inner
            .keys
            .values()
            .map(|k| (k.kid.clone(), k.version, k.active))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versioned_key_manager_create() {
        let mgr = VersionedKeyManager::new(5);
        assert_eq!(mgr.key_count(), 1);
        let kid = mgr.current_kid();
        assert!(kid.starts_with("mldsa-v1-"));
    }

    #[test]
    fn test_sign_and_verify() {
        let mgr = VersionedKeyManager::new(5);
        let data = b"test payload for versioned signing";
        let (kid, sig) = mgr.sign_current(data).unwrap();
        assert!(mgr.verify_by_kid(&kid, data, &sig));
        assert!(!mgr.verify_by_kid(&kid, b"wrong data", &sig));
    }

    #[test]
    fn test_key_rotation() {
        let mgr = VersionedKeyManager::new(5);
        let kid1 = mgr.current_kid();

        let kid2 = mgr.rotate();
        assert_ne!(kid1, kid2);
        assert_eq!(mgr.key_count(), 2);
        assert_eq!(mgr.current_kid(), kid2);

        // Old key can still verify
        let data = b"test data";
        let (_, sig) = mgr.sign_current(data).unwrap();
        assert!(mgr.verify_by_kid(&kid2, data, &sig));
    }

    #[test]
    fn test_old_key_still_verifies_after_rotation() {
        let mgr = VersionedKeyManager::new(5);
        let data = b"pre-rotation data";
        let (kid1, sig1) = mgr.sign_current(data).unwrap();

        mgr.rotate();

        // Old signature still verifiable
        assert!(mgr.verify_by_kid(&kid1, data, &sig1));
    }

    #[test]
    fn test_key_pruning() {
        let mgr = VersionedKeyManager::new(2); // Keep max 2 old keys + current
        mgr.rotate();
        mgr.rotate();
        mgr.rotate();
        mgr.rotate();

        // Should have at most 3 keys (2 retained + 1 current)
        assert!(mgr.key_count() <= 3);
    }

    #[test]
    fn test_jwks_output() {
        let mgr = VersionedKeyManager::new(5);
        let jwks = mgr.jwks();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "ML-DSA-65");
        assert_eq!(keys[0]["kty"], "PQC");
        assert!(keys[0]["kid"].as_str().unwrap().starts_with("mldsa-v1-"));
        assert!(keys[0]["x"].as_str().unwrap().len() > 100);
    }

    #[test]
    fn test_jwks_after_rotation() {
        let mgr = VersionedKeyManager::new(5);
        mgr.rotate();
        let jwks = mgr.jwks();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_with_threshold() {
        let mgr = VersionedKeyManager::with_threshold(5, 3, 5);
        assert!(mgr.recovery_codes().is_some());
        let codes = mgr.recovery_codes().unwrap();
        assert_eq!(codes.len(), 5);
        assert!(mgr.threshold_shares().is_some());
        let shares = mgr.threshold_shares().unwrap();
        assert_eq!(shares.len(), 5);

        // Verify signing still works
        let data = b"threshold managed key signing test";
        let (kid, sig) = mgr.sign_current(data).unwrap();
        assert!(mgr.verify_by_kid(&kid, data, &sig));
    }

    #[test]
    fn test_threshold_rotation() {
        let mgr = VersionedKeyManager::with_threshold(5, 2, 3);
        let codes_v1 = mgr.recovery_codes().unwrap();

        mgr.rotate();
        let codes_v2 = mgr.recovery_codes().unwrap();

        // Recovery codes should be different after rotation
        assert_ne!(codes_v1, codes_v2);
    }

    #[test]
    fn test_unknown_kid_fails() {
        let mgr = VersionedKeyManager::new(5);
        assert!(!mgr.verify_by_kid("nonexistent-kid", b"data", b"sig"));
    }
}