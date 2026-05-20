//! Extended ML-DSA batch signature verification, multi-signature support,
//! signature aggregation/compression, and quantum-safe timestamp proofs.
//!
//! Provides:
//! - Batch verification of 100+ ML-DSA-65 signatures (sequential & parallel)
//! - Multi-signature: multiple signers sign the same message
//! - Signature aggregation and compression for compact storage
//! - Quantum-safe timestamp proof system using ML-DSA-65

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::certgen::pqc;
use crate::signature::hex_encode;

// ---------------------------------------------------------------------------
// Batch Verification
// ---------------------------------------------------------------------------

/// A single entry for batch verification.
pub struct SignatureEntry {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Result of batch verification.
#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    pub total: usize,
    pub verified: usize,
    pub failed: usize,
    pub failed_indices: Vec<usize>,
    pub duration_ms: u128,
}

impl BatchVerificationResult {
    pub fn all_valid(&self) -> bool {
        self.failed == 0
    }
}

/// Verify a batch of ML-DSA-65 signatures sequentially.
pub fn batch_verify(entries: &[SignatureEntry]) -> BatchVerificationResult {
    let start = Instant::now();
    let mut verified = 0usize;
    let mut failed = 0usize;
    let mut failed_indices = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        match pqc::ml_dsa_verify(&entry.public_key, &entry.message, &entry.signature) {
            Ok(true) => verified += 1,
            _ => {
                failed += 1;
                failed_indices.push(i);
            }
        }
    }

    let duration = start.elapsed();
    info!(
        total = entries.len(),
        verified,
        failed,
        duration_ms = duration.as_millis(),
        "Batch verification completed (sequential)"
    );

    BatchVerificationResult {
        total: entries.len(),
        verified,
        failed,
        failed_indices,
        duration_ms: duration.as_millis(),
    }
}

/// Verify a batch of ML-DSA-65 signatures in parallel using threads.
pub fn batch_verify_parallel(
    entries: &[SignatureEntry],
    num_threads: usize,
) -> BatchVerificationResult {
    let start = Instant::now();
    let verified = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);
    let failed_indices = Mutex::new(Vec::new());

    let effective_threads = num_threads.max(1);
    let chunk_size = (entries.len() + effective_threads - 1) / effective_threads;

    std::thread::scope(|s| {
        for (chunk_idx, chunk) in entries.chunks(chunk_size).enumerate() {
            let verified = &verified;
            let failed = &failed;
            let failed_indices = &failed_indices;
            let base_idx = chunk_idx * chunk_size;

            s.spawn(move || {
                for (i, entry) in chunk.iter().enumerate() {
                    match pqc::ml_dsa_verify(&entry.public_key, &entry.message, &entry.signature)
                    {
                        Ok(true) => {
                            verified.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            failed.fetch_add(1, Ordering::Relaxed);
                            failed_indices.lock().unwrap().push(base_idx + i);
                        }
                    }
                }
            });
        }
    });

    let duration = start.elapsed();
    let mut failed_vec = failed_indices.into_inner().unwrap();
    failed_vec.sort();

    info!(
        total = entries.len(),
        verified = verified.load(Ordering::Relaxed),
        failed = failed.load(Ordering::Relaxed),
        threads = effective_threads,
        duration_ms = duration.as_millis(),
        "Batch verification completed (parallel)"
    );

    BatchVerificationResult {
        total: entries.len(),
        verified: verified.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
        failed_indices: failed_vec,
        duration_ms: duration.as_millis(),
    }
}

// ---------------------------------------------------------------------------
// Multi-Signature Support
// ---------------------------------------------------------------------------

/// A signer's contribution to a multi-signature.
#[derive(Debug, Clone)]
pub struct SignerContribution {
    pub signer_id: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A multi-signature: multiple signers independently sign the same message.
#[derive(Debug, Clone)]
pub struct MultiSignature {
    pub message_hash: String,
    pub contributions: Vec<SignerContribution>,
    pub required_signers: usize,
}

/// Builder for creating multi-signatures.
pub struct MultiSignatureBuilder {
    message: Vec<u8>,
    message_hash: String,
    contributions: Vec<SignerContribution>,
    required_signers: usize,
}

impl MultiSignatureBuilder {
    /// Create a new multi-signature builder for a message.
    pub fn new(message: &[u8], required_signers: usize) -> Self {
        let message_hash = hex_encode(&Sha256::digest(message));
        Self {
            message: message.to_vec(),
            message_hash,
            contributions: Vec::new(),
            required_signers,
        }
    }

    /// Add a signer's contribution. The signer signs the message with their own key.
    pub fn add_signer(
        &mut self,
        signer_id: &str,
        seed: &[u8],
        public_key: &[u8],
    ) -> anyhow::Result<()> {
        let signature = pqc::ml_dsa_sign(seed, &self.message)?;
        self.contributions.push(SignerContribution {
            signer_id: signer_id.to_string(),
            public_key: public_key.to_vec(),
            signature,
        });
        Ok(())
    }

    /// Build the multi-signature. Returns None if insufficient signers.
    pub fn build(self) -> Option<MultiSignature> {
        if self.contributions.len() < self.required_signers {
            return None;
        }
        Some(MultiSignature {
            message_hash: self.message_hash,
            contributions: self.contributions,
            required_signers: self.required_signers,
        })
    }
}

/// Verify a multi-signature: all contributions must be valid.
pub fn verify_multi_signature(multi_sig: &MultiSignature, message: &[u8]) -> bool {
    // Verify message hash
    let expected_hash = hex_encode(&Sha256::digest(message));
    if expected_hash != multi_sig.message_hash {
        return false;
    }

    // Must have at least required_signers contributions
    if multi_sig.contributions.len() < multi_sig.required_signers {
        return false;
    }

    // Every contribution must verify
    for contrib in &multi_sig.contributions {
        match pqc::ml_dsa_verify(&contrib.public_key, message, &contrib.signature) {
            Ok(true) => {}
            _ => return false,
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Signature Aggregation & Compression
// ---------------------------------------------------------------------------

/// An aggregated collection of signatures for compact storage/transmission.
#[derive(Debug, Clone)]
pub struct AggregatedSignatures {
    /// Individual entries: (signer_index, message_hash, signature_bytes).
    entries: Vec<AggregateEntry>,
    /// Shared public keys (deduplicated).
    public_keys: Vec<Vec<u8>>,
    /// Mapping from entry to public key index.
    key_indices: Vec<usize>,
    /// Total uncompressed size in bytes.
    pub uncompressed_size: usize,
    /// Total compressed size in bytes.
    pub compressed_size: usize,
}

#[derive(Debug, Clone)]
struct AggregateEntry {
    message_hash: String,
    signature: Vec<u8>,
}

/// Builder for aggregating signatures.
pub struct SignatureAggregator {
    entries: Vec<AggregateEntry>,
    public_keys: Vec<Vec<u8>>,
    key_indices: Vec<usize>,
    total_sig_size: usize,
}

impl SignatureAggregator {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            public_keys: Vec::new(),
            key_indices: Vec::new(),
            total_sig_size: 0,
        }
    }

    /// Add a signature to the aggregation.
    pub fn add(
        &mut self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) {
        // Deduplicate public keys
        let key_idx = match self.public_keys.iter().position(|k| k == public_key) {
            Some(idx) => idx,
            None => {
                self.public_keys.push(public_key.to_vec());
                self.public_keys.len() - 1
            }
        };

        let message_hash = hex_encode(&Sha256::digest(message));
        self.total_sig_size += signature.len() + public_key.len();

        self.entries.push(AggregateEntry {
            message_hash,
            signature: signature.to_vec(),
        });
        self.key_indices.push(key_idx);
    }

    /// Finalize the aggregation.
    pub fn finalize(self) -> AggregatedSignatures {
        let uncompressed_size = self.total_sig_size;
        // Compressed size: deduplicated keys + signatures + indices
        let compressed_size: usize = self.public_keys.iter().map(|k| k.len()).sum::<usize>()
            + self.entries.iter().map(|e| e.signature.len()).sum::<usize>()
            + self.key_indices.len() * 2; // 2 bytes per index

        AggregatedSignatures {
            entries: self.entries,
            public_keys: self.public_keys,
            key_indices: self.key_indices,
            uncompressed_size,
            compressed_size,
        }
    }
}

impl AggregatedSignatures {
    /// Number of signatures in the aggregate.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Number of unique public keys.
    pub fn unique_key_count(&self) -> usize {
        self.public_keys.len()
    }

    /// Compression ratio (compressed / uncompressed).
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.uncompressed_size as f64
    }

    /// Verify all signatures in the aggregate.
    pub fn verify_all(&self, messages: &[&[u8]]) -> BatchVerificationResult {
        assert_eq!(
            messages.len(),
            self.entries.len(),
            "Message count must match entry count"
        );

        let start = Instant::now();
        let mut verified = 0;
        let mut failed = 0;
        let mut failed_indices = Vec::new();

        for (i, (entry, &msg)) in self.entries.iter().zip(messages.iter()).enumerate() {
            let key_idx = self.key_indices[i];
            let public_key = &self.public_keys[key_idx];

            // Verify message hash
            let expected_hash = hex_encode(&Sha256::digest(msg));
            if expected_hash != entry.message_hash {
                failed += 1;
                failed_indices.push(i);
                continue;
            }

            match pqc::ml_dsa_verify(public_key, msg, &entry.signature) {
                Ok(true) => verified += 1,
                _ => {
                    failed += 1;
                    failed_indices.push(i);
                }
            }
        }

        BatchVerificationResult {
            total: self.entries.len(),
            verified,
            failed,
            failed_indices,
            duration_ms: start.elapsed().as_millis(),
        }
    }
}

// ---------------------------------------------------------------------------
// Quantum-Safe Timestamp Proofs
// ---------------------------------------------------------------------------

/// A quantum-safe timestamp proof using ML-DSA-65.
#[derive(Debug, Clone)]
pub struct TimestampProof {
    /// Unix timestamp (seconds) when the proof was created.
    pub timestamp: u64,
    /// SHA-256 hash of the original message (hex).
    pub message_hash: String,
    /// ML-DSA-65 signature over the proof payload (timestamp || message_hash).
    pub signature: Vec<u8>,
    /// ML-DSA-65 public key for verification.
    pub public_key: Vec<u8>,
    /// SHA-256 of the entire proof (timestamp || message_hash || signature) for integrity.
    pub proof_hash: String,
}

/// A timestamp authority that creates and verifies timestamp proofs.
pub struct TimestampAuthority {
    seed: Vec<u8>,
    public_key: Vec<u8>,
    fingerprint: String,
    proofs_issued: u64,
}

impl TimestampAuthority {
    /// Create a new timestamp authority with a fresh ML-DSA-65 keypair.
    pub fn new() -> Self {
        let kp = pqc::generate_ml_dsa_keypair();
        let fingerprint = hex_encode(&Sha256::digest(&kp.public_key)[..16]);
        info!(
            fingerprint = %fingerprint,
            "Timestamp authority initialized (ML-DSA-65)"
        );
        Self {
            seed: kp.seed,
            public_key: kp.public_key,
            fingerprint,
            proofs_issued: 0,
        }
    }

    /// Create a timestamp proof for a message.
    pub fn create_proof(&mut self, message: &[u8]) -> anyhow::Result<TimestampProof> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let message_hash = hex_encode(&Sha256::digest(message));

        // Proof payload = timestamp bytes || message hash bytes
        let mut payload = Vec::new();
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload.extend_from_slice(message_hash.as_bytes());

        let signature = pqc::ml_dsa_sign(&self.seed, &payload)?;

        // Compute proof integrity hash
        let mut proof_hasher = Sha256::new();
        proof_hasher.update(&timestamp.to_le_bytes());
        proof_hasher.update(message_hash.as_bytes());
        proof_hasher.update(&signature);
        let proof_hash = hex_encode(&proof_hasher.finalize());

        self.proofs_issued += 1;
        info!(
            timestamp,
            proof_hash = %proof_hash,
            proofs_issued = self.proofs_issued,
            "Timestamp proof created"
        );

        Ok(TimestampProof {
            timestamp,
            message_hash,
            signature,
            public_key: self.public_key.clone(),
            proof_hash,
        })
    }

    /// Get the authority's public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the authority's fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Number of proofs issued.
    pub fn proofs_issued(&self) -> u64 {
        self.proofs_issued
    }
}

/// Verify a timestamp proof.
pub fn verify_timestamp_proof(proof: &TimestampProof, message: &[u8]) -> bool {
    // Step 1: Verify message hash
    let expected_hash = hex_encode(&Sha256::digest(message));
    if expected_hash != proof.message_hash {
        return false;
    }

    // Step 2: Reconstruct payload and verify ML-DSA signature
    let mut payload = Vec::new();
    payload.extend_from_slice(&proof.timestamp.to_le_bytes());
    payload.extend_from_slice(proof.message_hash.as_bytes());

    match pqc::ml_dsa_verify(&proof.public_key, &payload, &proof.signature) {
        Ok(true) => {}
        _ => return false,
    }

    // Step 3: Verify proof integrity hash
    let mut proof_hasher = Sha256::new();
    proof_hasher.update(&proof.timestamp.to_le_bytes());
    proof_hasher.update(proof.message_hash.as_bytes());
    proof_hasher.update(&proof.signature);
    let computed_hash = hex_encode(&proof_hasher.finalize());

    computed_hash == proof.proof_hash
}

/// Verify a timestamp proof and check that the timestamp is within an acceptable range.
pub fn verify_timestamp_proof_with_time_check(
    proof: &TimestampProof,
    message: &[u8],
    max_age_seconds: u64,
) -> bool {
    if !verify_timestamp_proof(proof, message) {
        return false;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Timestamp must not be in the future (with small tolerance)
    if proof.timestamp > now + 60 {
        return false;
    }

    // Timestamp must not be too old
    if now - proof.timestamp > max_age_seconds {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Helper: Generate a batch of test entries
// ---------------------------------------------------------------------------

/// Generate N signed entries for batch verification testing.
pub fn generate_test_batch(count: usize) -> (Vec<SignatureEntry>, pqc::MlDsaKeyPair) {
    let kp = pqc::generate_ml_dsa_keypair();
    let entries: Vec<SignatureEntry> = (0..count)
        .map(|i| {
            let message = format!("batch test message #{i}").into_bytes();
            let signature = pqc::ml_dsa_sign(&kp.seed, &message).unwrap();
            SignatureEntry {
                message,
                signature,
                public_key: kp.public_key.clone(),
            }
        })
        .collect();
    (entries, kp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Batch Verification tests --

    #[test]
    fn test_batch_verify_small() {
        let (entries, _) = generate_test_batch(5);
        let result = batch_verify(&entries);
        assert!(result.all_valid());
        assert_eq!(result.total, 5);
        assert_eq!(result.verified, 5);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_batch_verify_100_signatures() {
        let (entries, _) = generate_test_batch(100);
        let result = batch_verify(&entries);
        assert!(result.all_valid(), "All 100 signatures should verify");
        assert_eq!(result.total, 100);
        assert_eq!(result.verified, 100);
    }

    #[test]
    fn test_batch_verify_with_one_invalid() {
        let (mut entries, _) = generate_test_batch(10);
        // Tamper with the 5th signature
        if let Some(byte) = entries[4].signature.last_mut() {
            *byte ^= 0xFF;
        }

        let result = batch_verify(&entries);
        assert!(!result.all_valid());
        assert_eq!(result.failed, 1);
        assert_eq!(result.failed_indices, vec![4]);
        assert_eq!(result.verified, 9);
    }

    #[test]
    fn test_batch_verify_with_multiple_invalid() {
        let (mut entries, _) = generate_test_batch(10);
        // Tamper with indices 2, 5, 8
        for &idx in &[2, 5, 8] {
            entries[idx].message = b"tampered".to_vec();
        }

        let result = batch_verify(&entries);
        assert_eq!(result.failed, 3);
        assert_eq!(result.failed_indices, vec![2, 5, 8]);
    }

    #[test]
    fn test_batch_verify_empty() {
        let result = batch_verify(&[]);
        assert!(result.all_valid());
        assert_eq!(result.total, 0);
    }

    #[test]
    fn test_batch_verify_parallel_small() {
        let (entries, _) = generate_test_batch(8);
        let result = batch_verify_parallel(&entries, 4);
        assert!(result.all_valid());
        assert_eq!(result.verified, 8);
    }

    #[test]
    fn test_batch_verify_parallel_with_invalid() {
        let (mut entries, _) = generate_test_batch(12);
        entries[3].message = b"tampered".to_vec();
        entries[9].message = b"tampered".to_vec();

        let result = batch_verify_parallel(&entries, 4);
        assert_eq!(result.failed, 2);
        assert!(result.failed_indices.contains(&3));
        assert!(result.failed_indices.contains(&9));
    }

    #[test]
    fn test_batch_verify_parallel_single_thread() {
        let (entries, _) = generate_test_batch(5);
        let result = batch_verify_parallel(&entries, 1);
        assert!(result.all_valid());
    }

    // -- Multi-Signature tests --

    #[test]
    fn test_multi_signature_basic() {
        let kp1 = pqc::generate_ml_dsa_keypair();
        let kp2 = pqc::generate_ml_dsa_keypair();
        let kp3 = pqc::generate_ml_dsa_keypair();

        let message = b"multi-sig test message";
        let mut builder = MultiSignatureBuilder::new(message, 2);
        builder.add_signer("signer-1", &kp1.seed, &kp1.public_key).unwrap();
        builder.add_signer("signer-2", &kp2.seed, &kp2.public_key).unwrap();
        builder.add_signer("signer-3", &kp3.seed, &kp3.public_key).unwrap();

        let multi_sig = builder.build().unwrap();
        assert_eq!(multi_sig.contributions.len(), 3);
        assert!(verify_multi_signature(&multi_sig, message));
    }

    #[test]
    fn test_multi_signature_wrong_message() {
        let kp1 = pqc::generate_ml_dsa_keypair();
        let kp2 = pqc::generate_ml_dsa_keypair();

        let message = b"correct message";
        let mut builder = MultiSignatureBuilder::new(message, 2);
        builder.add_signer("s1", &kp1.seed, &kp1.public_key).unwrap();
        builder.add_signer("s2", &kp2.seed, &kp2.public_key).unwrap();

        let multi_sig = builder.build().unwrap();
        assert!(!verify_multi_signature(&multi_sig, b"wrong message"));
    }

    #[test]
    fn test_multi_signature_insufficient_signers() {
        let kp1 = pqc::generate_ml_dsa_keypair();

        let message = b"test";
        let mut builder = MultiSignatureBuilder::new(message, 3);
        builder.add_signer("s1", &kp1.seed, &kp1.public_key).unwrap();

        // Only 1 signer, need 3
        assert!(builder.build().is_none());
    }

    #[test]
    fn test_multi_signature_tampered_contribution() {
        let kp1 = pqc::generate_ml_dsa_keypair();
        let kp2 = pqc::generate_ml_dsa_keypair();

        let message = b"tamper test";
        let mut builder = MultiSignatureBuilder::new(message, 2);
        builder.add_signer("s1", &kp1.seed, &kp1.public_key).unwrap();
        builder.add_signer("s2", &kp2.seed, &kp2.public_key).unwrap();

        let mut multi_sig = builder.build().unwrap();
        // Tamper with the second contribution's signature
        if let Some(byte) = multi_sig.contributions[1].signature.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(!verify_multi_signature(&multi_sig, message));
    }

    // -- Signature Aggregation tests --

    #[test]
    fn test_signature_aggregation() {
        let kp = pqc::generate_ml_dsa_keypair();
        let messages: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("agg message {i}").into_bytes())
            .collect();

        let mut aggregator = SignatureAggregator::new();
        for msg in &messages {
            let sig = pqc::ml_dsa_sign(&kp.seed, msg).unwrap();
            aggregator.add(&kp.public_key, msg, &sig);
        }

        let aggregated = aggregator.finalize();
        assert_eq!(aggregated.count(), 5);
        assert_eq!(aggregated.unique_key_count(), 1); // same key for all

        // Verify all
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let result = aggregated.verify_all(&msg_refs);
        assert!(result.all_valid());
    }

    #[test]
    fn test_signature_aggregation_multiple_keys() {
        let kp1 = pqc::generate_ml_dsa_keypair();
        let kp2 = pqc::generate_ml_dsa_keypair();

        let msg1 = b"message from signer 1";
        let msg2 = b"message from signer 2";
        let msg3 = b"another from signer 1";

        let sig1 = pqc::ml_dsa_sign(&kp1.seed, msg1).unwrap();
        let sig2 = pqc::ml_dsa_sign(&kp2.seed, msg2).unwrap();
        let sig3 = pqc::ml_dsa_sign(&kp1.seed, msg3).unwrap();

        let mut aggregator = SignatureAggregator::new();
        aggregator.add(&kp1.public_key, msg1, &sig1);
        aggregator.add(&kp2.public_key, msg2, &sig2);
        aggregator.add(&kp1.public_key, msg3, &sig3);

        let aggregated = aggregator.finalize();
        assert_eq!(aggregated.count(), 3);
        assert_eq!(aggregated.unique_key_count(), 2);
        assert!(aggregated.compression_ratio() < 1.0, "Should compress with key dedup");

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let result = aggregated.verify_all(&messages);
        assert!(result.all_valid());
    }

    #[test]
    fn test_signature_aggregation_compression_ratio() {
        let kp = pqc::generate_ml_dsa_keypair();
        let mut aggregator = SignatureAggregator::new();

        for i in 0..10 {
            let msg = format!("compress test {i}").into_bytes();
            let sig = pqc::ml_dsa_sign(&kp.seed, &msg).unwrap();
            aggregator.add(&kp.public_key, &msg, &sig);
        }

        let aggregated = aggregator.finalize();
        let ratio = aggregated.compression_ratio();
        // With 10 sigs from same key, dedup saves 9 copies of the public key
        assert!(ratio < 1.0, "Compression ratio should be < 1.0, got {ratio}");
    }

    // -- Timestamp Proof tests --

    #[test]
    fn test_timestamp_proof_create_verify() {
        let mut authority = TimestampAuthority::new();
        let message = b"timestamp test message";

        let proof = authority.create_proof(message).unwrap();
        assert!(verify_timestamp_proof(&proof, message));
        assert_eq!(authority.proofs_issued(), 1);
    }

    #[test]
    fn test_timestamp_proof_wrong_message() {
        let mut authority = TimestampAuthority::new();
        let proof = authority.create_proof(b"original message").unwrap();
        assert!(!verify_timestamp_proof(&proof, b"different message"));
    }

    #[test]
    fn test_timestamp_proof_tampered_signature() {
        let mut authority = TimestampAuthority::new();
        let mut proof = authority.create_proof(b"tamper test").unwrap();

        // Tamper with signature
        if let Some(byte) = proof.signature.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(!verify_timestamp_proof(&proof, b"tamper test"));
    }

    #[test]
    fn test_timestamp_proof_tampered_hash() {
        let mut authority = TimestampAuthority::new();
        let mut proof = authority.create_proof(b"hash tamper").unwrap();

        // Tamper with proof hash
        proof.proof_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!verify_timestamp_proof(&proof, b"hash tamper"));
    }

    #[test]
    fn test_timestamp_proof_with_time_check() {
        let mut authority = TimestampAuthority::new();
        let proof = authority.create_proof(b"time check test").unwrap();

        // Should be valid (just created, within 3600s)
        assert!(verify_timestamp_proof_with_time_check(
            &proof,
            b"time check test",
            3600
        ));
    }

    #[test]
    fn test_timestamp_proof_expired() {
        let mut authority = TimestampAuthority::new();
        let mut proof = authority.create_proof(b"old proof").unwrap();

        // Simulate old timestamp (but this breaks the signature, which is correct behavior)
        proof.timestamp = 1000; // Unix epoch + 1000s — very old
        assert!(!verify_timestamp_proof(&proof, b"old proof"));
    }

    #[test]
    fn test_timestamp_authority_multiple_proofs() {
        let mut authority = TimestampAuthority::new();

        for i in 0..5 {
            let msg = format!("proof #{i}").into_bytes();
            let proof = authority.create_proof(&msg).unwrap();
            assert!(verify_timestamp_proof(&proof, &msg));
        }
        assert_eq!(authority.proofs_issued(), 5);
    }

    #[test]
    fn test_timestamp_authority_fingerprint() {
        let authority = TimestampAuthority::new();
        assert!(!authority.fingerprint().is_empty());
        assert!(authority.public_key().len() > 1000); // ML-DSA-65 PK ~1952 bytes
    }

    // -- Cross-module integration test --

    #[test]
    fn test_batch_verify_different_signers() {
        let kp1 = pqc::generate_ml_dsa_keypair();
        let kp2 = pqc::generate_ml_dsa_keypair();

        let msg1 = b"message 1";
        let msg2 = b"message 2";

        let sig1 = pqc::ml_dsa_sign(&kp1.seed, msg1).unwrap();
        let sig2 = pqc::ml_dsa_sign(&kp2.seed, msg2).unwrap();

        let entries = vec![
            SignatureEntry {
                message: msg1.to_vec(),
                signature: sig1,
                public_key: kp1.public_key,
            },
            SignatureEntry {
                message: msg2.to_vec(),
                signature: sig2,
                public_key: kp2.public_key,
            },
        ];

        let result = batch_verify(&entries);
        assert!(result.all_valid());
    }
}