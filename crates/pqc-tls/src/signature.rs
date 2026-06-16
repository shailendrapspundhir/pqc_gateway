//! PQC Signature support: Hybrid (ECDSA-P256 + ML-DSA-65) and ML-DSA-65-only modes.
//!
//! Provides application-layer signing of data (e.g. response bodies) with
//! configurable signature modes selectable per-route or globally via env var.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

use crate::certgen::pqc;

// ---------------------------------------------------------------------------
// SignatureMode
// ---------------------------------------------------------------------------

/// Determines which signature algorithm(s) the gateway applies to responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMode {
    /// No PQC signatures — current/classical behaviour.
    Classical,
    /// ECDSA-P256 **and** ML-DSA-65 dual signatures.
    Hybrid,
    /// ML-DSA-65 only — for high-security / internal services.
    MlDsaOnly,
}

impl SignatureMode {
    /// Resolve the effective mode using precedence:
    /// `env_override > route_config > global_default > Classical`
    pub fn resolve(
        env_override: Option<&str>,
        route_mode: Option<SignatureMode>,
        global_default: SignatureMode,
    ) -> SignatureMode {
        if let Some(env_val) = env_override {
            if let Ok(m) = env_val.parse::<SignatureMode>() {
                return m;
            }
        }
        route_mode.unwrap_or(global_default)
    }
}

impl Default for SignatureMode {
    fn default() -> Self {
        Self::Classical
    }
}

impl fmt::Display for SignatureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Classical => write!(f, "classical"),
            Self::Hybrid => write!(f, "hybrid"),
            Self::MlDsaOnly => write!(f, "mldsa-only"),
        }
    }
}

impl FromStr for SignatureMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "classical" => Ok(Self::Classical),
            "hybrid" => Ok(Self::Hybrid),
            "mldsa-only" | "mldsa_only" | "mldsaonly" => Ok(Self::MlDsaOnly),
            other => Err(format!(
                "unknown signature mode '{other}': expected classical|hybrid|mldsa-only"
            )),
        }
    }
}

impl<'de> serde::Deserialize<'de> for SignatureMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for SignatureMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

// ---------------------------------------------------------------------------
// SignatureOutput
// ---------------------------------------------------------------------------

/// The result of signing a piece of data.
#[derive(Debug, Clone)]
pub struct SignatureOutput {
    /// `"ecdsa-p256+ml-dsa-65"` or `"ml-dsa-65"`.
    pub algorithm: String,
    /// Base64-encoded ML-DSA-65 signature.
    pub pqc_signature: String,
    /// Base64-encoded ECDSA-P256 signature (present only in Hybrid mode).
    pub classical_signature: Option<String>,
    /// Hex-encoded SHA-256 of the signed content.
    pub content_digest: String,
    /// Hex-encoded fingerprint of the signing public key(s).
    pub public_key_fingerprint: String,
}

// ---------------------------------------------------------------------------
// SignatureKeyManager
// ---------------------------------------------------------------------------

/// Holds both classical and PQC signing keys, generated once at startup.
#[derive(Clone)]
pub struct SignatureKeyManager {
    inner: Arc<Inner>,
}

struct Inner {
    ecdsa_signing_key: EcdsaSigningKey,
    ecdsa_verifying_key: EcdsaVerifyingKey,
    mldsa_seed: Vec<u8>,
    mldsa_public_key: Vec<u8>,
    fingerprint: String,
}

impl SignatureKeyManager {
    /// Create from a hex-encoded seed (read from env var).
    /// The seed is used for ML-DSA; ECDSA is generated fresh.
    pub fn from_seed_hex(hex: &str) -> Result<Self, String> {
        let seed_bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex: {e}"))
            })
            .collect::<Result<Vec<u8>, _>>()?;

        let ecdsa_signing_key = EcdsaSigningKey::random(&mut rand_core::OsRng);
        let ecdsa_verifying_key = EcdsaVerifyingKey::from(&ecdsa_signing_key);

        // Derive ML-DSA keypair from seed
        let seed_arr = ml_dsa::Seed::try_from(seed_bytes.as_slice())
            .map_err(|_| "Invalid ML-DSA-65 seed length (expected 32 bytes)".to_string())?;
        use ml_dsa::signature::Keypair as _;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_arr);
        let vk = sk.verifying_key();
        let mldsa_public_key = vk.encode().to_vec();

        let fingerprint = combined_fingerprint(
            &ecdsa_verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            &mldsa_public_key,
        );

        info!(
            fingerprint = %fingerprint,
            "Signature key manager initialised from env seed"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                ecdsa_signing_key,
                ecdsa_verifying_key,
                mldsa_seed: seed_bytes,
                mldsa_public_key,
                fingerprint,
            }),
        })
    }

    /// Export the ML-DSA seed as hex (for keygen CLI).
    pub fn seed_hex(&self) -> String {
        self.inner.mldsa_seed.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Generate fresh ECDSA-P256 + ML-DSA-65 key pairs.
    pub fn generate() -> Self {
        let ecdsa_signing_key = EcdsaSigningKey::random(&mut rand_core::OsRng);
        let ecdsa_verifying_key = EcdsaVerifyingKey::from(&ecdsa_signing_key);

        let mldsa_kp = pqc::generate_ml_dsa_keypair();

        let fingerprint = combined_fingerprint(
            &ecdsa_verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            &mldsa_kp.public_key,
        );

        info!(
            ecdsa_pk_size = ecdsa_verifying_key.to_encoded_point(false).as_bytes().len(),
            mldsa_pk_size = mldsa_kp.public_key.len(),
            fingerprint = %fingerprint,
            "Signature key manager initialised (ECDSA-P256 + ML-DSA-65)"
        );

        Self {
            inner: Arc::new(Inner {
                ecdsa_signing_key,
                ecdsa_verifying_key,
                mldsa_seed: mldsa_kp.seed,
                mldsa_public_key: mldsa_kp.public_key,
                fingerprint,
            }),
        }
    }

    /// Sign `data` according to `mode`. Returns `None` for `Classical`.
    pub fn sign(&self, mode: SignatureMode, data: &[u8]) -> Option<SignatureOutput> {
        match mode {
            SignatureMode::Classical => None,
            SignatureMode::Hybrid => Some(self.sign_hybrid(data)),
            SignatureMode::MlDsaOnly => Some(self.sign_mldsa_only(data)),
        }
    }

    /// Verify a `SignatureOutput` against `data`.
    pub fn verify(&self, data: &[u8], output: &SignatureOutput) -> bool {
        let digest_hex = hex_encode(&Sha256::digest(data));
        if digest_hex != output.content_digest {
            return false;
        }
        let pqc_ok = self.verify_mldsa(data, &output.pqc_signature);
        if !pqc_ok {
            return false;
        }
        if let Some(ref classical_b64) = output.classical_signature {
            return self.verify_ecdsa(data, classical_b64);
        }
        true
    }

    pub fn fingerprint(&self) -> &str {
        &self.inner.fingerprint
    }

    pub fn mldsa_public_key(&self) -> &[u8] {
        &self.inner.mldsa_public_key
    }

    pub fn ecdsa_verifying_key_bytes(&self) -> Vec<u8> {
        self.inner
            .ecdsa_verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    // -- private helpers --

    fn sign_hybrid(&self, data: &[u8]) -> SignatureOutput {
        let digest = Sha256::digest(data);
        let digest_hex = hex_encode(&digest);

        let ecdsa_sig: p256::ecdsa::DerSignature = self.inner.ecdsa_signing_key.sign(data);
        let classical_b64 = B64.encode(ecdsa_sig.as_bytes());

        let mldsa_sig = pqc::ml_dsa_sign(&self.inner.mldsa_seed, data)
            .expect("ML-DSA signing must not fail with valid seed");
        let pqc_b64 = B64.encode(&mldsa_sig);

        SignatureOutput {
            algorithm: "ecdsa-p256+ml-dsa-65".to_string(),
            pqc_signature: pqc_b64,
            classical_signature: Some(classical_b64),
            content_digest: digest_hex,
            public_key_fingerprint: self.inner.fingerprint.clone(),
        }
    }

    fn sign_mldsa_only(&self, data: &[u8]) -> SignatureOutput {
        let digest = Sha256::digest(data);
        let digest_hex = hex_encode(&digest);

        let mldsa_sig = pqc::ml_dsa_sign(&self.inner.mldsa_seed, data)
            .expect("ML-DSA signing must not fail with valid seed");
        let pqc_b64 = B64.encode(&mldsa_sig);

        SignatureOutput {
            algorithm: "ml-dsa-65".to_string(),
            pqc_signature: pqc_b64,
            classical_signature: None,
            content_digest: digest_hex,
            public_key_fingerprint: self.inner.fingerprint.clone(),
        }
    }

    fn verify_mldsa(&self, data: &[u8], pqc_b64: &str) -> bool {
        let sig_bytes = match B64.decode(pqc_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        pqc::ml_dsa_verify(&self.inner.mldsa_public_key, data, &sig_bytes).unwrap_or(false)
    }

    fn verify_ecdsa(&self, data: &[u8], classical_b64: &str) -> bool {
        let sig_bytes = match B64.decode(classical_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match p256::ecdsa::DerSignature::from_bytes(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.inner.ecdsa_verifying_key.verify(data, &sig).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn combined_fingerprint(ecdsa_pk: &[u8], mldsa_pk: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ecdsa_pk);
    hasher.update(mldsa_pk);
    let hash = hasher.finalize();
    hash[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() {
        let km = SignatureKeyManager::generate();
        let data = b"test payload for hybrid signing";
        let output = km.sign(SignatureMode::Hybrid, data).unwrap();
        assert_eq!(output.algorithm, "ecdsa-p256+ml-dsa-65");
        assert!(output.classical_signature.is_some());
        assert!(km.verify(data, &output));
    }

    #[test]
    fn test_mldsa_only_sign_verify() {
        let km = SignatureKeyManager::generate();
        let data = b"test payload for mldsa-only signing";
        let output = km.sign(SignatureMode::MlDsaOnly, data).unwrap();
        assert_eq!(output.algorithm, "ml-dsa-65");
        assert!(output.classical_signature.is_none());
        assert!(km.verify(data, &output));
    }

    #[test]
    fn test_hybrid_wrong_data_fails() {
        let km = SignatureKeyManager::generate();
        let data = b"original data";
        let output = km.sign(SignatureMode::Hybrid, data).unwrap();
        assert!(!km.verify(b"tampered data", &output));
    }

    #[test]
    fn test_mldsa_wrong_data_fails() {
        let km = SignatureKeyManager::generate();
        let data = b"original data";
        let output = km.sign(SignatureMode::MlDsaOnly, data).unwrap();
        assert!(!km.verify(b"tampered data", &output));
    }

    #[test]
    fn test_classical_mode_no_signature() {
        let km = SignatureKeyManager::generate();
        let data = b"should not be signed";
        assert!(km.sign(SignatureMode::Classical, data).is_none());
    }

    #[test]
    fn test_signature_mode_from_str() {
        assert_eq!("classical".parse::<SignatureMode>().unwrap(), SignatureMode::Classical);
        assert_eq!("hybrid".parse::<SignatureMode>().unwrap(), SignatureMode::Hybrid);
        assert_eq!("mldsa-only".parse::<SignatureMode>().unwrap(), SignatureMode::MlDsaOnly);
        assert_eq!("mldsa_only".parse::<SignatureMode>().unwrap(), SignatureMode::MlDsaOnly);
        assert!("unknown".parse::<SignatureMode>().is_err());
    }

    #[test]
    fn test_signature_mode_precedence() {
        // env override wins
        assert_eq!(
            SignatureMode::resolve(Some("mldsa-only"), Some(SignatureMode::Hybrid), SignatureMode::Classical),
            SignatureMode::MlDsaOnly
        );
        // route wins over global
        assert_eq!(
            SignatureMode::resolve(None, Some(SignatureMode::Hybrid), SignatureMode::Classical),
            SignatureMode::Hybrid
        );
        // global wins when no route or env
        assert_eq!(
            SignatureMode::resolve(None, None, SignatureMode::MlDsaOnly),
            SignatureMode::MlDsaOnly
        );
        // falls back to global default
        assert_eq!(
            SignatureMode::resolve(None, None, SignatureMode::Classical),
            SignatureMode::Classical
        );
    }

    #[test]
    fn test_content_digest_matches() {
        let km = SignatureKeyManager::generate();
        let data = b"digest verification test";
        let output = km.sign(SignatureMode::Hybrid, data).unwrap();
        let expected = hex_encode(&Sha256::digest(data));
        assert_eq!(output.content_digest, expected);
    }
}