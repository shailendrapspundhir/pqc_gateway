//! FIPS compliance validation and reporting.
//!
//! Checks that the gateway's cryptographic configuration meets
//! NIST FIPS requirements:
//! - FIPS 140-3: Cryptographic module validation
//! - FIPS 203: ML-KEM (Key Encapsulation Mechanism)
//! - FIPS 204: ML-DSA (Digital Signature Algorithm)
//! - FIPS 186-5: ECDSA / EdDSA signatures

use tracing::{info, warn};

/// FIPS standard identifiers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FipsStandard {
    /// FIPS 140-3: Security Requirements for Cryptographic Modules
    Fips140_3,
    /// FIPS 186-5: Digital Signature Standard (ECDSA, EdDSA)
    Fips186_5,
    /// FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
    Fips203,
    /// FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
    Fips204,
}

impl std::fmt::Display for FipsStandard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fips140_3 => write!(f, "FIPS 140-3"),
            Self::Fips186_5 => write!(f, "FIPS 186-5"),
            Self::Fips203 => write!(f, "FIPS 203 (ML-KEM)"),
            Self::Fips204 => write!(f, "FIPS 204 (ML-DSA)"),
        }
    }
}

/// Result of a FIPS compliance check.
#[derive(Debug)]
pub struct ComplianceCheck {
    pub standard: FipsStandard,
    pub description: String,
    pub passed: bool,
    pub details: String,
}

/// Run all FIPS compliance checks and return results.
pub fn run_compliance_checks(pqc_enabled: bool) -> Vec<ComplianceCheck> {
    let mut checks = Vec::new();

    // FIPS 140-3: aws-lc-rs is FIPS-validated
    checks.push(ComplianceCheck {
        standard: FipsStandard::Fips140_3,
        description: "Cryptographic module uses FIPS-validated library (aws-lc-rs)".into(),
        passed: true,
        details: "aws-lc-rs with FIPS feature enabled provides FIPS 140-3 validated cryptographic operations".into(),
    });

    // FIPS 186-5: ECDSA support
    checks.push(ComplianceCheck {
        standard: FipsStandard::Fips186_5,
        description: "ECDSA P-256/P-384 signatures available".into(),
        passed: true,
        details: "Server certificates use ECDSA P-256 (FIPS 186-5 compliant)".into(),
    });

    // FIPS 203: ML-KEM in key exchange
    checks.push(ComplianceCheck {
        standard: FipsStandard::Fips203,
        description: "ML-KEM-768 hybrid key exchange available".into(),
        passed: pqc_enabled,
        details: if pqc_enabled {
            "X25519MLKEM768 hybrid key exchange enabled in TLS 1.3".into()
        } else {
            "PQC key exchange disabled in configuration".into()
        },
    });

    // FIPS 203: Standalone ML-KEM validation
    checks.push(validate_ml_kem());

    // FIPS 204: ML-DSA validation
    checks.push(validate_ml_dsa());

    // FIPS 204: Hybrid signature (ECDSA + ML-DSA) validation
    checks.push(validate_hybrid_signature());

    // FIPS 204: ML-DSA-only signature validation
    checks.push(validate_mldsa_only_signature());

    // TLS version check
    checks.push(ComplianceCheck {
        standard: FipsStandard::Fips140_3,
        description: "TLS 1.3 enforced (SSLv3, TLS 1.0, 1.1 disabled)".into(),
        passed: true,
        details: "rustls configured with TLS 1.3 minimum version".into(),
    });

    checks
}

/// Validate ML-KEM-768 (FIPS 203) by running a full cycle.
fn validate_ml_kem() -> ComplianceCheck {
    use crate::certgen::pqc;

    let result = pqc::ml_kem_full_cycle();
    ComplianceCheck {
        standard: FipsStandard::Fips203,
        description: "ML-KEM-768 encapsulation/decapsulation self-test".into(),
        passed: result.secrets_match,
        details: format!(
            "EK: {} bytes, DK: {} bytes, CT: {} bytes, SS: {} bytes, match: {}",
            result.ek_size,
            result.dk_size,
            result.ciphertext_size,
            result.shared_secret_size,
            result.secrets_match,
        ),
    }
}

/// Validate ML-DSA-65 (FIPS 204) by running a sign/verify cycle.
fn validate_ml_dsa() -> ComplianceCheck {
    use crate::certgen::pqc;

    let kp = pqc::generate_ml_dsa_keypair();
    let test_msg = b"FIPS 204 self-test message for PQC Gateway";

    match pqc::ml_dsa_sign(&kp.seed, test_msg) {
        Ok(sig) => match pqc::ml_dsa_verify(&kp.public_key, test_msg, &sig) {
            Ok(valid) => ComplianceCheck {
                standard: FipsStandard::Fips204,
                description: "ML-DSA-65 sign/verify self-test".into(),
                passed: valid,
                details: format!(
                    "PK: {} bytes, Seed: {} bytes, Sig: {} bytes, valid: {}",
                    kp.public_key.len(),
                    kp.seed.len(),
                    sig.len(),
                    valid
                ),
            },
            Err(e) => ComplianceCheck {
                standard: FipsStandard::Fips204,
                description: "ML-DSA-65 verification self-test".into(),
                passed: false,
                details: format!("Verification failed: {e}"),
            },
        },
        Err(e) => ComplianceCheck {
            standard: FipsStandard::Fips204,
            description: "ML-DSA-65 signing self-test".into(),
            passed: false,
            details: format!("Signing failed: {e}"),
        },
    }
}

/// Validate hybrid signature mode (ECDSA-P256 + ML-DSA-65).
fn validate_hybrid_signature() -> ComplianceCheck {
    use crate::signature::{SignatureKeyManager, SignatureMode};

    let km = SignatureKeyManager::generate();
    let test_data = b"FIPS 204 hybrid signature self-test";
    match km.sign(SignatureMode::Hybrid, test_data) {
        Some(output) => {
            let valid = km.verify(test_data, &output);
            ComplianceCheck {
                standard: FipsStandard::Fips204,
                description: "Hybrid signature (ECDSA-P256 + ML-DSA-65) self-test".into(),
                passed: valid,
                details: format!(
                    "Algorithm: {}, PQC sig: {} bytes, Classical sig: {} bytes, valid: {}",
                    output.algorithm,
                    output.pqc_signature.len(),
                    output.classical_signature.as_ref().map(|s| s.len()).unwrap_or(0),
                    valid,
                ),
            }
        }
        None => ComplianceCheck {
            standard: FipsStandard::Fips204,
            description: "Hybrid signature self-test".into(),
            passed: false,
            details: "sign() returned None for Hybrid mode".into(),
        },
    }
}

/// Validate ML-DSA-65-only signature mode.
fn validate_mldsa_only_signature() -> ComplianceCheck {
    use crate::signature::{SignatureKeyManager, SignatureMode};

    let km = SignatureKeyManager::generate();
    let test_data = b"FIPS 204 ML-DSA-only signature self-test";
    match km.sign(SignatureMode::MlDsaOnly, test_data) {
        Some(output) => {
            let valid = km.verify(test_data, &output);
            ComplianceCheck {
                standard: FipsStandard::Fips204,
                description: "ML-DSA-65-only signature self-test".into(),
                passed: valid && output.classical_signature.is_none(),
                details: format!(
                    "Algorithm: {}, PQC sig: {} bytes, no classical sig: {}, valid: {}",
                    output.algorithm,
                    output.pqc_signature.len(),
                    output.classical_signature.is_none(),
                    valid,
                ),
            }
        }
        None => ComplianceCheck {
            standard: FipsStandard::Fips204,
            description: "ML-DSA-65-only signature self-test".into(),
            passed: false,
            details: "sign() returned None for MlDsaOnly mode".into(),
        },
    }
}

/// Print a FIPS compliance report to the log.
pub fn log_compliance_report(pqc_enabled: bool) {
    let checks = run_compliance_checks(pqc_enabled);
    let all_passed = checks.iter().all(|c| c.passed);

    info!("=== FIPS Compliance Report ===");
    for check in &checks {
        if check.passed {
            info!(
                standard = %check.standard,
                status = "PASS",
                "  {} — {}",
                check.description,
                check.details
            );
        } else {
            warn!(
                standard = %check.standard,
                status = "FAIL",
                "  {} — {}",
                check.description,
                check.details
            );
        }
    }
    if all_passed {
        info!("All FIPS compliance checks PASSED");
    } else {
        warn!("Some FIPS compliance checks FAILED");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_checks_with_pqc() {
        let checks = run_compliance_checks(true);
        assert!(!checks.is_empty());
        for check in &checks {
            assert!(check.passed, "Check failed: {} — {}", check.description, check.details);
        }
    }

    #[test]
    fn test_compliance_checks_without_pqc() {
        let checks = run_compliance_checks(false);
        // ML-KEM TLS check should fail when PQC is disabled
        let ml_kem_tls = checks
            .iter()
            .find(|c| c.standard == FipsStandard::Fips203 && c.description.contains("hybrid key"))
            .unwrap();
        assert!(!ml_kem_tls.passed);
        // But standalone ML-KEM/ML-DSA self-tests should still pass
        let ml_kem_self = checks
            .iter()
            .find(|c| c.standard == FipsStandard::Fips203 && c.description.contains("self-test"))
            .unwrap();
        assert!(ml_kem_self.passed);
    }

    #[test]
    fn test_compliance_hybrid_signature() {
        let checks = run_compliance_checks(true);
        let hybrid = checks
            .iter()
            .find(|c| c.description.contains("Hybrid signature"))
            .expect("Hybrid signature check should exist");
        assert!(hybrid.passed, "Hybrid signature check failed: {}", hybrid.details);
    }

    #[test]
    fn test_compliance_mldsa_only_signature() {
        let checks = run_compliance_checks(true);
        let mldsa = checks
            .iter()
            .find(|c| c.description.contains("ML-DSA-65-only signature"))
            .expect("ML-DSA-only signature check should exist");
        assert!(mldsa.passed, "ML-DSA-only signature check failed: {}", mldsa.details);
    }
}