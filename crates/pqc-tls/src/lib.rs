//! PQC-TLS: TLS 1.3 with Post-Quantum Cryptography support.
//!
//! Provides hybrid key exchange (X25519 + ML-KEM-768) for quantum-safe
//! TLS handshakes, with graceful fallback to classical TLS 1.3.
//! Implements FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards.

pub mod certs;
pub mod certgen;
pub mod config;
pub mod fips;
pub mod provider;