//! Request/Response Body Integrity with PQC.
//!
//! Provides:
//! - Request body integrity verification (clients sign request bodies)
//! - Response body signing with ML-DSA-65
//! - Content digest (SHA-256) computation and verification
//! - Middleware for automatic integrity checking

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use hyper::header::{HeaderName, HeaderValue};
use hyper::StatusCode;
use pqc_tls::versioned_keys::VersionedKeyManager;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::warn;

/// Compute SHA-256 digest of data, returned as hex string.
pub fn compute_digest(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify that a provided digest matches the data.
pub fn verify_digest(data: &[u8], expected_hex: &str) -> bool {
    compute_digest(data) == expected_hex
}

/// Sign a response body with ML-DSA-65 and attach integrity headers.
pub fn sign_response_body(
    key_manager: &VersionedKeyManager,
    body: &[u8],
    headers: &mut hyper::HeaderMap,
) {
    let digest = compute_digest(body);

    // Sign the body
    if let Some((kid, sig)) = key_manager.sign_current(body) {
        let sig_b64 = B64.encode(&sig);

        set_header(headers, "x-pqc-signature", &sig_b64);
        set_header(headers, "x-pqc-signature-algorithm", "ML-DSA-65");
        set_header(headers, "x-pqc-content-digest", &digest);
        set_header(headers, "x-pqc-key-id", &kid);
    }
}

/// Verify request body integrity headers.
///
/// Checks:
/// 1. X-PQC-Content-Digest matches SHA-256 of body
/// 2. X-PQC-Request-Signature verifies against the provided public key
pub fn verify_request_integrity(
    key_manager: &VersionedKeyManager,
    body: &[u8],
    headers: &hyper::HeaderMap,
) -> IntegrityResult {
    // Check content digest if provided
    if let Some(digest_val) = get_header(headers, "x-pqc-content-digest") {
        let computed = compute_digest(body);
        if computed != digest_val {
            return IntegrityResult::DigestMismatch {
                expected: digest_val,
                computed,
            };
        }
    }

    // Check signature if provided
    if let Some(sig_b64) = get_header(headers, "x-pqc-request-signature") {
        let kid = get_header(headers, "x-pqc-key-id").unwrap_or_default();

        let sig_bytes = match B64.decode(&sig_b64) {
            Ok(b) => b,
            Err(_) => return IntegrityResult::InvalidSignature("bad base64".to_string()),
        };

        if !key_manager.verify_by_kid(&kid, body, &sig_bytes) {
            return IntegrityResult::InvalidSignature("signature verification failed".to_string());
        }
    }

    IntegrityResult::Valid
}

/// Result of integrity verification.
#[derive(Debug, Clone, PartialEq)]
pub enum IntegrityResult {
    /// Body integrity verified successfully.
    Valid,
    /// Content digest does not match body.
    DigestMismatch { expected: String, computed: String },
    /// Signature verification failed.
    InvalidSignature(String),
}

impl std::fmt::Display for IntegrityResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::DigestMismatch { expected, computed } => {
                write!(f, "digest mismatch: expected={expected}, computed={computed}")
            }
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {msg}"),
        }
    }
}

/// Middleware that verifies request body integrity when PQC integrity headers are present.
pub async fn body_integrity_middleware(
    axum::extract::State(key_manager): axum::extract::State<Arc<VersionedKeyManager>>,
    req: Request,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();

    // Only verify if integrity headers are present
    let has_integrity_headers = parts.headers.contains_key("x-pqc-content-digest")
        || parts.headers.contains_key("x-pqc-request-signature");

    if !has_integrity_headers {
        let req = Request::from_parts(parts, body);
        return next.run(req).await;
    }

    // Read the body to verify
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!(error = %e, "Failed to read request body for integrity check");
            let req = Request::from_parts(parts, Body::empty());
            return next.run(req).await;
        }
    };

    let result = verify_request_integrity(&key_manager, &body_bytes, &parts.headers);

    match result {
        IntegrityResult::Valid => {
            let req = Request::from_parts(parts, Body::from(body_bytes));
            next.run(req).await
        }
        IntegrityResult::DigestMismatch { expected, computed } => {
            warn!(expected = %expected, computed = %computed, "Request body digest mismatch");
            let body = serde_json::json!({
                "error": "request body integrity check failed: digest mismatch",
                "status": 400
            });
            (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
        }
        IntegrityResult::InvalidSignature(msg) => {
            warn!(error = %msg, "Request body signature verification failed");
            let body = serde_json::json!({
                "error": format!("request body integrity check failed: {msg}"),
                "status": 400
            });
            (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
        }
    }
}

fn set_header(headers: &mut hyper::HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), v);
    }
}

fn get_header(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_digest() {
        let data = b"hello world";
        let digest = compute_digest(data);
        assert_eq!(digest.len(), 64); // SHA-256 hex = 64 chars
        // Known SHA-256 of "hello world"
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_digest() {
        let data = b"test data";
        let digest = compute_digest(data);
        assert!(verify_digest(data, &digest));
        assert!(!verify_digest(b"wrong data", &digest));
    }

    #[test]
    fn test_sign_and_verify_body() {
        let mgr = VersionedKeyManager::new(5);
        let body = b"response body content";

        let mut headers = hyper::HeaderMap::new();
        sign_response_body(&mgr, body, &mut headers);

        assert!(headers.contains_key("x-pqc-signature"));
        assert!(headers.contains_key("x-pqc-signature-algorithm"));
        assert!(headers.contains_key("x-pqc-content-digest"));
        assert!(headers.contains_key("x-pqc-key-id"));

        let digest = headers
            .get("x-pqc-content-digest")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(verify_digest(body, digest));
    }

    #[test]
    fn test_verify_request_integrity_valid() {
        let mgr = VersionedKeyManager::new(5);
        let body = b"request body";
        let digest = compute_digest(body);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-pqc-content-digest"),
            HeaderValue::from_str(&digest).unwrap(),
        );

        let result = verify_request_integrity(&mgr, body, &headers);
        assert_eq!(result, IntegrityResult::Valid);
    }

    #[test]
    fn test_verify_request_integrity_digest_mismatch() {
        let mgr = VersionedKeyManager::new(5);
        let body = b"request body";

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-pqc-content-digest"),
            HeaderValue::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
        );

        let result = verify_request_integrity(&mgr, body, &headers);
        assert!(matches!(result, IntegrityResult::DigestMismatch { .. }));
    }

    #[test]
    fn test_verify_request_integrity_with_signature() {
        let mgr = VersionedKeyManager::new(5);
        let body = b"signed request body";

        // Sign with the manager's current key
        let (kid, sig) = mgr.sign_current(body).unwrap();
        let sig_b64 = B64.encode(&sig);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-pqc-request-signature"),
            HeaderValue::from_str(&sig_b64).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-pqc-key-id"),
            HeaderValue::from_str(&kid).unwrap(),
        );

        let result = verify_request_integrity(&mgr, body, &headers);
        assert_eq!(result, IntegrityResult::Valid);
    }

    #[test]
    fn test_verify_request_integrity_bad_signature() {
        let mgr = VersionedKeyManager::new(5);
        let body = b"signed request body";

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-pqc-request-signature"),
            HeaderValue::from_str(&B64.encode(b"invalid-sig")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-pqc-key-id"),
            HeaderValue::from_str("nonexistent-kid").unwrap(),
        );

        let result = verify_request_integrity(&mgr, body, &headers);
        assert!(matches!(result, IntegrityResult::InvalidSignature(_)));
    }

    #[test]
    fn test_no_integrity_headers_passes() {
        let mgr = VersionedKeyManager::new(5);
        let body = b"plain body";
        let headers = hyper::HeaderMap::new();

        let result = verify_request_integrity(&mgr, body, &headers);
        assert_eq!(result, IntegrityResult::Valid);
    }
}