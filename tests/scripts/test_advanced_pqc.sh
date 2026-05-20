#!/usr/bin/env bash
#
# Advanced PQC Features — End-to-End Test Suite
#
# Tests:
#   1-5.   Multi-algorithm cert chain validation & trust store
#   6-12.  Shamir's Secret Sharing & threshold signatures
#   13-20. Batch ML-DSA verification, multi-sig, aggregation, timestamp proofs
#   21-25. Edge cases & integration tests
#
# Usage:
#   ./tests/scripts/test_advanced_pqc.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

pass() {
    echo -e "  ${GREEN}PASS${NC} - $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC} - $1"
    FAILED=$((FAILED + 1))
}

skip() {
    echo -e "  ${YELLOW}SKIP${NC} - $1"
    SKIPPED=$((SKIPPED + 1))
}

section() {
    echo ""
    echo -e "${BOLD}${CYAN}=== $1 ===${NC}"
    echo ""
}

# ------------------------------------------------------------------
cd "$PROJECT_DIR"

echo "============================================"
echo "  PQC Gateway — Advanced PQC Features Tests"
echo "  Multi-Algo Certs | Shamir SSS | Batch DSA"
echo "============================================"
echo ""

# Build everything first
echo -e "${YELLOW}Building workspace...${NC}"
BUILD_OUT=$(cargo build --workspace 2>&1)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful.${NC}"
else
    echo -e "${RED}Build failed:${NC}"
    echo "$BUILD_OUT" | tail -20
    exit 1
fi
echo ""

# ============================================================
# Part 1: Multi-Algorithm Certificate Chain Validation
# ============================================================
section "Part 1: Multi-Algorithm Certificate Chain Validation"

echo "--- Test 1: Hybrid chain ECDSA-P256 -> Ed25519 -> ML-DSA-65 ---"
TEST_OUT=$(cargo test -p pqc-tls test_hybrid_chain_ecdsa_ed25519_mldsa -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Hybrid cert chain (ECDSA→Ed25519→MLDSA) validates successfully"
    echo -e "  ${CYAN}[DETAIL]${NC} 3-level chain with cross-algorithm signatures verified"
else
    fail "Hybrid cert chain validation failed"
    echo "$TEST_OUT" | tail -5
fi

echo "--- Test 2: Single-algorithm chains (ECDSA, Ed25519, MLDSA) ---"
TEST_OUT=$(cargo test -p pqc-tls test_single_algorithm -- --nocapture 2>&1)
SINGLE_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$SINGLE_PASS" -ge 3 ]; then
    pass "All single-algorithm chains validate (ECDSA, Ed25519, MLDSA)"
else
    fail "Some single-algorithm chains failed ($SINGLE_PASS/3 passed)"
fi

echo "--- Test 3: Trust store revocation checks ---"
TEST_OUT=$(cargo test -p pqc-tls test_revoked_cert_rejected -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Revoked certificate correctly rejected"
else
    fail "Revocation check failed"
fi

echo "--- Test 4: Certificate pinning (success + violation) ---"
TEST_OUT=$(cargo test -p pqc-tls test_pinning -- --nocapture 2>&1)
PIN_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$PIN_PASS" -ge 2 ]; then
    pass "Certificate pinning: valid pin accepted, violation rejected"
else
    fail "Certificate pinning tests failed ($PIN_PASS/2)"
fi

echo "--- Test 5: Expired / not-yet-valid certificates rejected ---"
EXPIRED_OUT=$(cargo test -p pqc-tls test_expired_cert_rejected -- --nocapture 2>&1)
NOTYETVALID_OUT=$(cargo test -p pqc-tls test_not_yet_valid_rejected -- --nocapture 2>&1)
EXPIRED_OK=$(echo "$EXPIRED_OUT" | grep -c "\.\.\. ok" || true)
NOTYETVALID_OK=$(echo "$NOTYETVALID_OUT" | grep -c "\.\.\. ok" || true)
if [ "$EXPIRED_OK" -ge 1 ] && [ "$NOTYETVALID_OK" -ge 1 ]; then
    pass "Expired and not-yet-valid certificates correctly rejected"
else
    fail "Expiry validation failed (expired=$EXPIRED_OK, not_yet_valid=$NOTYETVALID_OK)"
fi

echo "--- Test 5b: Pre-expiry warnings generated ---"
TEST_OUT=$(cargo test -p pqc-tls test_expiry_warning -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Pre-expiry warning generated for near-expiry certificates"
else
    fail "Expiry warning test failed"
fi

echo "--- Test 5c: Tampered signature rejected ---"
TEST_OUT=$(cargo test -p pqc-tls test_tampered_signature_rejected -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Tampered certificate signature correctly detected and rejected"
else
    fail "Tampered signature detection failed"
fi

echo "--- Test 5d: 4-level hybrid chain ---"
TEST_OUT=$(cargo test -p pqc-tls test_long_hybrid_chain_4_levels -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "4-level hybrid chain (ECDSA→Ed25519→MLDSA→ECDSA) validates"
else
    fail "4-level chain validation failed"
fi

echo "--- Test 5e: Non-CA signing child rejected ---"
TEST_OUT=$(cargo test -p pqc-tls test_non_ca_signing_child_rejected -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Non-CA certificate correctly rejected as chain intermediate"
else
    fail "Non-CA intermediate detection failed"
fi

# ============================================================
# Part 2: Shamir's Secret Sharing & Threshold Signatures
# ============================================================
section "Part 2: Shamir's Secret Sharing & Threshold Signatures"

echo "--- Test 6: GF(256) arithmetic correctness ---"
TEST_OUT=$(cargo test -p pqc-tls "test_gf256_" -- --nocapture 2>&1)
GF_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$GF_PASS" -ge 3 ]; then
    pass "GF(256) field arithmetic verified (mul, identity, inverse, commutativity)"
    echo -e "  ${CYAN}[DETAIL]${NC} All 255 non-zero inverses verified: a * a^(-1) = 1"
else
    fail "GF(256) arithmetic tests failed ($GF_PASS passed)"
fi

echo "--- Test 7: Secret split/reconstruct (basic) ---"
TEST_OUT=$(cargo test -p pqc-tls test_split_reconstruct_basic -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Shamir SSS: 3-of-5 split/reconstruct works"
else
    fail "Basic split/reconstruct failed"
fi

echo "--- Test 8: ML-DSA-65 seed split/reconstruct + signing ---"
TEST_OUT=$(cargo test -p pqc-tls test_split_reconstruct_mldsa_seed -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "32-byte ML-DSA seed split/reconstructed; signing works with recovered seed"
else
    fail "ML-DSA seed split/reconstruct failed"
fi

echo "--- Test 9: Insufficient shares yields wrong secret ---"
TEST_OUT=$(cargo test -p pqc-tls test_insufficient_shares_wrong_result -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Below-threshold shares correctly produce incorrect secret"
else
    fail "Insufficient shares test failed"
fi

echo "--- Test 10: All C(5,3)=10 share combinations work ---"
TEST_OUT=$(cargo test -p pqc-tls test_different_share_combinations -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "All 10 combinations of 3-of-5 shares reconstruct correctly"
else
    fail "Share combination test failed"
fi

echo "--- Test 11: Distributed multi-party signing ---"
TEST_OUT=$(cargo test -p pqc-tls test_distributed_signing -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Distributed signing: 3 parties generate valid ML-DSA signature"
else
    fail "Distributed signing failed"
fi

echo "--- Test 12: Threshold key manager lifecycle ---"
TEST_OUT=$(cargo test -p pqc-tls test_threshold_key_manager -- --nocapture 2>&1)
MNGR_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$MNGR_PASS" -ge 1 ]; then
    pass "Threshold key manager: create, sign, verify, quorum enforcement"
else
    fail "Key manager lifecycle tests failed"
fi

echo "--- Test 12b: Recovery codes roundtrip ---"
TEST_OUT=$(cargo test -p pqc-tls test_recovery_codes_roundtrip -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Recovery codes: generate → parse → reconstruct → sign → verify"
else
    fail "Recovery code roundtrip failed"
fi

echo "--- Test 12c: Key manager recovery from codes ---"
TEST_OUT=$(cargo test -p pqc-tls test_threshold_key_manager_recovery -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Key manager recovered from recovery codes; same public key restored"
else
    fail "Key manager recovery failed"
fi

# ============================================================
# Part 3: Batch ML-DSA Verification, Multi-Sig, Aggregation
# ============================================================
section "Part 3: Batch ML-DSA Verification, Multi-Sig, Aggregation"

echo "--- Test 13: Batch verify 100 ML-DSA-65 signatures ---"
TEST_OUT=$(cargo test -p pqc-tls test_batch_verify_100_signatures -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Batch verified 100 ML-DSA-65 signatures"
    DURATION=$(echo "$TEST_OUT" | grep -oP 'duration_ms=\K\d+' | head -1 || true)
    [ -n "$DURATION" ] && echo -e "  ${CYAN}[PERF]${NC} Verification time: ${DURATION}ms for 100 signatures"
else
    fail "Batch verification of 100 signatures failed"
fi

echo "--- Test 14: Batch verify with invalid signatures detected ---"
ONE_INV_OUT=$(cargo test -p pqc-tls test_batch_verify_with_one_invalid -- --nocapture 2>&1)
MULTI_INV_OUT=$(cargo test -p pqc-tls test_batch_verify_with_multiple_invalid -- --nocapture 2>&1)
ONE_OK=$(echo "$ONE_INV_OUT" | grep -c "\.\.\. ok" || true)
MULTI_OK=$(echo "$MULTI_INV_OUT" | grep -c "\.\.\. ok" || true)
if [ "$ONE_OK" -ge 1 ] && [ "$MULTI_OK" -ge 1 ]; then
    pass "Invalid signatures correctly detected in batch (single + multiple)"
else
    fail "Batch invalid detection failed (one=$ONE_OK, multi=$MULTI_OK)"
fi

echo "--- Test 15: Parallel batch verification ---"
TEST_OUT=$(cargo test -p pqc-tls test_batch_verify_parallel -- --nocapture 2>&1)
PAR_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$PAR_PASS" -ge 2 ]; then
    pass "Parallel batch verification works (multi-thread + single-thread)"
else
    fail "Parallel batch verification failed ($PAR_PASS passed)"
fi

echo "--- Test 16: Multi-signature (multiple signers, same message) ---"
TEST_OUT=$(cargo test -p pqc-tls test_multi_signature -- --nocapture 2>&1)
MSIG_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$MSIG_PASS" -ge 2 ]; then
    pass "Multi-signature: 3 signers, verification, tamper detection"
else
    fail "Multi-signature tests failed ($MSIG_PASS passed)"
fi

echo "--- Test 17: Signature aggregation & compression ---"
TEST_OUT=$(cargo test -p pqc-tls test_signature_aggregation -- --nocapture 2>&1)
AGG_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$AGG_PASS" -ge 2 ]; then
    pass "Signature aggregation with key deduplication and compression"
else
    fail "Aggregation tests failed ($AGG_PASS passed)"
fi

echo "--- Test 18: Aggregation compression ratio ---"
TEST_OUT=$(cargo test -p pqc-tls test_signature_aggregation_compression_ratio -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Compression ratio < 1.0 with same-key deduplication"
else
    fail "Compression ratio test failed"
fi

echo "--- Test 19: Quantum-safe timestamp proofs ---"
TEST_OUT=$(cargo test -p pqc-tls test_timestamp_proof -- --nocapture 2>&1)
TS_PASS=$(echo "$TEST_OUT" | grep -c "\.\.\. ok" || true)
if [ "$TS_PASS" -ge 3 ]; then
    pass "Timestamp proofs: create, verify, tamper detection, time bounds"
else
    fail "Timestamp proof tests failed ($TS_PASS passed)"
fi

echo "--- Test 20: Timestamp authority issues multiple proofs ---"
TEST_OUT=$(cargo test -p pqc-tls test_timestamp_authority_multiple_proofs -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Timestamp authority issued and verified 5 proofs"
else
    fail "Multiple proofs test failed"
fi

# ============================================================
# Part 4: Edge Cases & Integration
# ============================================================
section "Part 4: Edge Cases & Integration"

echo "--- Test 21: Empty chain rejected ---"
TEST_OUT=$(cargo test -p pqc-tls test_empty_chain_rejected -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Empty certificate chain correctly rejected"
else
    fail "Empty chain test failed"
fi

echo "--- Test 22: Chain broken (issuer mismatch) ---"
TEST_OUT=$(cargo test -p pqc-tls test_chain_broken_issuer_mismatch -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Broken chain with issuer mismatch detected"
else
    fail "Chain break detection failed"
fi

echo "--- Test 23: Single-byte and large secret splitting ---"
SINGLE_BYTE_OUT=$(cargo test -p pqc-tls test_single_byte_secret -- --nocapture 2>&1)
LARGE_OUT=$(cargo test -p pqc-tls test_large_secret_split -- --nocapture 2>&1)
SB_OK=$(echo "$SINGLE_BYTE_OUT" | grep -c "\.\.\. ok" || true)
LG_OK=$(echo "$LARGE_OUT" | grep -c "\.\.\. ok" || true)
if [ "$SB_OK" -ge 1 ] && [ "$LG_OK" -ge 1 ]; then
    pass "Edge cases: 1-byte and 256-byte secrets split/reconstruct"
else
    fail "Edge case splitting failed (single_byte=$SB_OK, large=$LG_OK)"
fi

echo "--- Test 24: Batch verify with different signers ---"
TEST_OUT=$(cargo test -p pqc-tls test_batch_verify_different_signers -- --nocapture 2>&1)
if echo "$TEST_OUT" | grep -q "test .* ok"; then
    pass "Batch verification with mixed signers works"
else
    fail "Mixed-signer batch test failed"
fi

echo "--- Test 25: Full workspace test suite ---"
echo -e "  ${CYAN}[INFO]${NC} Running complete cargo test --workspace..."
TEST_OUT=$(cargo test --workspace 2>&1)
if echo "$TEST_OUT" | grep -q "test result: ok" && ! echo "$TEST_OUT" | grep -q "FAILED"; then
    TOTAL_TESTS=$(echo "$TEST_OUT" | grep -oP '\d+ passed' | tail -1 || true)
    pass "All cargo unit tests pass across workspace"

    # Count tests per module
    CERT_CHAIN_TESTS=$(echo "$TEST_OUT" | grep -c "cert_chain::tests::" || true)
    THRESHOLD_TESTS=$(echo "$TEST_OUT" | grep -c "threshold::tests::" || true)
    BATCH_TESTS=$(echo "$TEST_OUT" | grep -c "batch_verify::tests::" || true)
    echo -e "  ${CYAN}[BREAKDOWN]${NC} cert_chain: $CERT_CHAIN_TESTS | threshold: $THRESHOLD_TESTS | batch_verify: $BATCH_TESTS"
else
    fail "Workspace test suite has failures"
    echo "$TEST_OUT" | grep "FAILED\|error\[" | head -10
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================"
TOTAL=$((PASSED + FAILED))
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${SKIPPED} skipped${NC} out of ${TOTAL} tests"
echo ""
echo "  Features verified:"
echo "    - Multi-algorithm cert chains (ECDSA/Ed25519/ML-DSA-65)"
echo "    - Trust store with revocation, pinning, expiry warnings"
echo "    - Shamir's Secret Sharing over GF(256)"
echo "    - Threshold signatures with quorum enforcement"
echo "    - Recovery codes for key recovery"
echo "    - Batch ML-DSA-65 verification (100+ signatures)"
echo "    - Multi-signature support"
echo "    - Signature aggregation with compression"
echo "    - Quantum-safe timestamp proofs"
echo "============================================"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0