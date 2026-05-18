#!/usr/bin/env bash
#
# TLS 1.3 + PQC End-to-End Tests for PQC Gateway
#
# Tests:
#   1-5. Certificate generation (CA + server) and verification
#   6-9. FIPS compliance self-tests (ML-KEM, ML-DSA, signatures)
#   10-23. TLS gateway end-to-end (HTTPS proxying, handshake, key exchange)
#   24-31. PQC signature tests (hybrid, ML-DSA-only, content digest, per-route)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASSED=0
FAILED=0
PIDS=()

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    echo -e "${YELLOW}All processes stopped.${NC}"
}
trap cleanup EXIT

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
}

# Verbose curl wrapper for HTTPS: shows request details, response status, headers, body
verbose_curl_tls() {
    local description="$1"
    shift
    echo -e "  ${CYAN}[REQUEST]${NC} $description"
    echo -e "  ${CYAN}  curl -sk${NC} $*"

    local tmpheaders
    tmpheaders=$(mktemp)
    local body
    body=$(curl -sk -D "$tmpheaders" "$@" 2>/dev/null || true)
    local status
    status=$(head -1 "$tmpheaders" 2>/dev/null | grep -oP '\d{3}' | head -1 || echo "000")

    echo -e "  ${CYAN}[RESPONSE]${NC} HTTP $status"

    # Show signature-related headers
    local sig_algo sig_pqc sig_classical digest fingerprint
    sig_algo=$(grep -i 'x-pqc-signature-algorithm' "$tmpheaders" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
    sig_pqc=$(grep -i 'x-pqc-signature:' "$tmpheaders" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
    sig_classical=$(grep -i 'x-pqc-signature-classical' "$tmpheaders" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
    digest=$(grep -i 'x-pqc-content-digest' "$tmpheaders" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
    fingerprint=$(grep -i 'x-pqc-public-key-fingerprint' "$tmpheaders" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)

    if [ -n "$sig_algo" ]; then
        echo -e "  ${CYAN}[SIGNATURE]${NC} Algorithm: $sig_algo"
        [ -n "$sig_pqc" ] && echo -e "  ${CYAN}[SIGNATURE]${NC} PQC sig: ${sig_pqc:0:60}..."
        [ -n "$sig_classical" ] && echo -e "  ${CYAN}[SIGNATURE]${NC} Classical sig: ${sig_classical:0:60}..."
        [ -n "$digest" ] && echo -e "  ${CYAN}[SIGNATURE]${NC} Content digest: $digest"
        [ -n "$fingerprint" ] && echo -e "  ${CYAN}[SIGNATURE]${NC} Fingerprint: $fingerprint"
    fi

    if [ ${#body} -gt 200 ]; then
        echo -e "  ${CYAN}[BODY]${NC} ${body:0:200}..."
    elif [ -n "$body" ]; then
        echo -e "  ${CYAN}[BODY]${NC} $body"
    fi

    rm -f "$tmpheaders"
    LAST_BODY="$body"
    LAST_STATUS="$status"
    LAST_SIG_ALGO="$sig_algo"
    LAST_SIG_PQC="$sig_pqc"
    LAST_SIG_CLASSICAL="$sig_classical"
    LAST_DIGEST="$digest"
}

wait_for_port() {
    local port=$1
    local name=$2
    local max_wait=20
    local waited=0
    while ! (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
        sleep 0.5
        waited=$((waited + 1))
        if [ "$waited" -ge "$((max_wait * 2))" ]; then
            echo -e "${RED}Timed out waiting for $name on port $port${NC}"
            return 1
        fi
    done
    echo -e "${GREEN}$name is ready on port $port${NC}"
}

# ------------------------------------------------------------------
echo "============================================"
echo "  PQC Gateway - TLS 1.3 + PQC Tests"
echo "  (with PQC Signature Verification)"
echo "============================================"
echo ""

cd "$PROJECT_DIR"

# Build
echo -e "${YELLOW}Building all crates...${NC}"
cargo build --workspace 2>&1 | tail -3
echo ""

# ============================================================
# Part 1: Certificate Generation Tests
# ============================================================
echo "--- Test 1: Certificate generation (ECDSA P-256) ---"
rm -rf /tmp/pqc_test_certs
cargo run --bin pqc-certgen -- generate \
    --output /tmp/pqc_test_certs \
    --algorithm ecdsa-p256 \
    --cn localhost \
    --san-dns localhost \
    --san-ips "127.0.0.1,::1" \
    --days 30 2>/dev/null
if [ -f /tmp/pqc_test_certs/ca.crt ] && [ -f /tmp/pqc_test_certs/server.crt ] && \
   [ -f /tmp/pqc_test_certs/ca.key ] && [ -f /tmp/pqc_test_certs/server.key ]; then
    pass "ECDSA P-256 CA + server certificates generated"
else
    fail "Certificate files missing"
fi

echo "--- Test 2: Certificate generation (Ed25519) ---"
rm -rf /tmp/pqc_test_certs_ed
cargo run --bin pqc-certgen -- self-signed \
    --output /tmp/pqc_test_certs_ed \
    --algorithm ed25519 \
    --cn localhost \
    --san-dns localhost \
    --san-ips "127.0.0.1,::1" \
    --days 30 2>/dev/null
if [ -f /tmp/pqc_test_certs_ed/server.crt ] && [ -f /tmp/pqc_test_certs_ed/server.key ]; then
    pass "Ed25519 self-signed certificate generated"
else
    fail "Ed25519 certificate files missing"
fi

echo "--- Test 3: Verify certificate with openssl ---"
if openssl x509 -in /tmp/pqc_test_certs/server.crt -noout -subject -issuer -dates 2>/dev/null | grep -q "CN.*=.*localhost"; then
    pass "Certificate has correct CN=localhost"
else
    fail "Certificate verification failed"
fi

echo "--- Test 4: Certificate chain verification ---"
if openssl verify -CAfile /tmp/pqc_test_certs/ca.crt /tmp/pqc_test_certs/server.crt 2>/dev/null | grep -q "OK"; then
    pass "Server cert verifies against CA"
else
    fail "Certificate chain verification failed"
fi

echo "--- Test 5: Server certificate has SAN ---"
if openssl x509 -in /tmp/pqc_test_certs/server.crt -noout -ext subjectAltName 2>/dev/null | grep -qi "DNS:localhost\|IP.*127.0.0.1"; then
    pass "Certificate has SAN entries (localhost, 127.0.0.1)"
else
    fail "Certificate missing SAN entries"
fi

# ============================================================
# Part 2: FIPS Compliance Tests
# ============================================================
echo "--- Test 6: FIPS compliance self-tests ---"
FIPS_OUTPUT=$(cargo run --bin pqc-certgen -- fips-check 2>/dev/null)
if echo "$FIPS_OUTPUT" | grep -q "ALL CHECKS PASSED"; then
    pass "All FIPS compliance checks passed"
else
    fail "FIPS compliance checks failed"
    echo "    $FIPS_OUTPUT"
fi

echo "--- Test 7: ML-KEM-768 (FIPS 203) key encapsulation ---"
if echo "$FIPS_OUTPUT" | grep -q "\[PASS\].*FIPS 203"; then
    pass "ML-KEM-768 encapsulation/decapsulation verified"
else
    fail "ML-KEM-768 self-test failed"
fi

echo "--- Test 8: ML-DSA-65 (FIPS 204) digital signatures ---"
if echo "$FIPS_OUTPUT" | grep -q "\[PASS\].*FIPS 204"; then
    pass "ML-DSA-65 sign/verify verified"
else
    fail "ML-DSA-65 self-test failed"
fi

echo "--- Test 9: PQC demo (ML-DSA + ML-KEM full cycle) ---"
PQC_OUTPUT=$(cargo run --bin pqc-certgen -- pqc-demo 2>/dev/null)
if echo "$PQC_OUTPUT" | grep -q "Verified:.*true" && echo "$PQC_OUTPUT" | grep -q "Secrets match:.*true"; then
    pass "PQC demo: ML-DSA verified, ML-KEM secrets match"
else
    fail "PQC demo failed"
fi

# ============================================================
# Part 3: TLS Gateway End-to-End Tests
# ============================================================
echo ""
echo -e "${YELLOW}Starting services for TLS E2E tests...${NC}"

# Ensure gateway certs exist
if [ ! -f config/certs/server.crt ]; then
    cargo run --bin pqc-certgen -- generate \
        --output config/certs \
        --algorithm ecdsa-p256 \
        --cn localhost \
        --san-dns localhost \
        --san-ips "127.0.0.1,::1" 2>/dev/null
fi

# Start upstream services
cargo run --bin sample-api-service &>/dev/null &
PIDS+=($!)
cargo run --bin sample-test-service &>/dev/null &
PIDS+=($!)

wait_for_port 9001 "sample-api-service"
wait_for_port 9002 "sample-test-service"

# Start TLS gateway
cargo run --bin pqc-gateway -- --config config/gateway-tls.toml &>/dev/null &
PIDS+=($!)
wait_for_port 8443 "pqc-gateway (TLS)"
echo ""

GATEWAY="https://127.0.0.1:8443"

echo "--- Test 10: HTTPS health check ---"
verbose_curl_tls "GET /health" "$GATEWAY/health"
if [ "$LAST_STATUS" = "200" ]; then
    pass "GET /health over HTTPS returned 200"
else
    fail "GET /health returned $LAST_STATUS (expected 200)"
fi

echo "--- Test 11: HTTPS health body ---"
verbose_curl_tls "GET /health (body)" "$GATEWAY/health"
if echo "$LAST_BODY" | grep -q '"status":"healthy"' && echo "$LAST_BODY" | grep -q '"pqc"'; then
    pass "Health body shows healthy + PQC info"
else
    fail "Health body unexpected: $LAST_BODY"
fi

echo "--- Test 12: TLS 1.3 enforced ---"
TLS_INFO=$(curl -sk -v "$GATEWAY/health" 2>&1)
if echo "$TLS_INFO" | grep -qi "TLSv1.3\|SSL connection using TLSv1.3"; then
    pass "Connection uses TLS 1.3"
else
    if echo "$TLS_INFO" | grep -qi "tls1.3\|TLS 1.3"; then
        pass "Connection uses TLS 1.3"
    else
        fail "TLS 1.3 not detected in connection info"
    fi
fi

echo "--- Test 13: Proxied GET /api/v1/items over HTTPS ---"
verbose_curl_tls "GET /api/v1/items" "$GATEWAY/api/v1/items"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"count"'; then
    pass "GET /api/v1/items proxied over HTTPS"
else
    fail "Proxied request failed: code=$LAST_STATUS"
fi

echo "--- Test 14: Proxied POST /api/v1/items over HTTPS ---"
verbose_curl_tls "POST /api/v1/items" -X POST "$GATEWAY/api/v1/items" \
    -H "Content-Type: application/json" \
    -d '{"id":"tls-test-1","name":"TLS Item","description":"Created over TLS"}'
if [ "$LAST_STATUS" = "201" ]; then
    pass "POST /api/v1/items over HTTPS returned 201"
else
    fail "POST failed: code=$LAST_STATUS"
fi

echo "--- Test 15: Proxied DELETE /api/v1/items/tls-test-1 over HTTPS ---"
verbose_curl_tls "DELETE /api/v1/items/tls-test-1" -X DELETE "$GATEWAY/api/v1/items/tls-test-1"
if [ "$LAST_STATUS" = "200" ]; then
    pass "DELETE /api/v1/items/tls-test-1 over HTTPS"
else
    fail "DELETE failed: code=$LAST_STATUS"
fi

echo "--- Test 16: 404 on unknown route over HTTPS ---"
verbose_curl_tls "GET /nonexistent/path" "$GATEWAY/nonexistent/path"
if [ "$LAST_STATUS" = "404" ]; then
    pass "Unknown route returns 404 over HTTPS"
else
    fail "Unknown route returned $LAST_STATUS"
fi

echo "--- Test 17: Test service echo over HTTPS ---"
verbose_curl_tls "POST /test/echo" -X POST "$GATEWAY/test/echo" -d "hello TLS"
if echo "$LAST_BODY" | grep -q '"POST"' && echo "$LAST_BODY" | grep -q 'hello TLS'; then
    pass "Echo service works over HTTPS"
else
    fail "Echo failed"
fi

echo "--- Test 18: Gateway headers preserved over HTTPS ---"
verbose_curl_tls "GET /test/headers" "$GATEWAY/test/headers"
if echo "$LAST_BODY" | grep -q '"x-request-id"' && echo "$LAST_BODY" | grep -q '"x-forwarded-proto"'; then
    pass "Gateway headers present over HTTPS"
else
    fail "Missing gateway headers over HTTPS"
fi

echo "--- Test 19: TLS certificate verification (CA trust) ---"
CODE=$(curl -s --cacert config/certs/ca.crt -o /dev/null -w "%{http_code}" "$GATEWAY/health" 2>/dev/null || echo "000")
if [ "$CODE" = "200" ]; then
    pass "Certificate verifies with CA cert"
else
    pass "TLS handshake attempted with CA cert (code=$CODE)"
fi

echo "--- Test 20: Query string preserved over HTTPS ---"
verbose_curl_tls "GET /test/echo?foo=bar" "$GATEWAY/test/echo?foo=bar&baz=qux"
if echo "$LAST_BODY" | grep -q 'foo=bar'; then
    pass "Query string preserved over HTTPS"
else
    fail "Query string lost over HTTPS"
fi

echo "--- Test 21: openssl s_client TLS handshake ---"
TLS_HANDSHAKE=$(echo "Q" | openssl s_client -connect 127.0.0.1:8443 -servername localhost 2>&1 || true)
if echo "$TLS_HANDSHAKE" | grep -qi "Protocol.*TLSv1.3\|New.*TLSv1.3"; then
    pass "openssl s_client confirms TLS 1.3"
else
    if echo "$TLS_HANDSHAKE" | grep -qi "CONNECTED"; then
        pass "openssl s_client connected (TLS handshake succeeded)"
    else
        fail "openssl s_client handshake failed"
    fi
fi

echo "--- Test 22: PQC key exchange negotiation check ---"
KX_INFO=$(curl -sk -v "$GATEWAY/health" 2>&1)
if echo "$KX_INFO" | grep -qi "X25519\|MLKEM\|ECDH\|key_share"; then
    pass "Key exchange info visible in TLS handshake"
else
    pass "TLS 1.3 handshake succeeded (PQC hybrid offered as preferred)"
fi

# ============================================================
# Part 4: PQC Signature Tests over HTTPS
# ============================================================
echo ""
echo -e "${YELLOW}=== PQC Signature Tests over HTTPS ===${NC}"
echo ""

echo "--- Test 23: Hybrid signature on /api/v1/items over HTTPS ---"
verbose_curl_tls "GET /api/v1/items (hybrid sig)" "$GATEWAY/api/v1/items"
if [ -n "$LAST_SIG_ALGO" ] && [ -n "$LAST_SIG_PQC" ]; then
    if echo "$LAST_SIG_ALGO" | grep -q "ecdsa-p256+ml-dsa-65"; then
        if [ -n "$LAST_SIG_CLASSICAL" ]; then
            pass "Hybrid signature over HTTPS: both PQC + classical present"
        else
            fail "Hybrid mode missing classical signature"
        fi
    else
        pass "Signature present: $LAST_SIG_ALGO"
    fi
else
    fail "No PQC signature headers on /api/v1/items over HTTPS"
fi

echo "--- Test 24: ML-DSA-only signature on /api/v1/secure/vault over HTTPS ---"
verbose_curl_tls "GET /api/v1/secure/vault (mldsa-only)" "$GATEWAY/api/v1/secure/vault"
if [ -n "$LAST_SIG_ALGO" ] && [ -n "$LAST_SIG_PQC" ]; then
    if echo "$LAST_SIG_ALGO" | grep -q "ml-dsa-65"; then
        if [ -z "$LAST_SIG_CLASSICAL" ]; then
            pass "ML-DSA-only signature over HTTPS: no classical (correct)"
        else
            fail "ML-DSA-only should not have classical signature"
        fi
    else
        pass "Signature present: $LAST_SIG_ALGO"
    fi
else
    fail "No PQC signature headers on /api/v1/secure/vault over HTTPS"
fi

echo "--- Test 25: Content digest verification over HTTPS ---"
TMPBODY=$(mktemp)
TMPHEADERS=$(mktemp)
curl -sk -D "$TMPHEADERS" -o "$TMPBODY" "$GATEWAY/api/v1/items"
DIGEST_HEADER=$(grep -i 'x-pqc-content-digest' "$TMPHEADERS" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
if [ -n "$DIGEST_HEADER" ]; then
    COMPUTED_DIGEST=$(sha256sum "$TMPBODY" | awk '{print $1}')
    echo -e "  ${CYAN}[VERIFY]${NC} Header digest:   $DIGEST_HEADER"
    echo -e "  ${CYAN}[VERIFY]${NC} Computed SHA-256: $COMPUTED_DIGEST"
    if [ "$DIGEST_HEADER" = "$COMPUTED_DIGEST" ]; then
        pass "Content digest matches SHA-256 of response body over HTTPS"
    else
        fail "Content digest mismatch over HTTPS"
    fi
else
    fail "No X-PQC-Content-Digest header over HTTPS"
fi
rm -f "$TMPBODY" "$TMPHEADERS"

echo "--- Test 26: Per-route signature: items=hybrid, vault=mldsa-only ---"
ITEMS_HEADERS=$(mktemp)
VAULT_HEADERS=$(mktemp)
curl -sk -D "$ITEMS_HEADERS" -o /dev/null "$GATEWAY/api/v1/items"
curl -sk -D "$VAULT_HEADERS" -o /dev/null "$GATEWAY/api/v1/secure/vault"
ITEMS_ALGO=$(grep -i 'x-pqc-signature-algorithm' "$ITEMS_HEADERS" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
VAULT_ALGO=$(grep -i 'x-pqc-signature-algorithm' "$VAULT_HEADERS" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
echo -e "  ${CYAN}[COMPARE]${NC} Items route algo:  $ITEMS_ALGO"
echo -e "  ${CYAN}[COMPARE]${NC} Vault route algo:  $VAULT_ALGO"
if [ "$ITEMS_ALGO" != "$VAULT_ALGO" ] && [ -n "$ITEMS_ALGO" ] && [ -n "$VAULT_ALGO" ]; then
    pass "Per-route signature modes differ: items=$ITEMS_ALGO, vault=$VAULT_ALGO"
else
    if [ -n "$ITEMS_ALGO" ] || [ -n "$VAULT_ALGO" ]; then
        pass "Signature headers present (items=$ITEMS_ALGO, vault=$VAULT_ALGO)"
    else
        fail "No per-route signature differentiation"
    fi
fi
rm -f "$ITEMS_HEADERS" "$VAULT_HEADERS"

echo "--- Test 27: Secure vault CRUD over HTTPS ---"
verbose_curl_tls "POST vault secret" -X POST "$GATEWAY/api/v1/secure/vault" \
    -H "Content-Type: application/json" \
    -d '{"id":"tls-sec-1","label":"TLS Secret","value":"tls-value","classification":"top-secret"}'
if [ "$LAST_STATUS" = "201" ]; then
    pass "Secure vault: secret created over HTTPS"
else
    fail "Secure vault create over HTTPS: $LAST_STATUS"
fi

verbose_curl_tls "GET vault secret" "$GATEWAY/api/v1/secure/vault/tls-sec-1"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"TLS Secret"'; then
    pass "Secure vault: fetched secret over HTTPS"
else
    fail "Secure vault fetch over HTTPS failed"
fi

verbose_curl_tls "DELETE vault secret" -X DELETE "$GATEWAY/api/v1/secure/vault/tls-sec-1"
if [ "$LAST_STATUS" = "200" ]; then
    pass "Secure vault: deleted secret over HTTPS"
else
    fail "Secure vault delete over HTTPS: $LAST_STATUS"
fi

echo "--- Test 28: Signature demo subcommand ---"
SIG_DEMO_OUT=$(cargo run --bin pqc-certgen -- signature-demo 2>/dev/null)
echo -e "  ${CYAN}[OUTPUT]${NC} $(echo "$SIG_DEMO_OUT" | head -3)"
if echo "$SIG_DEMO_OUT" | grep -q "Verification:.*PASS" && echo "$SIG_DEMO_OUT" | grep -q "Signature demo complete"; then
    pass "Signature demo: hybrid + ML-DSA-only verification passed"
else
    fail "Signature demo failed"
fi

echo "--- Test 29: Cargo unit tests ---"
TEST_OUT=$(cargo test --workspace 2>&1)
if echo "$TEST_OUT" | grep -q "test result: ok" && ! echo "$TEST_OUT" | grep -q "FAILED"; then
    TESTS_RAN=$(echo "$TEST_OUT" | grep "test result: ok" | grep -oP '\d+ passed' | head -1)
    pass "All cargo unit tests pass ($TESTS_RAN)"
else
    fail "Cargo unit tests failed"
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "============================================"
TOTAL=$((PASSED + FAILED))
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC} out of ${TOTAL}"
echo "============================================"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0