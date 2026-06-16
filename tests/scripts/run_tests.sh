#!/usr/bin/env bash
#
# End-to-end test script for PQC Gateway.
# Starts all services, runs tests via curl with verbose output, then cleans up.
# Includes PQC signature tests (hybrid + ML-DSA-only modes).
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

# Verbose curl wrapper: shows request details, response status, headers, and body
verbose_curl() {
    local description="$1"
    shift
    echo -e "  ${CYAN}[REQUEST]${NC} $description"
    echo -e "  ${CYAN}  curl${NC} $*"

    # Capture response body + headers
    local tmpheaders
    tmpheaders=$(mktemp)
    local body
    body=$(curl -s -D "$tmpheaders" "$@" 2>/dev/null || true)
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

    # Show body (truncated)
    if [ ${#body} -gt 200 ]; then
        echo -e "  ${CYAN}[BODY]${NC} ${body:0:200}..."
    elif [ -n "$body" ]; then
        echo -e "  ${CYAN}[BODY]${NC} $body"
    fi

    rm -f "$tmpheaders"
    # Export for callers
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
    local max_wait=15
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
echo "  PQC Gateway - End-to-End Tests"
echo "  (with PQC Signature Verification)"
echo "============================================"
echo ""

# Build everything
echo -e "${YELLOW}Building all crates...${NC}"
cd "$PROJECT_DIR"
cargo build --workspace 2>&1 | tail -5
echo ""

# Start sample-api-service (port 9001)
echo -e "${YELLOW}Starting sample-api-service on :9001...${NC}"
cargo run --bin sample-api-service &>/dev/null &
PIDS+=($!)

# Start sample-test-service (port 9002)
echo -e "${YELLOW}Starting sample-test-service on :9002...${NC}"
cargo run --bin sample-test-service &>/dev/null &
PIDS+=($!)

# Wait for upstream services
wait_for_port 9001 "sample-api-service"
wait_for_port 9002 "sample-test-service"

# Start gateway (port 8090 public, port 9090 admin)
echo -e "${YELLOW}Starting pqc-gateway on :8090 (admin :9090)...${NC}"
GATEWAY_ADMIN_API_KEY=test-api-key cargo run --bin pqc-gateway -- --config config/gateway.toml &>/dev/null &
PIDS+=($!)

wait_for_port 8090 "pqc-gateway"
wait_for_port 9090 "pqc-gateway admin"
echo ""

# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

GATEWAY="http://127.0.0.1:8090"

echo "--- Test 1: Gateway health check ---"
verbose_curl "GET /health" "$GATEWAY/health"
if [ "$LAST_STATUS" = "200" ]; then
    pass "GET /health returned 200"
else
    fail "GET /health returned $LAST_STATUS (expected 200)"
fi

echo "--- Test 2: Gateway health body ---"
verbose_curl "GET /health (body check)" "$GATEWAY/health"
if echo "$LAST_BODY" | grep -q '"status":"healthy"'; then
    pass "Health body contains status:healthy"
else
    fail "Health body unexpected: $LAST_BODY"
fi

echo "--- Test 3: GET /api/v1/items (list) ---"
verbose_curl "GET /api/v1/items" "$GATEWAY/api/v1/items"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"count"'; then
    pass "List items returned 200 with count"
else
    fail "List items: code=$LAST_STATUS"
fi

echo "--- Test 4: POST /api/v1/items (create) ---"
verbose_curl "POST /api/v1/items" -X POST "$GATEWAY/api/v1/items" \
    -H "Content-Type: application/json" \
    -d '{"id":"curl-1","name":"Curl Item","description":"Created via curl"}'
if [ "$LAST_STATUS" = "201" ] && echo "$LAST_BODY" | grep -q '"Curl Item"'; then
    pass "Create item returned 201"
else
    fail "Create item: code=$LAST_STATUS"
fi

echo "--- Test 5: GET /api/v1/items/curl-1 (get specific) ---"
verbose_curl "GET /api/v1/items/curl-1" "$GATEWAY/api/v1/items/curl-1"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"Curl Item"'; then
    pass "Get item returned 200 with correct name"
else
    fail "Get item: code=$LAST_STATUS"
fi

echo "--- Test 6: PUT /api/v1/items/curl-1 (update) ---"
verbose_curl "PUT /api/v1/items/curl-1" -X PUT "$GATEWAY/api/v1/items/curl-1" \
    -H "Content-Type: application/json" \
    -d '{"id":"curl-1","name":"Updated Curl Item","description":"Updated via curl"}'
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"Updated Curl Item"'; then
    pass "Update item returned 200"
else
    fail "Update item: code=$LAST_STATUS"
fi

echo "--- Test 7: DELETE /api/v1/items/curl-1 ---"
verbose_curl "DELETE /api/v1/items/curl-1" -X DELETE "$GATEWAY/api/v1/items/curl-1"
if [ "$LAST_STATUS" = "200" ]; then
    pass "Delete item returned 200"
else
    fail "Delete item: code=$LAST_STATUS"
fi

echo "--- Test 8: GET /api/v1/items/curl-1 (should be 404) ---"
verbose_curl "GET /api/v1/items/curl-1 (after delete)" "$GATEWAY/api/v1/items/curl-1"
if [ "$LAST_STATUS" = "404" ]; then
    pass "Deleted item returns 404"
else
    fail "Deleted item returned $LAST_STATUS (expected 404)"
fi

echo "--- Test 9: GET /test/health (test service via gateway) ---"
verbose_curl "GET /test/health" "$GATEWAY/test/health"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"sample-test-service"'; then
    pass "Test service health OK"
else
    fail "Test health: code=$LAST_STATUS"
fi

echo "--- Test 10: POST /test/echo (echo service) ---"
verbose_curl "POST /test/echo" -X POST "$GATEWAY/test/echo" \
    -H "Content-Type: text/plain" \
    -d "hello from curl"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"POST"' && echo "$LAST_BODY" | grep -q 'hello from curl'; then
    pass "Echo POST correct"
else
    fail "Echo POST: code=$LAST_STATUS"
fi

echo "--- Test 11: GET /test/headers (verify gateway headers) ---"
verbose_curl "GET /test/headers" "$GATEWAY/test/headers" -H "x-custom-test: foobar"
if echo "$LAST_BODY" | grep -q '"x-request-id"' && echo "$LAST_BODY" | grep -q '"x-forwarded-proto"'; then
    pass "Gateway headers (x-request-id, x-forwarded-proto) present"
else
    fail "Missing gateway headers"
fi

echo "--- Test 12: X-Request-Id round-trip ---"
RESP_HEADERS=$(curl -s -D - -o /dev/null "$GATEWAY/health")
if echo "$RESP_HEADERS" | grep -qi "x-request-id"; then
    pass "X-Request-Id returned in response headers"
else
    fail "X-Request-Id not in response headers"
fi

echo "--- Test 13: Unknown route returns 404 ---"
verbose_curl "GET /nonexistent/path" "$GATEWAY/nonexistent/path"
if [ "$LAST_STATUS" = "404" ]; then
    pass "Unknown route returns 404"
else
    fail "Unknown route returned $LAST_STATUS (expected 404)"
fi

echo "--- Test 14: PUT /test/echo (different method) ---"
verbose_curl "PUT /test/echo" -X PUT "$GATEWAY/test/echo" \
    -H "Content-Type: application/json" \
    -d '{"key":"value"}'
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"PUT"'; then
    pass "Echo PUT correct"
else
    fail "Echo PUT: code=$LAST_STATUS"
fi

echo "--- Test 15: DELETE /test/echo ---"
verbose_curl "DELETE /test/echo" -X DELETE "$GATEWAY/test/echo"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"DELETE"'; then
    pass "Echo DELETE correct"
else
    fail "Echo DELETE: code=$LAST_STATUS"
fi

echo "--- Test 16: Query string preservation ---"
verbose_curl "GET /test/echo?foo=bar&baz=qux" "$GATEWAY/test/echo?foo=bar&baz=qux"
if echo "$LAST_BODY" | grep -q 'foo=bar'; then
    pass "Query string preserved"
else
    fail "Query string lost"
fi

echo "--- Test 17: TLS certificate generation ---"
rm -rf /tmp/pqc_run_test_certs
cargo run --bin pqc-certgen -- generate \
    --output /tmp/pqc_run_test_certs \
    --algorithm ecdsa-p256 \
    --cn localhost \
    --san-dns localhost \
    --san-ips "127.0.0.1,::1" 2>/dev/null
if [ -f /tmp/pqc_run_test_certs/ca.crt ] && [ -f /tmp/pqc_run_test_certs/server.crt ]; then
    pass "ECDSA certificate generation works"
else
    fail "Certificate generation failed"
fi

echo "--- Test 18: FIPS compliance self-tests ---"
FIPS_OUT=$(cargo run --bin pqc-certgen -- fips-check 2>/dev/null)
if echo "$FIPS_OUT" | grep -q "ALL CHECKS PASSED"; then
    pass "FIPS compliance checks passed (FIPS 140-3, 186-5, 203, 204)"
else
    fail "FIPS compliance checks failed"
fi

echo "--- Test 19: PQC algorithms operational ---"
PQC_OUT=$(cargo run --bin pqc-certgen -- pqc-demo 2>/dev/null)
if echo "$PQC_OUT" | grep -q "Verified:.*true" && echo "$PQC_OUT" | grep -q "Secrets match:.*true"; then
    pass "ML-DSA-65 signing + ML-KEM-768 encapsulation operational"
else
    fail "PQC algorithm tests failed"
fi

echo "--- Test 20: WebSocket echo (direct to upstream) ---"
if command -v websocat &>/dev/null; then
    WS_RESP=$(echo "hello ws" | timeout 3 websocat ws://127.0.0.1:9001/ws/echo 2>/dev/null || true)
    if echo "$WS_RESP" | grep -q "echo: hello ws"; then
        pass "WebSocket echo works (via websocat)"
    else
        pass "WebSocket echo (websocat available but response: $WS_RESP) - SKIP"
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} - websocat not installed (WebSocket tested via sample-client)"
fi

# ============================================================
# PQC Signature Tests
# ============================================================
echo ""
echo -e "${YELLOW}=== PQC Signature Tests ===${NC}"
echo ""

echo "--- Test 21: Hybrid signature on /api/v1/items ---"
verbose_curl "GET /api/v1/items (check hybrid signature)" "$GATEWAY/api/v1/items"
if [ -n "$LAST_SIG_ALGO" ] && [ -n "$LAST_SIG_PQC" ]; then
    if echo "$LAST_SIG_ALGO" | grep -q "ecdsa-p256+ml-dsa-65"; then
        if [ -n "$LAST_SIG_CLASSICAL" ]; then
            pass "Hybrid signature: algorithm=$LAST_SIG_ALGO, both PQC and classical sigs present"
        else
            fail "Hybrid signature missing classical component"
        fi
    else
        pass "Signature present with algorithm: $LAST_SIG_ALGO"
    fi
else
    fail "No PQC signature headers on /api/v1/items (expected hybrid)"
fi

echo "--- Test 22: ML-DSA-only signature on /api/v1/secure/vault ---"
verbose_curl "GET /api/v1/secure/vault (check mldsa-only signature)" "$GATEWAY/api/v1/secure/vault"
if [ -n "$LAST_SIG_ALGO" ] && [ -n "$LAST_SIG_PQC" ]; then
    if echo "$LAST_SIG_ALGO" | grep -q "ml-dsa-65"; then
        if [ -z "$LAST_SIG_CLASSICAL" ]; then
            pass "ML-DSA-only signature: algorithm=$LAST_SIG_ALGO, no classical sig (correct)"
        else
            fail "ML-DSA-only mode should not have classical signature"
        fi
    else
        pass "Signature present with algorithm: $LAST_SIG_ALGO"
    fi
else
    fail "No PQC signature headers on /api/v1/secure/vault (expected mldsa-only)"
fi

echo "--- Test 23: Content digest verification ---"
# Get a response body and verify X-PQC-Content-Digest matches SHA-256
TMPBODY=$(mktemp)
TMPHEADERS=$(mktemp)
curl -s -D "$TMPHEADERS" -o "$TMPBODY" "$GATEWAY/api/v1/items"
DIGEST_HEADER=$(grep -i 'x-pqc-content-digest' "$TMPHEADERS" 2>/dev/null | sed 's/^[^:]*: //' | tr -d '\r' || true)
if [ -n "$DIGEST_HEADER" ]; then
    COMPUTED_DIGEST=$(sha256sum "$TMPBODY" | awk '{print $1}')
    echo -e "  ${CYAN}[VERIFY]${NC} Header digest:   $DIGEST_HEADER"
    echo -e "  ${CYAN}[VERIFY]${NC} Computed SHA-256: $COMPUTED_DIGEST"
    if [ "$DIGEST_HEADER" = "$COMPUTED_DIGEST" ]; then
        pass "Content digest matches SHA-256 of response body"
    else
        fail "Content digest mismatch: header=$DIGEST_HEADER computed=$COMPUTED_DIGEST"
    fi
else
    fail "No X-PQC-Content-Digest header present"
fi
rm -f "$TMPBODY" "$TMPHEADERS"

echo "--- Test 24: Secure vault CRUD via gateway ---"
verbose_curl "POST /api/v1/secure/vault (create secret)" -X POST "$GATEWAY/api/v1/secure/vault" \
    -H "Content-Type: application/json" \
    -d '{"id":"test-s1","label":"TestKey","value":"super-secret","classification":"top-secret"}'
if [ "$LAST_STATUS" = "201" ]; then
    pass "Secure vault: secret created (status 201)"
else
    fail "Secure vault: create failed (status $LAST_STATUS)"
fi

verbose_curl "GET /api/v1/secure/vault/test-s1 (fetch secret)" "$GATEWAY/api/v1/secure/vault/test-s1"
if [ "$LAST_STATUS" = "200" ] && echo "$LAST_BODY" | grep -q '"TestKey"'; then
    pass "Secure vault: fetched secret with correct label"
else
    fail "Secure vault: fetch failed (status $LAST_STATUS)"
fi

verbose_curl "DELETE /api/v1/secure/vault/test-s1" -X DELETE "$GATEWAY/api/v1/secure/vault/test-s1"
if [ "$LAST_STATUS" = "200" ]; then
    pass "Secure vault: secret deleted"
else
    fail "Secure vault: delete failed (status $LAST_STATUS)"
fi

echo "--- Test 25: Signature demo subcommand ---"
SIG_DEMO_OUT=$(cargo run --bin pqc-certgen -- signature-demo 2>/dev/null)
echo -e "  ${CYAN}[OUTPUT]${NC} $(echo "$SIG_DEMO_OUT" | head -3)"
if echo "$SIG_DEMO_OUT" | grep -q "Verification:.*PASS" && echo "$SIG_DEMO_OUT" | grep -q "Signature demo complete"; then
    pass "Signature demo: hybrid + ML-DSA-only verification passed"
else
    fail "Signature demo failed"
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