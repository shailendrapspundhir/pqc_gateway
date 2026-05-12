# PQC Gateway

A Post-Quantum Cryptography enabled API Gateway written in Rust, featuring TLS 1.3 with hybrid PQC key exchange (X25519 + ML-KEM-768) and FIPS 203/204 compliance.

See [DESIGN.md](DESIGN.md) for the full phased design document.

## Features

- **TLS 1.3** with rustls (pure Rust, no OpenSSL dependency)
- **PQC Hybrid Key Exchange**: X25519MLKEM768 (X25519 + ML-KEM-768) for quantum-safe handshakes
- **FIPS Compliance**: FIPS 140-3 (aws-lc-rs), FIPS 186-5 (ECDSA), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
- **Certificate Generation**: CA + server certs with ECDSA P-256 or Ed25519
- **PQC Primitives**: ML-DSA-65 signing/verification, ML-KEM-768 encapsulation/decapsulation (pure Rust)
- **Reverse Proxy**: Path-based routing, header injection, request-id tracking
- **Runtime FIPS Self-Tests**: Cryptographic validation at startup

## Prerequisites

```bash
chmod +x prerequisites.sh
./prerequisites.sh
```

Requires cmake for the aws-lc-rs FIPS-validated crypto provider.

## Quick Start

### Build

```bash
cargo build --workspace
```

### Generate TLS Certificates

```bash
# Generate CA + server certificate (ECDSA P-256)
cargo run --bin pqc-certgen -- generate --output config/certs

# Or self-signed for quick testing
cargo run --bin pqc-certgen -- self-signed --output config/certs

# Or with Ed25519
cargo run --bin pqc-certgen -- generate --output config/certs --algorithm ed25519
```

### Run (Plain HTTP)

```bash
cargo run --bin sample-api-service &   # Port 9001
cargo run --bin sample-test-service &  # Port 9002
cargo run --bin pqc-gateway -- --config config/gateway.toml  # Port 8090
```

### Run (HTTPS with TLS 1.3 + PQC)

```bash
cargo run --bin sample-api-service &   # Port 9001
cargo run --bin sample-test-service &  # Port 9002
cargo run --bin pqc-gateway -- --config config/gateway-tls.toml  # Port 8443
```

### Verify PQC & FIPS

```bash
# Run FIPS compliance self-tests
cargo run --bin pqc-certgen -- fips-check

# Run PQC algorithm demo (ML-DSA-65 + ML-KEM-768)
cargo run --bin pqc-certgen -- pqc-demo
```

### Test

```bash
# Unit tests (15 tests: pqc-tls + pqc-proxy)
cargo test --workspace

# Plain HTTP end-to-end tests (19 tests)
bash tests/scripts/run_tests.sh

# TLS 1.3 + PQC end-to-end tests (23 tests)
bash tests/scripts/test_tls_pqc.sh
```

### TLS Configuration

Edit `config/gateway-tls.toml`:

```toml
[tls]
enabled = true
cert_file = "config/certs/server.crt"
key_file = "config/certs/server.key"
min_version = "1.3"
pqc_enabled = true    # Enable X25519MLKEM768 hybrid key exchange
https_port = 8443
```

## Project Structure

```
crates/
  pqc-gateway/         # Main gateway binary (HTTP + HTTPS server)
  pqc-proxy/           # Core proxy library (routing, middleware, forwarding)
  pqc-tls/             # TLS 1.3 + PQC library
    src/
      provider.rs      #   CryptoProvider with X25519MLKEM768 key exchange
      certs.rs         #   PEM certificate/key loading
      certgen.rs       #   Certificate generation + PQC primitives (ML-DSA, ML-KEM)
      config.rs        #   TLS configuration types
      fips.rs          #   FIPS 203/204 compliance validation
  pqc-certgen/         # Certificate generation CLI tool
  sample-api-service/  # Example CRUD + WebSocket service
  sample-test-service/ # Example echo/health service
  sample-client/       # Test client (HTTP + HTTPS)
config/
  gateway.toml         # Plain HTTP configuration
  gateway-tls.toml     # TLS 1.3 + PQC configuration
  certs/               # Generated certificates
tests/scripts/
  run_tests.sh         # Plain HTTP E2E test suite
  test_tls_pqc.sh      # TLS + PQC E2E test suite
```
