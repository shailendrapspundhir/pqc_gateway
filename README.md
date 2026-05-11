# PQC Gateway

A Post-Quantum Cryptography enabled API Gateway written in Rust.

See [DESIGN.md](DESIGN.md) for the full phased design document.

## Prerequisites

Run the installer script to set up all dependencies (gcc, libc-dev, pkg-config, OpenSSL headers, Rust):

```bash
chmod +x prerequisites.sh
./prerequisites.sh
```

Requires `sudo` for system package installation. Supports Ubuntu/Debian, Fedora/RHEL, Arch, and macOS.

## Quick Start (Phase 1 — Core Gateway)

### Build

```bash
cargo build --workspace
```

### Run

Start the upstream services, then the gateway:

```bash
# Terminal 1: API service (port 9001)
cargo run --bin sample-api-service

# Terminal 2: Test service (port 9002)
cargo run --bin sample-test-service

# Terminal 3: Gateway (port 8080)
cargo run --bin pqc-gateway -- --config config/gateway.toml
```

### Test

```bash
# Unit tests
cargo test --workspace

# End-to-end bash tests (starts/stops all services automatically)
bash tests/scripts/run_tests.sh

# Rust sample client (requires services to be running)
cargo run --bin sample-client
```

### Configuration

Edit `config/gateway.toml` to add routes:

```toml
[[routes]]
id = "my-service"
path_prefix = "/api/myservice"
upstream = "http://127.0.0.1:3000"
methods = ["GET", "POST"]
timeout_ms = 10000
```

## Project Structure

```
crates/
  pqc-gateway/        # Main gateway binary
  pqc-proxy/          # Core proxy library (routing, middleware, forwarding)
  sample-api-service/ # Example CRUD + WebSocket service
  sample-test-service/ # Example echo/health service
  sample-client/      # Test client that exercises the gateway
config/
  gateway.toml        # Gateway configuration
tests/scripts/
  run_tests.sh        # End-to-end test suite
```
