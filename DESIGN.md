# PQC Gateway — Design Document

A Post-Quantum Cryptography (PQC) enabled API Gateway written in Rust, with TLS 1.3
fallback, JWT authentication, RBAC, user auth, DPoP, QUIC (HTTP/3), and WebSocket support.

---

## Table of Contents

1. [Vision & Goals](#1-vision--goals)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Project Structure](#4-project-structure)
5. [Phase-Wise Implementation Plan](#5-phase-wise-implementation-plan)
   - [Phase 1 — Core Gateway Foundation](#phase-1--core-gateway-foundation)
   - [Phase 2 — TLS 1.3 + PQC Hybrid Handshake](#phase-2--tls-13--pqc-hybrid-handshake)
   - [Phase 3 — JWT Authentication & User Auth](#phase-3--jwt-authentication--user-auth)
   - [Phase 4 — RBAC (Role-Based Access Control)](#phase-4--rbac-role-based-access-control)
   - [Phase 5 — DPoP (Demonstrating Proof of Possession)](#phase-5--dpop-demonstrating-proof-of-possession)
   - [Phase 6 — QUIC / HTTP/3 (UDP Transport)](#phase-6--quic--http3-udp-transport)
   - [Phase 7 — WebSocket Support](#phase-7--websocket-support)
   - [Phase 8 — Observability & Production Hardening](#phase-8--observability--production-hardening)
6. [Security Considerations](#6-security-considerations)
7. [Testing Strategy](#7-testing-strategy)
8. [Performance Targets](#8-performance-targets)
9. [Future Roadmap](#9-future-roadmap)

---

## 1. Vision & Goals

Modern API gateways must prepare for the post-quantum era. The "harvest now, decrypt
later" threat means that data encrypted today with classical algorithms (RSA, ECDH) can
be stored and decrypted once cryptographically relevant quantum computers arrive. NIST
finalized the first PQC standards (FIPS 203, 204, 205) in August 2024, and federal
migration timelines target deprecation of quantum-vulnerable algorithms by 2030-2035.

**This gateway aims to be:**

- **Quantum-resistant by default** — PQC hybrid key exchange (X25519 + ML-KEM-768) and
  PQC signatures (ML-DSA) for TLS, with graceful fallback to classical TLS 1.3.
- **Full-featured auth** — JWT validation/issuance, user registration/login, role-based
  access control, and DPoP token binding.
- **Multi-protocol** — HTTP/1.1, HTTP/2, HTTP/3 (QUIC over UDP), and WebSocket.
- **Production-grade** — Structured logging, metrics, tracing, rate limiting, circuit
  breaking, health checks, graceful shutdown.
- **Configurable** — TOML/YAML configuration for routes, upstreams, TLS, auth policies,
  and RBAC rules. Hot-reload without downtime.

**Non-goals (for now):**

- Full service mesh / sidecar proxy (focus is on edge gateway).
- GraphQL-specific features.
- Built-in API versioning or transformation engine.

---

## 2. High-Level Architecture

```
                         Clients
                           │
            ┌──────────────┼──────────────┐
            │              │              │
        HTTP/1.1        HTTP/3         WebSocket
        HTTP/2        (QUIC/UDP)
        (TCP)              │              │
            │              │              │
            ▼              ▼              ▼
    ┌─────────────────────────────────────────┐
    │            TLS Termination              │
    │   ┌─────────────────────────────────┐   │
    │   │  PQC Hybrid (X25519+ML-KEM-768) │   │
    │   │  Fallback: Classical TLS 1.3    │   │
    │   └─────────────────────────────────┘   │
    ├─────────────────────────────────────────┤
    │           Middleware Pipeline            │
    │  ┌─────┐ ┌─────┐ ┌──────┐ ┌─────────┐  │
    │  │Trace│→│Rate │→│ Auth │→│  RBAC   │  │
    │  │     │ │Limit│ │(JWT) │ │         │  │
    │  └─────┘ └─────┘ └──────┘ └─────────┘  │
    │  ┌──────┐ ┌────────┐ ┌──────────────┐  │
    │  │ DPoP │→│ Timeout│→│ Compression  │  │
    │  └──────┘ └────────┘ └──────────────┘  │
    ├─────────────────────────────────────────┤
    │             Router / Proxy              │
    │  Path-based routing, load balancing,    │
    │  header rewriting, upstream forwarding  │
    ├─────────────────────────────────────────┤
    │         Upstream Connections             │
    │   (HTTP client w/ connection pooling)    │
    └──────┬──────────┬──────────┬────────────┘
           │          │          │
       Service A  Service B  Service C
```

The gateway is a single binary with the following logical layers:

| Layer               | Responsibility                                          |
|---------------------|---------------------------------------------------------|
| **Listener**        | Accepts TCP (HTTP/1.1, HTTP/2) and UDP (QUIC/HTTP/3)   |
| **TLS Termination** | PQC hybrid handshake with classical fallback            |
| **Middleware**       | Tower-based pipeline: tracing, auth, RBAC, DPoP, etc.  |
| **Router**          | Path/host-based routing to upstream services            |
| **Proxy**           | Forwards requests, manages upstream connection pools    |
| **WebSocket**       | Upgrade handling, bidirectional frame forwarding        |
| **Auth Engine**     | JWT issuance/validation, user store, RBAC evaluation    |
| **Config**          | TOML config loading, hot-reload via file watch or API   |
| **Observability**   | Prometheus metrics, structured tracing, health endpoint |

---

## 3. Technology Stack

### Core Framework

| Component          | Crate / Technology         | Rationale                                   |
|--------------------|----------------------------|---------------------------------------------|
| Async Runtime      | `tokio`                    | Industry standard, required by most crates  |
| HTTP Framework     | `axum` + `tower` + `hyper` | Best middleware composability via Tower      |
| Configuration      | `config` + `serde`         | Multi-format config (TOML, YAML, env vars)  |
| CLI                | `clap`                     | Argument parsing, subcommands               |
| Logging / Tracing  | `tracing` + `tracing-subscriber` | Structured, span-based observability  |

### Cryptography & TLS

| Component                | Crate / Technology              | Rationale                                  |
|--------------------------|---------------------------------|--------------------------------------------|
| TLS (classical)          | `rustls` + `ring`               | Pure Rust, high performance, no OpenSSL    |
| PQC Key Exchange         | `rustls-post-quantum`           | Hybrid X25519+ML-KEM-768 CryptoProvider    |
| PQC Primitives (KEM)     | `ml-kem` (RustCrypto)           | Pure Rust, FIPS 203, no_std, NIST vectors  |
| PQC Primitives (Sigs)    | `ml-dsa` (RustCrypto)           | Pure Rust, FIPS 204, NIST vectors          |
| Classical Fallback       | `ring` / `aws-lc-rs`           | ECDH (X25519), Ed25519, RSA               |
| Certificate Handling     | `rustls-pemfile`, `rcgen`       | PEM parsing, self-signed cert generation   |
| Password Hashing         | `argon2`                        | Argon2id — memory-hard, recommended        |

### Authentication & Authorization

| Component        | Crate / Technology     | Rationale                                      |
|------------------|------------------------|-------------------------------------------------|
| JWT              | `jsonwebtoken`         | Mature, supports RS256/ES256/EdDSA, custom claims |
| DPoP             | Custom (RFC 9449)      | Built on `jsonwebtoken` + `ring`/`ml-dsa`       |
| Password Hashing | `argon2`               | Argon2id for user credential storage            |
| RBAC             | Custom engine          | Policy file driven, path + method + role matching |
| Session/Token    | `uuid` + `chrono`      | Token IDs, expiration management                |

### Networking & Protocols

| Component        | Crate / Technology         | Rationale                                    |
|------------------|----------------------------|----------------------------------------------|
| HTTP/1.1 + HTTP/2| `hyper` (via `axum`)       | Built-in with axum                           |
| QUIC / HTTP/3    | `quinn` + `h3` + `h3-quinn`| Pure Rust, mature, excellent async API      |
| WebSocket        | `axum` built-in + `tokio-tungstenite` | Native upgrade support in axum  |
| Upstream Client  | `hyper-util` / `reqwest`   | Connection pooling, TLS to upstreams         |

### Storage & State

| Component        | Crate / Technology       | Rationale                                      |
|------------------|--------------------------|-------------------------------------------------|
| User Store       | `sqlx` + SQLite/Postgres | Async, compile-time query checks               |
| Rate Limit State | `dashmap` / `moka`       | Concurrent in-memory caches                    |
| RBAC Policy      | TOML files               | Simple, version-controllable, hot-reloadable   |
| Session Store    | In-memory / Redis        | Token revocation, DPoP nonce tracking          |

### Observability

| Component  | Crate / Technology                  | Rationale                          |
|------------|-------------------------------------|------------------------------------|
| Metrics    | `metrics` + `metrics-exporter-prometheus` | Prometheus-compatible export |
| Tracing    | `tracing` + `tracing-opentelemetry` | Distributed tracing support       |
| Health     | Custom `/health` endpoint           | Liveness + readiness probes       |

---

## 4. Project Structure

```
pqc_gateway/
├── Cargo.toml                  # Workspace root
├── Cargo.lock
├── DESIGN.md                   # This file
├── README.md
├── config/
│   ├── gateway.toml            # Main gateway configuration
│   ├── routes.toml             # Route definitions
│   ├── rbac.toml               # RBAC policies
│   └── certs/                  # TLS certificates
│       ├── server.crt
│       ├── server.key
│       └── ca.crt
├── crates/
│   ├── pqc-gateway/            # Main binary crate
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs         # Entry point, CLI, server startup
│   │       ├── config.rs       # Configuration loading & validation
│   │       ├── server.rs       # Listener setup (TCP + QUIC)
│   │       └── error.rs        # Gateway-wide error types
│   ├── pqc-tls/                # TLS termination library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── hybrid.rs       # PQC hybrid handshake config
│   │       ├── fallback.rs     # Classical TLS 1.3 fallback
│   │       └── certs.rs        # Certificate loading & rotation
│   ├── pqc-auth/               # Authentication library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── jwt.rs          # JWT issuance & validation
│   │       ├── user.rs         # User registration, login, storage
│   │       ├── password.rs     # Argon2id hashing & verification
│   │       ├── dpop.rs         # DPoP proof creation & validation
│   │       └── middleware.rs   # Tower auth middleware
│   ├── pqc-rbac/               # RBAC engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── policy.rs       # Policy parsing & evaluation
│   │       ├── roles.rs        # Role definitions & hierarchy
│   │       └── middleware.rs   # Tower RBAC middleware
│   ├── pqc-proxy/              # Reverse proxy & routing
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── router.rs       # Path/host-based route matching
│   │       ├── upstream.rs     # Upstream connection management
│   │       ├── lb.rs           # Load balancing strategies
│   │       └── websocket.rs    # WebSocket upgrade & forwarding
│   └── pqc-quic/               # QUIC/HTTP/3 listener
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── listener.rs     # Quinn-based QUIC listener
│           └── h3_handler.rs   # HTTP/3 request handling
├── tests/
│   ├── integration/            # End-to-end integration tests
│   ├── tls/                    # TLS handshake tests (PQC + fallback)
│   └── auth/                   # Auth flow tests
├── benches/                    # Criterion benchmarks
└── docker/
    ├── Dockerfile
    └── docker-compose.yml
```

This workspace structure keeps concerns separated while allowing shared types and tight
integration. Each crate can be tested and benchmarked independently.

---

## 5. Phase-Wise Implementation Plan

---

### Phase 1 — Core Gateway Foundation

**Goal:** A working reverse proxy that accepts HTTP/1.1 and HTTP/2 connections over
plain TCP, routes requests to upstream services based on path/host rules, and returns
responses. No TLS, no auth — just the skeleton.

**Duration estimate:** 2-3 weeks

#### 1.1 Project Scaffolding

- Initialize Cargo workspace with the crate layout above.
- Set up `clap` CLI: `pqc-gateway --config ./config/gateway.toml`.
- Set up `tracing-subscriber` with JSON + pretty-print output.
- Define `gateway.toml` schema:

```toml
[server]
bind_address = "0.0.0.0"
http_port = 8080

[logging]
level = "info"        # trace, debug, info, warn, error
format = "pretty"     # pretty | json
```

#### 1.2 HTTP Listener (TCP)

- Use `axum::serve` with `hyper` on a `tokio::net::TcpListener`.
- Support HTTP/1.1 and HTTP/2 (h2c — cleartext for now).
- Implement graceful shutdown via `tokio::signal` (SIGTERM, SIGINT).
- Health endpoint: `GET /health` → `200 OK { "status": "healthy" }`.

#### 1.3 Route Configuration & Matching

- Define `routes.toml`:

```toml
[[routes]]
path_prefix = "/api/v1/users"
upstream = "http://127.0.0.1:9001"
strip_prefix = true
methods = ["GET", "POST", "PUT", "DELETE"]

[[routes]]
path_prefix = "/api/v1/orders"
upstream = "http://127.0.0.1:9002"
strip_prefix = true
```

- Build a `Router` that matches incoming requests to configured routes.
- Support path-prefix matching, exact matching, and wildcard catch-all.
- Unmatched routes return `404 Not Found`.

#### 1.4 Reverse Proxy (Upstream Forwarding)

- Forward matched requests to upstream using `hyper-util` HTTP client.
- Preserve original headers; add `X-Forwarded-For`, `X-Forwarded-Proto`,
  `X-Request-Id` headers.
- Connection pooling to upstreams (reuse TCP connections).
- Configurable timeouts per route:

```toml
[[routes]]
path_prefix = "/api/v1/slow"
upstream = "http://127.0.0.1:9003"
timeout_ms = 30000
```

#### 1.5 Tower Middleware Foundation

- Set up `tower::ServiceBuilder` pipeline:
  1. `TraceLayer` — request/response logging with span context.
  2. `TimeoutLayer` — global default timeout (configurable).
  3. `RequestIdLayer` — generate UUID per request.
- Demonstrate middleware ordering and selective application.

#### Deliverables

- [ ] Cargo workspace compiles and runs.
- [ ] Requests to configured paths are proxied to upstreams.
- [ ] Unmatched paths return 404.
- [ ] Structured request/response logs with request IDs.
- [ ] Graceful shutdown on SIGTERM.
- [ ] Integration test: start gateway + mock upstream, send request, verify response.

---

### Phase 2 — TLS 1.3 + PQC Hybrid Handshake

**Goal:** TLS termination with a PQC hybrid key exchange (X25519 + ML-KEM-768) as the
preferred cipher, falling back to classical TLS 1.3 (X25519 ECDHE) for clients that
don't support PQC. PQC signature support (ML-DSA) for server certificates where possible.

**Duration estimate:** 2-3 weeks

#### 2.1 Classical TLS 1.3 Baseline

- Integrate `rustls` with `axum-server` (or `tokio-rustls`).
- Load server certificate and private key from PEM files.
- Configure TLS 1.3-only (disable TLS 1.2 and below).
- Verify with `openssl s_client` and `curl --tlsv1.3`.

```toml
[tls]
enabled = true
cert_file = "config/certs/server.crt"
key_file = "config/certs/server.key"
min_version = "1.3"
```

#### 2.2 PQC Hybrid Key Exchange

- Use `rustls-post-quantum` to provide a `CryptoProvider` that supports
  **X25519MLKEM768** (hybrid classical + PQC key encapsulation).
- This is the key exchange used during the TLS handshake — it protects the session
  key agreement against quantum attacks.
- Algorithm details:
  - **ML-KEM-768** (FIPS 203): Lattice-based KEM, ~AES-192 equivalent security.
  - **X25519**: Classical ECDH, provides security even if ML-KEM is broken.
  - Combined: Hybrid ensures security under both classical and quantum threat models.

- Configure `rustls::ServerConfig` with the PQC crypto provider:

```rust
use rustls_post_quantum::X25519MLKEM768;

let crypto_provider = rustls::crypto::CryptoProvider {
    kx_groups: vec![X25519MLKEM768, rustls::crypto::ring::kx_group::X25519],
    ..rustls::crypto::ring::default_provider()
};

let tls_config = ServerConfig::builder_with_provider(Arc::new(crypto_provider))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
```

#### 2.3 Graceful Fallback

- The `kx_groups` list is ordered by preference: PQC hybrid first, classical second.
- Clients that support `X25519MLKEM768` (e.g., Chrome 131+, BoringSSL, recent curl)
  will negotiate PQC. Others will fall back to X25519.
- No application-level logic needed — `rustls` handles negotiation automatically.
- Log which key exchange was negotiated for each connection (via `rustls` connection info).

#### 2.4 PQC Signatures (Experimental / Forward-Looking)

- Classical certificates (ECDSA P-256 / Ed25519) remain the baseline for server identity.
- Investigate ML-DSA-65 (FIPS 204) for server certificate signatures:
  - Requires a CA that issues PQC certificates (or self-signed for testing).
  - Use `rcgen` with ML-DSA to generate test certificates.
  - Larger signature sizes (~2.4 KB for ML-DSA-65 vs ~64 bytes for Ed25519).
- **Hybrid certificate approach**: Dual certificates — serve classical cert by default,
  PQC cert to clients that advertise support (via signature_algorithms extension).
- Mark as experimental; classical signatures are sufficient for now since the quantum
  threat to signatures requires real-time quantum computation (not harvest-now attacks).

#### 2.5 Certificate Rotation

- Watch certificate files for changes (via `notify` crate or periodic polling).
- Reload `rustls::ServerConfig` without restarting the gateway.
- Log certificate expiry warnings.

#### Deliverables

- [ ] TLS 1.3 handshake works with classical clients.
- [ ] PQC-capable clients negotiate X25519MLKEM768.
- [ ] Non-PQC clients fall back to X25519 seamlessly.
- [ ] Connection logs show negotiated key exchange algorithm.
- [ ] Certificate hot-reload without downtime.
- [ ] Test: handshake with `curl` (classical) and a PQC-enabled client.
- [ ] Benchmark: handshake latency comparison (PQC hybrid vs classical).

---

### Phase 3 — JWT Authentication & User Auth

**Goal:** The gateway can authenticate users via JWT tokens. It supports both validating
externally issued JWTs and issuing its own tokens via a built-in user registration and
login flow. Tokens use PQC-safe algorithms where supported.

**Duration estimate:** 2-3 weeks

#### 3.1 JWT Validation Middleware

- Tower middleware that extracts `Authorization: Bearer <token>` header.
- Validates JWT signature, expiration (`exp`), not-before (`nbf`), issuer (`iss`),
  audience (`aud`).
- Supported algorithms: `ES256` (P-256), `EdDSA` (Ed25519), `RS256`.
- On success: injects decoded claims into request extensions.
- On failure: returns `401 Unauthorized` with error detail.

```toml
[auth.jwt]
enabled = true
issuer = "pqc-gateway"
audience = "pqc-gateway-api"
secret_or_key_file = "config/certs/jwt-public.pem"
algorithms = ["ES256", "EdDSA"]
clock_skew_seconds = 30
```

- Routes can opt-in or opt-out of JWT validation:

```toml
[[routes]]
path_prefix = "/api/v1/users"
upstream = "http://127.0.0.1:9001"
auth_required = true

[[routes]]
path_prefix = "/public"
upstream = "http://127.0.0.1:9002"
auth_required = false
```

#### 3.2 User Registration & Login

- Built-in auth endpoints (not proxied — handled by the gateway itself):
  - `POST /auth/register` — Create user account.
  - `POST /auth/login` — Authenticate and receive JWT.
  - `POST /auth/refresh` — Refresh an expiring token.
  - `POST /auth/logout` — Revoke refresh token.

- User model:

```rust
struct User {
    id: Uuid,
    username: String,
    email: String,
    password_hash: String,    // Argon2id
    roles: Vec<String>,       // ["admin", "user"]
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    active: bool,
}
```

- Database: SQLite for development, PostgreSQL for production (via `sqlx`).
- Password hashing: Argon2id with recommended parameters:
  - Memory: 64 MB, Iterations: 3, Parallelism: 4.

#### 3.3 JWT Issuance

- On successful login, issue:
  - **Access token** (short-lived, 15 min): Contains user ID, roles, standard claims.
  - **Refresh token** (long-lived, 7 days): Opaque or JWT, stored server-side for
    revocation.

- JWT payload:

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "pqc-gateway",
  "aud": "pqc-gateway-api",
  "exp": 1700000000,
  "iat": 1699999100,
  "roles": ["user", "editor"],
  "jti": "unique-token-id"
}
```

- Signing key: ES256 (P-256) as default. Support Ed25519.
- **PQC JWT signing (future)**: When `jsonwebtoken` or a successor supports ML-DSA,
  switch to ML-DSA-44 for JWT signatures. For now, use classical algorithms — JWTs are
  short-lived so the quantum harvest-now threat is minimal.

#### 3.4 Token Revocation

- Maintain a revocation list (in-memory `DashMap` or Redis).
- On logout, add the token's `jti` to the revocation list.
- Middleware checks revocation list during validation.
- Expired entries are periodically purged.

#### Deliverables

- [ ] JWT middleware validates tokens on protected routes.
- [ ] Unprotected routes pass through without auth.
- [ ] User registration with unique username/email enforcement.
- [ ] Login returns access + refresh tokens.
- [ ] Refresh flow issues new access token.
- [ ] Logout revokes refresh token.
- [ ] Invalid/expired tokens return 401 with clear error messages.
- [ ] Integration test: register → login → access protected route → refresh → logout.

---

### Phase 4 — RBAC (Role-Based Access Control)

**Goal:** Fine-grained access control based on user roles. Each route + HTTP method
combination can require specific roles. Supports role hierarchy and deny rules.

**Duration estimate:** 1-2 weeks

#### 4.1 RBAC Policy Definition

- Policies defined in `rbac.toml`:

```toml
[roles]
# Role hierarchy: admin inherits all permissions of editor and user
admin = { inherits = ["editor"] }
editor = { inherits = ["user"] }
user = { inherits = [] }
viewer = { inherits = [] }

[[policies]]
path = "/api/v1/users"
method = "GET"
allow_roles = ["user"]           # user, editor, admin (via inheritance)

[[policies]]
path = "/api/v1/users"
method = "POST"
allow_roles = ["admin"]

[[policies]]
path = "/api/v1/users/*"
method = "DELETE"
allow_roles = ["admin"]

[[policies]]
path = "/api/v1/articles"
method = "POST"
allow_roles = ["editor"]

[[policies]]
path = "/admin/**"
deny_roles = ["viewer"]
allow_roles = ["admin"]
```

#### 4.2 RBAC Evaluation Engine

- Role hierarchy resolution: if user has `admin`, they inherit `editor` and `user`
  permissions transitively.
- Matching order: most specific path first, then method match.
- Deny rules take precedence over allow rules.
- Default policy: configurable (`deny` or `allow` when no policy matches).

```rust
pub struct RbacEngine {
    policies: Vec<Policy>,
    role_hierarchy: HashMap<String, HashSet<String>>,
    default_action: Action, // Deny or Allow
}

impl RbacEngine {
    pub fn evaluate(&self, user_roles: &[String], path: &str, method: &str) -> Action;
}
```

#### 4.3 RBAC Middleware

- Tower middleware that runs after JWT middleware (needs claims in request extensions).
- Extracts roles from JWT claims.
- Evaluates against the RBAC engine.
- Returns `403 Forbidden` if denied.

#### 4.4 Policy Hot-Reload

- Watch `rbac.toml` for changes.
- Rebuild `RbacEngine` and swap via `Arc<ArcSwap<RbacEngine>>` for lock-free reads.
- Log policy reload events.

#### Deliverables

- [ ] RBAC policies loaded from TOML.
- [ ] Role hierarchy works (admin inherits editor inherits user).
- [ ] Path glob matching (wildcards, `**` for deep match).
- [ ] Deny-before-allow evaluation.
- [ ] 403 returned for unauthorized role + path + method combos.
- [ ] Policy hot-reload without restart.
- [ ] Unit tests for policy evaluation edge cases.

---

### Phase 5 — DPoP (Demonstrating Proof of Possession)

**Goal:** Implement RFC 9449 DPoP to cryptographically bind access tokens to a
client-held key pair, preventing token theft and replay. Extend with PQC signature
algorithms.

**Duration estimate:** 2 weeks

#### 5.1 DPoP Overview (RFC 9449)

DPoP prevents stolen tokens from being replayed by a different client. The flow:

1. Client generates an asymmetric key pair (persisted per device).
2. On token request, client sends a `DPoP` header containing a signed JWT proof:
   - `typ: "dpop+jwt"`
   - `jwk`: Client's public key.
   - `jti`: Unique proof ID.
   - `htm`: HTTP method (e.g., `POST`).
   - `htu`: Target URI (e.g., `https://gateway.example.com/auth/token`).
   - `iat`: Issued-at timestamp.
   - `nonce`: Server-provided nonce (if required).
3. Server validates the proof and issues a token with `cnf.jkt` (JWK thumbprint of the
   client's public key).
4. On resource requests, client sends both `Authorization: DPoP <token>` and a new
   `DPoP` proof. The `ath` claim in the proof is a hash of the access token.
5. Resource server validates that the proof's key matches the token's `cnf.jkt`.

#### 5.2 DPoP Proof Validation

- Parse `DPoP` header as a JWT.
- Verify the signature using the embedded `jwk` public key.
- Validate claims:
  - `typ` == `"dpop+jwt"`
  - `htm` matches the request method.
  - `htu` matches the request URI (after normalization).
  - `iat` is within acceptable clock skew (configurable, default 60s).
  - `jti` has not been seen before (replay protection).
  - `ath` (if present) == base64url(SHA-256(access_token)).
  - `nonce` matches the server-issued nonce (if nonce policy is active).
- Supported algorithms: `ES256`, `EdDSA`. Future: ML-DSA-44 for PQC DPoP proofs.

#### 5.3 DPoP Token Binding

- Modify the JWT issuance (Phase 3) to include `cnf` claim:

```json
{
  "sub": "user-uuid",
  "cnf": {
    "jkt": "base64url-sha256-thumbprint-of-client-public-key"
  }
}
```

- The `jkt` is computed per RFC 7638 (JWK Thumbprint).

#### 5.4 DPoP Nonce Management

- Server can require nonces to prevent pre-generated proofs:
  - Return `DPoP-Nonce` header in responses.
  - Reject proofs without a valid nonce (error: `use_dpop_nonce`).
  - Client must retry with the provided nonce.
- Nonce storage: in-memory `moka` cache with TTL (default 5 min).

#### 5.5 DPoP Middleware

- Tower middleware (runs after JWT middleware):
  1. Check if the `Authorization` scheme is `DPoP`.
  2. Extract and validate the `DPoP` header proof.
  3. Verify `cnf.jkt` in the token matches the proof's public key.
  4. On failure: `401` with `error="invalid_dpop_proof"`.

```toml
[auth.dpop]
enabled = true
require_nonce = true
nonce_ttl_seconds = 300
proof_max_age_seconds = 60
replay_cache_size = 100000
```

#### 5.6 PQC DPoP (Forward-Looking)

- When ML-DSA support is available in JWT libraries, allow clients to sign DPoP proofs
  with ML-DSA-44 (smallest parameter set, sufficient for short-lived proofs).
- Server advertises supported DPoP algorithms via a discovery endpoint or header.
- Hybrid approach: accept both classical (ES256) and PQC (ML-DSA) proofs during
  transition.

#### Deliverables

- [ ] DPoP proof validation (signature, claims, replay, nonce).
- [ ] Token issuance with `cnf.jkt` binding.
- [ ] DPoP middleware rejects stolen tokens used from different key.
- [ ] Nonce management with `DPoP-Nonce` header flow.
- [ ] Replay detection via `jti` cache.
- [ ] Integration test: full DPoP flow (generate key → get token → use token).
- [ ] Error responses match RFC 9449 (error codes, `DPoP-Nonce` header).

---

### Phase 6 — QUIC / HTTP/3 (UDP Transport)

**Goal:** Accept HTTP/3 connections over QUIC (UDP), running alongside the existing
TCP listeners. QUIC provides better performance on lossy networks, faster connection
establishment (0-RTT), and built-in multiplexing without head-of-line blocking.

**Duration estimate:** 2-3 weeks

#### 6.1 QUIC Listener with Quinn

- Add `quinn` + `h3` + `h3-quinn` crates.
- Create a QUIC endpoint bound to a UDP socket, using the same TLS config as TCP
  (with PQC hybrid key exchange).
- Accept incoming QUIC connections in a separate Tokio task.

```toml
[server]
bind_address = "0.0.0.0"
http_port = 8080          # TCP (HTTP/1.1 + HTTP/2)
h3_port = 8443            # UDP (QUIC / HTTP/3)
```

- Quinn uses `rustls` natively, so the PQC `CryptoProvider` from Phase 2 works directly.

#### 6.2 HTTP/3 Request Handling

- Use the `h3` crate to accept HTTP/3 requests from the QUIC connection.
- Convert `h3::server::Request` into a format compatible with the existing middleware
  pipeline.
- The core approach: convert HTTP/3 requests to `http::Request<Body>`, run them through
  the same Tower middleware stack and router, then convert responses back to HTTP/3.

```rust
// Pseudo-code for HTTP/3 handler
async fn handle_h3_connection(conn: quinn::Connection, app: Router) {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;
    while let Some((req, stream)) = h3_conn.accept().await? {
        let http_req = convert_h3_to_http(req);
        let response = app.call(http_req).await;
        send_h3_response(stream, response).await;
    }
}
```

#### 6.3 Shared Middleware Pipeline

- The same Tower middleware stack (tracing, auth, RBAC, DPoP, timeout) handles both
  TCP and QUIC requests.
- The router and proxy logic is transport-agnostic.
- Add a `X-Forwarded-Proto: h3` header for HTTP/3 requests so upstreams can
  differentiate.

#### 6.4 Alt-Svc Header for HTTP/3 Discovery

- TCP (HTTP/2) responses include `Alt-Svc` header to advertise HTTP/3 availability:

```
Alt-Svc: h3=":8443"; ma=3600
```

- Clients that support HTTP/3 (modern browsers, curl with HTTP/3) will upgrade
  automatically on subsequent requests.

#### 6.5 QUIC Transport Configuration

```toml
[quic]
max_idle_timeout_ms = 30000
max_concurrent_bidi_streams = 100
max_concurrent_uni_streams = 100
initial_window_size = 1048576       # 1 MB
keep_alive_interval_ms = 15000
```

#### Deliverables

- [ ] QUIC listener accepts connections on UDP port.
- [ ] HTTP/3 requests are routed through the same middleware/router as HTTP/1.1+2.
- [ ] PQC hybrid TLS works over QUIC (same certificate, same key exchange).
- [ ] `Alt-Svc` header advertises HTTP/3 on HTTP/2 responses.
- [ ] Integration test: HTTP/3 request via `h3` client crate.
- [ ] Benchmark: HTTP/3 vs HTTP/2 latency and throughput comparison.

---

### Phase 7 — WebSocket Support

**Goal:** The gateway can proxy WebSocket connections. Clients upgrade from HTTP to
WebSocket, and the gateway establishes a corresponding upstream WebSocket connection,
forwarding frames bidirectionally.

**Duration estimate:** 1-2 weeks

#### 7.1 WebSocket Upgrade Handling

- Use `axum::extract::WebSocketUpgrade` for HTTP/1.1 WebSocket upgrades.
- Detect `Upgrade: websocket` header and `Connection: Upgrade`.
- Apply authentication middleware *before* the upgrade (JWT validation on the initial
  HTTP request).
- After auth, perform the upgrade.

#### 7.2 Upstream WebSocket Connection

- Establish a WebSocket connection to the upstream service using
  `tokio-tungstenite`.
- Forward the original request headers (auth, cookies, custom headers) to the
  upstream handshake.

#### 7.3 Bidirectional Frame Forwarding

- Two concurrent tasks per WebSocket connection:
  1. Client → Gateway → Upstream (forward client frames).
  2. Upstream → Gateway → Client (forward upstream frames).
- Handle text frames, binary frames, ping/pong, and close frames.
- Use `tokio::select!` for clean shutdown when either side closes.

```rust
async fn proxy_websocket(client_ws: WebSocket, upstream_url: &str) {
    let (upstream_ws, _) = tokio_tungstenite::connect_async(upstream_url).await?;
    let (client_tx, client_rx) = client_ws.split();
    let (upstream_tx, upstream_rx) = upstream_ws.split();

    let client_to_upstream = forward(client_rx, upstream_tx);
    let upstream_to_client = forward(upstream_rx, client_tx);

    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }
}
```

#### 7.4 WebSocket Route Configuration

```toml
[[routes]]
path_prefix = "/ws/chat"
upstream = "ws://127.0.0.1:9001/chat"
protocol = "websocket"
auth_required = true

[[routes]]
path_prefix = "/ws/notifications"
upstream = "ws://127.0.0.1:9002/notifications"
protocol = "websocket"
auth_required = false
```

#### 7.5 WebSocket over QUIC (WebTransport — Future)

- HTTP/3 supports WebTransport (draft RFC), which provides WebSocket-like
  bidirectional streams over QUIC.
- Mark as experimental / future phase — the `h3` crate has emerging support.
- For now, WebSocket support is over TCP (HTTP/1.1 upgrade) only.

#### Deliverables

- [ ] WebSocket upgrade works through the gateway.
- [ ] Auth middleware runs on the upgrade request.
- [ ] Bidirectional frame forwarding works correctly.
- [ ] Connection cleanup on client or upstream disconnect.
- [ ] Ping/pong keepalive forwarding.
- [ ] Integration test: WebSocket echo test through the gateway.

---

### Phase 8 — Observability & Production Hardening

**Goal:** Make the gateway production-ready with comprehensive observability, rate
limiting, circuit breaking, and operational features.

**Duration estimate:** 2-3 weeks

#### 8.1 Prometheus Metrics

Expose `GET /metrics` endpoint with:

| Metric                                | Type      | Labels                           |
|---------------------------------------|-----------|----------------------------------|
| `gateway_requests_total`              | Counter   | method, path, status, protocol   |
| `gateway_request_duration_seconds`    | Histogram | method, path, protocol           |
| `gateway_active_connections`          | Gauge     | protocol (h1, h2, h3, ws)       |
| `gateway_upstream_requests_total`     | Counter   | upstream, status                 |
| `gateway_upstream_latency_seconds`    | Histogram | upstream                         |
| `gateway_tls_handshake_total`         | Counter   | kx_algorithm (x25519, mlkem768)  |
| `gateway_tls_handshake_duration_secs` | Histogram | kx_algorithm                     |
| `gateway_auth_attempts_total`         | Counter   | result (success, failure, expired)|
| `gateway_rbac_denials_total`          | Counter   | role, path                       |
| `gateway_dpop_validations_total`      | Counter   | result                           |
| `gateway_rate_limit_rejections_total` | Counter   | path                             |

#### 8.2 Structured Tracing

- Every request gets a trace span with: request_id, method, path, user_id (if authed),
  protocol, upstream, duration.
- Use `tracing-opentelemetry` for export to Jaeger / OTLP collector.
- Propagate trace context (`traceparent` header) to upstreams.

#### 8.3 Rate Limiting

- Token bucket or sliding window rate limiting per:
  - IP address (default).
  - Authenticated user ID.
  - API key.
- Configurable per route:

```toml
[[routes]]
path_prefix = "/api/v1/expensive"
upstream = "http://127.0.0.1:9001"
rate_limit = { requests = 100, window_seconds = 60 }
```

- Return `429 Too Many Requests` with `Retry-After` header.
- Use `governor` or `tower-governor` crate.

#### 8.4 Circuit Breaker

- Per-upstream circuit breaker:
  - **Closed**: Normal operation.
  - **Open**: Upstream considered down, return `503` immediately.
  - **Half-open**: Allow probe requests to check recovery.
- Trip threshold: configurable error rate or consecutive failures.
- Recovery timeout: configurable.

#### 8.5 Request/Response Size Limits

```toml
[server]
max_request_body_bytes = 10485760   # 10 MB
max_response_body_bytes = 52428800  # 50 MB
```

#### 8.6 CORS

- Configurable CORS via `tower-http::CorsLayer`:

```toml
[cors]
allowed_origins = ["https://app.example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allowed_headers = ["Authorization", "Content-Type", "DPoP"]
max_age_seconds = 3600
```

#### 8.7 Graceful Shutdown & Drain

- On SIGTERM: stop accepting new connections.
- Drain in-flight requests with a configurable timeout (default 30s).
- Close WebSocket connections with proper close frames.
- Close QUIC connections with `CONNECTION_CLOSE` frames.

#### 8.8 Admin API

- Optional admin listener on a separate port:

```toml
[admin]
enabled = true
bind_address = "127.0.0.1"
port = 9090
```

- Endpoints:
  - `GET /admin/health` — Detailed health (upstreams, connection counts).
  - `GET /admin/metrics` — Prometheus metrics.
  - `POST /admin/config/reload` — Trigger config reload.
  - `GET /admin/routes` — List active routes.
  - `GET /admin/connections` — Active connection stats.

#### Deliverables

- [ ] Prometheus metrics endpoint with all key metrics.
- [ ] Structured JSON logs with trace context.
- [ ] Rate limiting works per-IP and per-user.
- [ ] Circuit breaker trips on upstream failures and recovers.
- [ ] CORS headers are configurable and correct.
- [ ] Graceful shutdown drains connections cleanly.
- [ ] Admin API provides operational visibility.
- [ ] Load test: 10K concurrent connections, p99 latency < 10ms for proxy.

---

## 6. Security Considerations

### TLS & Cryptography

- **Hybrid-only key exchange**: Never offer pure PQC without a classical component
  during the transition period. If ML-KEM is broken, X25519 still protects the session.
- **TLS 1.3 minimum**: Never allow TLS 1.2 or below. No CBC cipher suites, no RSA
  key exchange.
- **Certificate pinning**: Optional support for pinning upstream certificates.
- **Key material protection**: Private keys loaded into memory are zeroized on drop
  (`zeroize` crate). No logging of key material.
- **Constant-time operations**: Use `subtle` crate for comparisons of secrets, tokens,
  and hashes.

### Authentication & Tokens

- **JWT validation is strict**: Always verify signature, `exp`, `nbf`, `iss`, `aud`.
  Reject `alg: none`.
- **Short token lifetimes**: Access tokens ≤ 15 minutes. Refresh tokens ≤ 7 days with
  rotation.
- **DPoP replay window**: `jti` cache must be sized to handle peak traffic. Use
  probabilistic data structures (bloom filter) if memory constrained.
- **Password storage**: Argon2id only. Never store plaintext or use fast hashes.

### Input Validation

- **Header injection**: Sanitize all headers forwarded to upstreams.
- **Path traversal**: Normalize paths before routing; reject `../` sequences.
- **Request smuggling**: Strict HTTP parsing mode in hyper. Reject ambiguous
  `Content-Length` / `Transfer-Encoding` combinations.
- **WebSocket origin validation**: Configurable allowed origins for WebSocket upgrades.

### Denial of Service

- **Connection limits**: Max connections per IP, max total connections.
- **Slowloris protection**: Read/write timeouts on all connections.
- **Large request rejection**: Enforce body size limits before reading full body.
- **QUIC amplification**: Rely on Quinn's built-in address validation (retry tokens).

---

## 7. Testing Strategy

### Unit Tests

- Every crate has focused unit tests for its core logic.
- RBAC policy evaluation: exhaustive tests for hierarchy, wildcards, deny rules.
- JWT: malformed tokens, expired tokens, wrong algorithm, missing claims.
- DPoP: replay detection, nonce validation, `ath` computation.
- Route matching: prefix, exact, wildcard, method filtering.

### Integration Tests

- Full gateway lifecycle: start → route requests → shutdown.
- Auth flows: register → login → access → refresh → logout.
- TLS: classical handshake, PQC hybrid handshake, fallback verification.
- WebSocket: upgrade → send/receive → close.
- QUIC: HTTP/3 request → response through middleware.

### Property-Based Tests

- Use `proptest` or `quickcheck` for:
  - Route matching (fuzz paths and methods).
  - RBAC evaluation (fuzz roles, paths, methods).
  - JWT claims (fuzz all fields).

### Performance Tests

- Use `criterion` for microbenchmarks:
  - TLS handshake (PQC vs classical).
  - JWT validation throughput.
  - Route matching latency.
  - RBAC evaluation latency.
- Use `k6` or `wrk` for load testing:
  - Requests per second at various concurrency levels.
  - P50/P95/P99 latency under load.
  - Memory usage stability over time.

### Security Tests

- Fuzz HTTP parsing with `cargo-fuzz`.
- Test for known attack patterns (request smuggling, header injection).
- Verify constant-time token comparison.
- Test TLS configuration with `testssl.sh`.

---

## 8. Performance Targets

| Metric                              | Target                                |
|-------------------------------------|---------------------------------------|
| Proxy throughput (HTTP/2)           | > 50,000 requests/sec (single core)   |
| Proxy latency (p99, no upstream)    | < 1 ms                                |
| TLS handshake (classical)           | < 2 ms                                |
| TLS handshake (PQC hybrid)          | < 5 ms                                |
| JWT validation                      | < 50 μs per token                     |
| RBAC evaluation                     | < 10 μs per request                   |
| Memory (idle, no connections)       | < 20 MB                               |
| Memory (10K active connections)     | < 500 MB                              |
| WebSocket frame forwarding latency  | < 0.5 ms                              |
| Startup time                        | < 500 ms                              |

---

## 9. Future Roadmap

Items beyond the 8 phases, for consideration:

- **mTLS (Mutual TLS)**: Client certificate authentication with PQC certificates.
- **gRPC proxying**: HTTP/2 gRPC passthrough with header-based routing.
- **WebTransport**: Bidirectional streams over HTTP/3 (QUIC) — successor to WebSocket.
- **API Key management**: Issue and rotate API keys, rate limit per key.
- **OAuth 2.0 Authorization Server**: Full OAuth2 flows (authorization code, client
  credentials) — currently only resource server / token validation.
- **Plugin system**: WASM-based plugins for custom middleware logic.
- **Cluster mode**: Multiple gateway instances with shared state (Redis/etcd) for
  rate limiting, session, and config sync.
- **PQC certificate ecosystem**: As CAs start issuing ML-DSA certificates, support
  them natively for server identity and mTLS.
- **SLH-DSA (FIPS 205)**: Hash-based signature backup for cryptographic diversity.
- **FN-DSA (FIPS 206)**: FALCON-based signatures when standardized.
- **HQC**: Code-based KEM backup when NIST standardizes it (~2026).

---

## Appendix A: NIST PQC Standards Reference

| Standard | Algorithm  | Type       | Based On         | Use Case               |
|----------|-----------|------------|------------------|------------------------|
| FIPS 203 | ML-KEM    | KEM        | CRYSTALS-Kyber   | Key exchange (TLS)     |
| FIPS 204 | ML-DSA    | Signature  | CRYSTALS-Dilithium| Certificates, JWT, DPoP|
| FIPS 205 | SLH-DSA   | Signature  | SPHINCS+         | Backup signatures      |
| (Draft)  | FN-DSA    | Signature  | FALCON           | Compact signatures     |

## Appendix B: Key Crate Versions (Baseline)

| Crate                    | Version  | Purpose                          |
|--------------------------|----------|----------------------------------|
| `tokio`                  | 1.x      | Async runtime                    |
| `axum`                   | 0.8+     | HTTP framework                   |
| `tower`                  | 0.5+     | Middleware abstraction            |
| `hyper`                  | 1.x      | HTTP implementation              |
| `rustls`                 | 0.23+    | TLS library                      |
| `rustls-post-quantum`    | latest   | PQC hybrid key exchange          |
| `quinn`                  | 0.11+    | QUIC implementation              |
| `h3`                     | latest   | HTTP/3 protocol                  |
| `jsonwebtoken`           | 9.x      | JWT handling                     |
| `argon2`                 | 0.5+     | Password hashing                 |
| `sqlx`                   | 0.8+     | Database access                  |
| `ml-kem`                 | latest   | FIPS 203 (RustCrypto)            |
| `ml-dsa`                 | latest   | FIPS 204 (RustCrypto)            |
| `tracing`                | 0.1+     | Structured logging               |
| `metrics`                | latest   | Metrics collection               |
| `governor`               | latest   | Rate limiting                    |
| `moka`                   | latest   | Concurrent cache                 |
| `tokio-tungstenite`      | latest   | WebSocket client                 |

---

*This document is the living design reference for the PQC Gateway project.
Update it as implementation decisions are made and requirements evolve.*