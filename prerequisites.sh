#!/usr/bin/env bash
#
# prerequisites.sh — Install all dependencies needed to build and run pqc_gateway.
# Supports Ubuntu/Debian and Fedora/RHEL/Arch. Installs Rust if missing.
#
# Usage:
#   chmod +x prerequisites.sh
#   ./prerequisites.sh
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --------------------------------------------------------------------------
# Detect OS / package manager
# --------------------------------------------------------------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-$OS_ID}"
    elif [ "$(uname)" = "Darwin" ]; then
        OS_ID="macos"
        OS_LIKE="macos"
    else
        OS_ID="unknown"
        OS_LIKE="unknown"
    fi
}

detect_os
info "Detected OS: $OS_ID ($OS_LIKE)"

# --------------------------------------------------------------------------
# Install system packages (gcc, libc-dev, pkg-config, libssl-dev, curl)
# --------------------------------------------------------------------------
install_system_deps() {
    info "Installing system dependencies..."

    case "$OS_ID" in
        ubuntu|debian|pop|linuxmint)
            apt-get update -qq
            apt-get install -y \
                build-essential \
                gcc \
                libc6-dev \
                pkg-config \
                libssl-dev \
                curl \
                git
            ;;
        fedora)
            dnf install -y \
                gcc \
                glibc-devel \
                pkg-config \
                openssl-devel \
                curl \
                git
            ;;
        centos|rhel|rocky|almalinux)
            yum install -y \
                gcc \
                glibc-devel \
                pkgconfig \
                openssl-devel \
                curl \
                git
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm \
                base-devel \
                openssl \
                pkg-config \
                curl \
                git
            ;;
        macos)
            if ! command -v brew &>/dev/null; then
                warn "Homebrew not found. Installing..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install openssl pkg-config curl git
            ;;
        *)
            # Try debian-style first, then fedora-style
            if command -v apt-get &>/dev/null; then
                apt-get update -qq
                apt-get install -y build-essential pkg-config libssl-dev curl git
            elif command -v dnf &>/dev/null; then
                dnf install -y gcc glibc-devel pkg-config openssl-devel curl git
            elif command -v yum &>/dev/null; then
                yum install -y gcc glibc-devel pkgconfig openssl-devel curl git
            elif command -v pacman &>/dev/null; then
                pacman -Sy --noconfirm base-devel openssl pkg-config curl git
            else
                error "Unsupported OS: $OS_ID. Please install manually:"
                error "  - gcc (C compiler)"
                error "  - libc development headers"
                error "  - pkg-config"
                error "  - OpenSSL development headers"
                error "  - curl"
                error "  - git"
                exit 1
            fi
            ;;
    esac

    info "System dependencies installed."
}

# --------------------------------------------------------------------------
# Install Rust via rustup (if not present)
# --------------------------------------------------------------------------
install_rust() {
    if command -v rustc &>/dev/null && command -v cargo &>/dev/null; then
        local rust_version
        rust_version=$(rustc --version)
        info "Rust already installed: $rust_version"
    else
        info "Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
        info "Rust installed: $(rustc --version)"
    fi
}

# --------------------------------------------------------------------------
# Verify everything works
# --------------------------------------------------------------------------
verify() {
    info "Verifying installations..."
    local ok=true

    for cmd in gcc cc pkg-config curl git rustc cargo; do
        if command -v "$cmd" &>/dev/null; then
            printf "  %-12s %s\n" "$cmd" "$(command -v "$cmd")"
        else
            error "  $cmd — NOT FOUND"
            ok=false
        fi
    done

    echo ""
    info "Versions:"
    echo "  gcc:   $(gcc --version 2>&1 | head -1)"
    echo "  rustc: $(rustc --version)"
    echo "  cargo: $(cargo --version)"

    if [ "$ok" = true ]; then
        echo ""
        info "All prerequisites satisfied."
        info ""
        info "Next steps:"
        info "  cargo build --workspace          # Build everything"
        info "  cargo test  --workspace          # Run unit tests"
        info "  bash tests/scripts/run_tests.sh  # Run E2E tests"
    else
        echo ""
        error "Some tools are missing. Please install them manually."
        exit 1
    fi
}

# --------------------------------------------------------------------------
# Clean up any leftover .cargo/config.toml overrides
# --------------------------------------------------------------------------
clean_cargo_config() {
    local config_file=".cargo/config.toml"
    if [ -f "$config_file" ]; then
        # Check if it contains the hardcoded user-local gcc paths
        if grep -q "/.local/usr/bin" "$config_file" 2>/dev/null; then
            info "Removing stale .cargo/config.toml with hardcoded paths..."
            rm "$config_file"
            # Remove directory if empty
            rmdir .cargo 2>/dev/null || true
            info "Cleaned up. System gcc will be used directly."
        fi
    fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
echo "============================================"
echo "  PQC Gateway — Prerequisites Installer"
echo "============================================"
echo ""

install_system_deps
install_rust
clean_cargo_config
echo ""
verify