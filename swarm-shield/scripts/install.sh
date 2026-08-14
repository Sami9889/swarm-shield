#!/bin/bash
# swarm-shield Enterprise Installer
# Installs dependencies and configures the environment for swarm-shield

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}[info]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
error() { echo -e "${RED}[error]${NC} $1"; }
ok() { echo -e "${GREEN}[ok]${NC} $1"; }

banner() {
    echo -e "${BLUE}"
    echo "================================================================"
    echo "  swarm-shield Enterprise Installer"
    echo "  WebRTC P2P Swarm Mesh + Adaptive Proof-of-Work"
    echo "================================================================"
    echo -e "${NC}"
}

check_cmd() {
    if command -v "$1" &> /dev/null; then
        ok "$1 installed"
        return 0
    else
        warn "$1 not found"
        return 1
    fi
}

install_go() {
    if check_cmd go; then
        go version
        return 0
    fi
    info "Installing Go 1.22..."
    GO_VERSION="1.22.5"
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    ok "Go ${GO_VERSION} installed"
}

install_docker() {
    if check_cmd docker; then
        docker --version
        return 0
    fi
    info "Installing Docker..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm /tmp/get-docker.sh
    ok "Docker installed"
}

install_helm() {
    if check_cmd helm; then
        helm version --short
        return 0
    fi
    info "Installing Helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 -o /tmp/get-helm.sh
    chmod 700 /tmp/get-helm.sh
    /tmp/get-helm.sh
    rm /tmp/get-helm.sh
    ok "Helm installed"
}

setup_project() {
    info "Configuring swarm-shield project..."

    cd "$(dirname "$0")/.."

    if command -v go &> /dev/null; then
        info "Downloading Go modules..."
        go mod download
        ok "Go modules downloaded"
    else
        warn "Go not found, skipping go mod download"
    fi

    if [ ! -f ".env" ]; then
        info "Creating .env configuration..."
        JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "change-me-in-production-$(date +%s)")
        cat > .env << EOF
PORT=8080
JWT_SECRET=${JWT_SECRET}
HOST=0.0.0.0

FEATURE_P2P=true
FEATURE_POW=true
FEATURE_WEBSOCKET=true
FEATURE_AUDIT_LOG=true
FEATURE_METRICS=true

RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPM=120
RATE_LIMIT_BURST=20

METRICS_ENABLED=true
METRICS_ENDPOINT=0.0.0.0
METRICS_PATH=/metrics
EOF
        ok ".env created"
    fi

    mkdir -p data/logs data/cache
    ok "Data directories ready"
}

main() {
    banner

    OS=$(uname -s)
    case $OS in
        Linux*) ;;
            *) error "Unsupported OS: $OS. Linux required."; exit 1 ;;
    esac

    info "Starting swarm-shield enterprise setup..."
    echo ""

    check_cmd node || {
        info "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
        ok "Node.js installed"
    }
    install_go
    install_docker
    install_helm

    echo ""
    setup_project

    echo ""
    ok "Setup complete."
    echo ""
    info "Next steps:"
    echo "  1. Review .env configuration"
    echo "  2. Run: npm run dev"
    echo "  3. Open: http://localhost:8080"
    echo "  4. Generate API key: npm run generate-api-key"
    echo ""
    info "Production deployment:"
    echo "  docker compose -f deploy/docker-compose.yml up -d"
    echo ""
}

main "$@"
