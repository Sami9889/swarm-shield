set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { printf "${CYAN}[info]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[warn]${NC} %s\n" "$1"; }
error() { printf "${RED}[error]${NC} %s\n" "$1"; }
ok() { printf "${GREEN}[ok]${NC} %s\n" "$1"; }

banner() {
    printf "${BLUE}================================================================"
    printf "\n  Swarm Shield Enterprise Installer"
    printf "\n  WebRTC P2P Swarm Mesh + Adaptive Proof-of-Work"
    printf "\n================================================================"
    printf "${NC}\n"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --skip-go        Skip Go installation
  --skip-docker    Skip Docker installation
  --skip-helm      Skip Helm installation
  --dev-only       Install only development dependencies
  --help           Show this help message

Examples:
  $(basename "$0")                  # Full installation
  $(basename "$0") --dev-only       # Development only
  $(basename "$0") --skip-docker    # Skip Docker
EOF
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="${ID}"
        OS_VERSION="${VERSION_ID}"
    else
        error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    info "Detected OS: ${OS} ${OS_VERSION}"
}

check_command() {
    local cmd="$1"
    local name="${2:-$1}"

    if command -v "$cmd" &> /dev/null; then
        local version
        version=$("$cmd" version 2>/dev/null || "$cmd" --version 2>/dev/null || echo "installed")
        ok "${name} is installed: ${version}"
        return 0
    else
        warn "${name} not found"
        return 1
    fi
}

resolve_sudo_user() {
    if [ -n "${SUDO_USER:-}" ]; then
        echo "$SUDO_USER"
    else
        echo "$USER"
    fi
}

require_privileges() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This step requires root privileges. Re-run with sudo."
        exit 1
    fi
}

install_go() {
    local skip="${1:-false}"
    if [ "$skip" = "true" ]; then
        info "Skipping Go installation"
        return
    fi

    if check_command go "Go"; then
        return
    fi

    info "Installing Go 1.22.5..."
    local go_version="1.22.5"
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64) go_arch="amd64" ;;
        aarch64|arm64) go_arch="arm64" ;;
        armv7l) go_arch="armv6l" ;;
        *) error "Unsupported architecture: ${arch}"; exit 1 ;;
    esac

    require_privileges

    local download_url="https://go.dev/dl/go${go_version}.linux-${go_arch}.tar.gz"
    local checksum_url="${download_url}.sha256"
    local tmp_tar
    tmp_tar=$(mktemp /tmp/go-install.XXXXXX.tar.gz)

    info "Downloading Go from: ${download_url}"

    if ! curl -fsSL "$download_url" -o "$tmp_tar"; then
        error "Failed to download Go"
        rm -f "$tmp_tar"
        exit 1
    fi

    local expected_checksum
    expected_checksum=$(curl -fsSL "$checksum_url" | tr -d '[:space:]')
    if [ -z "$expected_checksum" ]; then
        error "Failed to fetch Go checksum"
        rm -f "$tmp_tar"
        exit 1
    fi

    local actual_checksum
    actual_checksum=$(sha256sum "$tmp_tar" | awk '{print $1}')

    if [ "$actual_checksum" != "$expected_checksum" ]; then
        error "Go tarball checksum mismatch"
        rm -f "$tmp_tar"
        exit 1
    fi

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp_tar"
    rm -f "$tmp_tar"

    local target_user
    target_user=$(resolve_sudo_user)
    local target_home
    target_home=$(eval echo "~${target_user}")

    if ! grep -q '/usr/local/go/bin' "${target_home}/.bashrc" 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "${target_home}/.bashrc"
        echo 'export GOPATH=$HOME/go' >> "${target_home}/.bashrc"
        echo 'export PATH=$PATH:$GOPATH/bin' >> "${target_home}/.bashrc"
    fi

    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    ok "Go ${go_version} installed successfully"
}

install_docker() {
    local skip="${1:-false}"
    if [ "$skip" = "true" ]; then
        info "Skipping Docker installation"
        return
    fi

    if check_command docker "Docker"; then
        if ! groups | grep -q docker; then
            warn "Current user is not in the docker group"
            info "Run: sudo usermod -aG docker $USER"
        fi
        return
    fi

    info "Installing Docker..."

    case "$OS" in
        ubuntu|debian)
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sh /tmp/get-docker.sh
            rm /tmp/get-docker.sh
            ;;
        centos|rhel|fedora)
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sh /tmp/get-docker.sh
            rm /tmp/get-docker.sh
            ;;
        *)
            warn "Unsupported OS for automatic Docker installation: ${OS}"
            info "Please install Docker manually from https://docs.docker.com/engine/install/"
            return
            ;;
    esac

    if ! groups | grep -q docker; then
        sudo usermod -aG docker "$USER" 2>/dev/null || true
        warn "Added $USER to docker group. Log out and back in for changes to take effect."
    fi

    ok "Docker installed successfully"
}

install_helm() {
    local skip="${1:-false}"
    if [ "$skip" = "true" ]; then
        info "Skipping Helm installation"
        return
    fi

    if check_command helm "Helm"; then
        return
    fi

    info "Installing Helm..."

    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 -o /tmp/get-helm.sh
    chmod 700 /tmp/get-helm.sh
    /tmp/get-helm.sh
    rm /tmp/get-helm.sh

    ok "Helm installed successfully"
}

setup_project() {
    info "Configuring swarm-shield project..."
    cd "$PROJECT_ROOT" || exit 1

    if command -v go &> /dev/null; then
        info "Downloading Go modules..."
        if ! go mod download; then
            warn "Failed to download Go modules"
        else
            ok "Go modules downloaded"
        fi
    else
        warn "Go not found, skipping go mod download"
    fi

    if [ ! -f ".env" ]; then
        info "Creating .env configuration..."
        local jwt_secret
        if ! jwt_secret=$(openssl rand -hex 32 2>/dev/null); then
            error "Failed to generate JWT_SECRET. openssl is required."
            exit 1
        fi

        cat > .env << EOF

PORT=8080
HOST=0.0.0.0

JWT_SECRET=${jwt_secret}

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
        chmod 600 .env
        ok "Created .env configuration"
    else
        info ".env already exists, skipping"
    fi

    mkdir -p data/logs data/cache
    ok "Data directories ready"
}

main() {
    banner

    local skip_go=false
    local skip_docker=false
    local skip_helm=false
    local dev_only=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-go) skip_go=true; shift ;;
            --skip-docker) skip_docker=true; shift ;;
            --skip-helm) skip_helm=true; shift ;;
            --dev-only) dev_only=true; shift ;;
            --help|-h) usage; exit 0 ;;
            *) error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    if [ "$dev_only" = "true" ]; then
        skip_docker=true
        skip_helm=true
    fi

    if [ "$(uname -s)" != "Linux" ]; then
        error "Unsupported OS: $(uname -s). Linux required."
        exit 1
    fi

    detect_os

    info "Starting swarm-shield enterprise installation..."
    echo ""

    check_command node "Node.js" || {
        warn "Node.js not found. Please install Node.js 20+ manually."
    }

    install_go "$skip_go"
    install_docker "$skip_docker"
    install_helm "$skip_helm"

    echo ""
    setup_project

    echo ""
    ok "Installation complete."
    echo ""
    info "Next steps:"
    echo "  1. Review .env configuration"
    echo "  2. Run: npm run dev"
    echo "  3. Open: http://localhost:8080"
    echo ""
    info "Production deployment:"
    echo "  docker compose -f deploy/docker-compose.yml up -d"
    echo ""
    info "Helm deployment:"
    echo "  helm install swarm-shield deploy/helm/swarm-shield"
    echo ""
}

main "$@"
