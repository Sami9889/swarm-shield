set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SECRETS_DIR="${PROJECT_ROOT}/secrets"
ENCRYPTION_KEY_FILE="${SECRETS_DIR}/master.key"

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
    printf "\n  Swarm Shield Secrets Setup"
    printf "\n  AES-256-CBC Encrypted Credential Management"
    printf "\n================================================================"
    printf "${NC}\n"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --docker-secrets   Create plaintext secret files for Docker secrets
  --encrypted        Create AES-256-CBC encrypted secrets (default)
  --help             Show this help message

Examples:
  $(basename "$0")                    # Encrypted secrets (default)
  $(basename "$0") --docker-secrets   # Docker secrets
EOF
}

validate_password() {
    local name="$1"
    local password="$2"
    local min_length="${3:-16}"

    if [ ${#password} -lt "$min_length" ]; then
        error "${name} must be at least ${min_length} characters"
        return 1
    fi

    if [[ "$password" =~ [A-Z]+ ]] && [[ "$password" =~ [a-z]+ ]] && [[ "$password" =~ [0-9]+ ]]; then
        return 0
    else
        warn "${name} should contain uppercase, lowercase, and numbers"
        return 0
    fi
}

generate_password() {
    local length="${1:-32}"
    openssl rand -base64 "$((length * 3 / 4))" | tr -d '/+=' | head -c "$length"
}

prompt_credentials() {
    local -a jwt_secret postgres_password redis_password grafana_password
    local postgres_user postgres_db

    echo ""
    info "Enter credentials (press Enter for auto-generated secure defaults)"
    echo ""

    read -rp "JWT Secret (min 32 chars, auto-generated if empty): " jwt_secret
    if [ -z "$jwt_secret" ]; then
        jwt_secret=$(openssl rand -hex 32)
        ok "Generated JWT Secret (64 hex chars)"
    else
        if ! validate_password "JWT_SECRET" "$jwt_secret" 32; then
            error "JWT_SECRET must be at least 32 characters"
            exit 1
        fi
    fi

    read -rp "PostgreSQL Password (min 16 chars): " postgres_password
    if [ -z "$postgres_password" ]; then
        postgres_password=$(generate_password 24)
        ok "Generated PostgreSQL password"
    else
        if ! validate_password "POSTGRES_PASSWORD" "$postgres_password" 16; then
            error "POSTGRES_PASSWORD must be at least 16 characters"
            exit 1
        fi
    fi

    read -rp "Redis Password (press Enter for no auth): " redis_password
    if [ -n "$redis_password" ] && ! validate_password "REDIS_PASSWORD" "$redis_password" 16; then
        error "REDIS_PASSWORD must be at least 16 characters"
        exit 1
    fi

    read -rp "Grafana Admin Password (min 8 chars): " grafana_password
    if [ -z "$grafana_password" ]; then
        grafana_password=$(generate_password 16)
        ok "Generated Grafana admin password"
    else
        if ! validate_password "GRAFANA_PASSWORD" "$grafana_password" 8; then
            error "GRAFANA_PASSWORD must be at least 8 characters"
            exit 1
        fi
    fi

    read -rp "PostgreSQL User [swarm]: " postgres_user
    postgres_user=${postgres_user:-swarm}

    read -rp "PostgreSQL Database [swarm_shield]: " postgres_db
    postgres_db=${postgres_db:-swarm_shield}

    JWT_SECRET="$jwt_secret"
    POSTGRES_PASSWORD="$postgres_password"
    REDIS_PASSWORD="$redis_password"
    GRAFANA_PASSWORD="$grafana_password"
    POSTGRES_USER="$postgres_user"
    POSTGRES_DB="$postgres_db"
}

encrypt_secret() {
    local name="$1"
    local value="$2"
    local outfile="${SECRETS_DIR}/${name}.enc"

    if [ -z "$value" ]; then
        warn "Skipping empty secret: ${name}"
        return 0
    fi

    if ! echo -n "$value" | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:"$ENCRYPTION_KEY" -out "$outfile" 2>/dev/null; then
        error "Failed to encrypt secret: ${name}"
        return 1
    fi

    chmod 600 "$outfile"
    ok "Encrypted ${name} -> ${outfile}"
}

create_docker_secret() {
    local name="$1"
    local value="$2"
    local outfile="${SECRETS_DIR}/${name}.txt"

    if [ -z "$value" ]; then
        warn "Skipping empty secret: ${name}"
        return 0
    fi

    printf '%s' "$value" > "$outfile"
    chmod 600 "$outfile"
    ok "Created Docker secret: ${outfile}"
}

write_config_env() {
    local config_file="${SECRETS_DIR}/config.env"

    cat > "$config_file" << EOF

POSTGRES_USER=${POSTGRES_USER}
POSTGRES_DB=${POSTGRES_DB}

PORT=8080
HOST=0.0.0.0

REDIS_ENABLED=true
POSTGRES_ENABLED=true
METRICS_ENABLED=true
FEATURE_P2P=true
FEATURE_POW=true
FEATURE_WEBSOCKET=true
FEATURE_AUDIT_LOG=true

RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPM=120
RATE_LIMIT_BURST=20

METRICS_ENDPOINT=0.0.0.0
METRICS_PATH=/metrics
EOF

    chmod 600 "$config_file"
    ok "Created configuration: ${config_file}"
}

main() {
    banner

    local mode="encrypted"
    case "${1:-}" in
        --docker-secrets) mode="docker" ;;
        --encrypted) mode="encrypted" ;;
        --help|-h) usage; exit 0 ;;
        *) ;;
    esac

    if [ ! -d "$SECRETS_DIR" ]; then
        mkdir -p "$SECRETS_DIR"
        chmod 700 "$SECRETS_DIR"
        ok "Created secrets directory: ${SECRETS_DIR}"
    fi

    if [ "$mode" = "encrypted" ]; then
        if [ -f "$ENCRYPTION_KEY_FILE" ]; then
            info "Loading existing encryption key"
            ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")
        else
            info "Generating new encryption key"
            ENCRYPTION_KEY=$(openssl rand -hex 32)
            printf '%s' "$ENCRYPTION_KEY" > "$ENCRYPTION_KEY_FILE"
            chmod 600 "$ENCRYPTION_KEY_FILE"
            ok "Generated encryption key: ${ENCRYPTION_KEY_FILE}"
        fi
    fi

    prompt_credentials

    echo ""
    info "Writing secrets (mode: ${mode})..."

    case "$mode" in
        encrypted)
            encrypt_secret "jwt_secret" "$JWT_SECRET"
            encrypt_secret "postgres_password" "$POSTGRES_PASSWORD"
            encrypt_secret "redis_password" "$REDIS_PASSWORD"
            encrypt_secret "grafana_password" "$GRAFANA_PASSWORD"
            ;;
        docker)
            create_docker_secret "jwt_secret" "$JWT_SECRET"
            create_docker_secret "postgres_password" "$POSTGRES_PASSWORD"
            create_docker_secret "redis_password" "$REDIS_PASSWORD"
            create_docker_secret "grafana_password" "$GRAFANA_PASSWORD"
            ;;
    esac

    write_config_env

    echo ""
    ok "Setup complete."
    echo ""
    info "Secrets stored in: ${SECRETS_DIR}/"
    info "Configuration: ${SECRETS_DIR}/config.env"
    echo ""
    info "Next steps:"
    echo "  1. Review ${SECRETS_DIR}/config.env"
    echo "  2. Start services: docker compose -f deploy/docker-compose.yml up -d"
    echo ""

    if [ "$mode" = "encrypted" ]; then
        warn "Keep ${ENCRYPTION_KEY_FILE} secure. Back it up to a safe location."
    fi
}

main "$@"
