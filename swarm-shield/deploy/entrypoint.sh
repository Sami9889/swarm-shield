set -euo pipefail

readonly SECRETS_DIR="/run/secrets/swarm-shield"
readonly REQUIRED_SECRETS=("jwt_secret" "postgres_password")
readonly OPTIONAL_SECRETS=("redis_password" "grafana_password")

log() {
    printf '[swarm-shield-entrypoint] %s\n' "$*" >&2
}

log_error() {
    printf '[swarm-shield-entrypoint] ERROR: %s\n' "$*" >&2
}

read_secret_file() {
    local file_path="$1"
    if [ -f "$file_path" ]; then
        tr -d '[:space:]' < "$file_path"
    else
        echo ""
    fi
}

read_encrypted_secret() {
    local name="$1"
    local enc_file="${SECRETS_DIR}/${name}.enc"
    local key_file="${SECRETS_DIR}/master.key"

    if [ ! -f "$enc_file" ] || [ ! -f "$key_file" ]; then
        echo ""
        return
    fi

    local key
    key=$(cat "$key_file")

    if [ -z "$key" ]; then
        log_error "Encryption key is empty for secret: ${name}"
        echo ""
        return
    fi

    if ! openssl enc -d -aes-256-cbc -pbkdf2 -salt -pass pass:"$key" -in "$enc_file" 2>/dev/null; then
        log_error "Failed to decrypt secret: ${name}"
        echo ""
        return
    fi
}

resolve_secret() {
    local var_name="$1"
    local secret_name="$2"
    local file_var="${var_name}_FILE"
    local value=""

    if [ -n "${!file_var:-}" ]; then
        value=$(read_secret_file "${!file_var}")
        if [ -n "$value" ]; then
            log "Resolved ${secret_name} from Docker secret file: ${!file_var}"
            echo "$value"
            return
        fi
    fi

    value=$(read_encrypted_secret "$secret_name")
    if [ -n "$value" ]; then
        log "Resolved ${secret_name} from encrypted secrets"
        echo "$value"
        return
    fi

    if [ -n "${!var_name:-}" ]; then
        log "Resolved ${secret_name} from environment variable"
        echo "${!var_name}"
        return
    fi

    echo ""
}

validate_secret() {
    local name="$1"
    local value="$2"

    if [ -z "$value" ]; then
        log_error "Required secret not resolved: ${name}"
        return 1
    fi

    if [ "$name" = "jwt_secret" ] && [ ${#value} -lt 32 ]; then
        log_error "JWT_SECRET must be at least 32 characters for security"
        return 1
    fi

    return 0
}

main() {
    log "Initializing Swarm Shield entrypoint"

    local jwt_secret
    jwt_secret=$(resolve_secret "JWT_SECRET" "jwt_secret")
    if ! validate_secret "jwt_secret" "$jwt_secret"; then
        log_error "JWT_SECRET resolution failed"
        exit 1
    fi
    export JWT_SECRET="$jwt_secret"

    local postgres_password
    postgres_password=$(resolve_secret "POSTGRES_PASSWORD" "postgres_password")
    if ! validate_secret "postgres_password" "$postgres_password"; then
        log_error "POSTGRES_PASSWORD resolution failed"
        exit 1
    fi
    export POSTGRES_PASSWORD="$postgres_password"

    local redis_password
    redis_password=$(resolve_secret "REDIS_PASSWORD" "redis_password")
    if [ -n "$redis_password" ]; then
        export REDIS_PASSWORD="$redis_password"
    fi

    local grafana_password
    grafana_password=$(resolve_secret "GF_SECURITY_ADMIN_PASSWORD" "grafana_password")
    if [ -n "$grafana_password" ]; then
        export GF_SECURITY_ADMIN_PASSWORD="$grafana_password"
    fi

    local postgres_user="${POSTGRES_USER:-swarm}"
    local postgres_db="${POSTGRES_DB:-swarm_shield}"

    if [ -f "${SECRETS_DIR}/config.env" ]; then
        local config_user config_db
        config_user=$(grep -E '^POSTGRES_USER=' "${SECRETS_DIR}/config.env" 2>/dev/null | cut -d= -f2- || echo "")
        config_db=$(grep -E '^POSTGRES_DB=' "${SECRETS_DIR}/config.env" 2>/dev/null | cut -d= -f2- || echo "")

        if [ -n "$config_user" ]; then
            postgres_user="$config_user"
        fi
        if [ -n "$config_db" ]; then
            postgres_db="$config_db"
        fi
    fi

    export POSTGRES_USER="$postgres_user"
    export POSTGRES_DB="$postgres_db"

    if [ -z "${DATABASE_URL:-}" ]; then
        export DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable"
    fi

    log "Starting Swarm Shield with configuration:"
    log "  POSTGRES_USER: ${POSTGRES_USER}"
    log "  POSTGRES_DB: ${POSTGRES_DB}"
    log "  REDIS_ENABLED: ${REDIS_ENABLED:-true}"
    log "  POSTGRES_ENABLED: ${POSTGRES_ENABLED:-true}"
    log "  METRICS_ENABLED: ${METRICS_ENABLED:-true}"

    exec /swarm-shield "$@"
}

main "$@"
