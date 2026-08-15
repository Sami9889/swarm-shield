set -uo pipefail

readonly GF_PASSWORD="${GF_SECURITY_ADMIN_PASSWORD:-admin}"
readonly GF_USER="${GF_SECURITY_ADMIN_USER:-admin}"
readonly GF_HEALTH_URL="http://localhost:3000/api/health"
readonly MAX_WAIT_SECONDS=90

log() {
    printf '[grafana-entrypoint] %s\n' "$*" >&2
}

log_error() {
    printf '[grafana-entrypoint] ERROR: %s\n' "$*" >&2
}

start_grafana() {
    if [ -f /run.sh ]; then
        log "Starting Grafana via /run.sh"
        /run.sh "$@" &
    elif command -v grafana-server >/dev/null 2>&1; then
        log "Starting Grafana via grafana-server"
        grafana-server \
            --homepath=/usr/share/grafana \
            --config=/etc/grafana/grafana.ini \
            --packaging=docker \
            "$@" &
    else
        log_error "Neither /run.sh nor grafana-server found"
        return 1
    fi
}

wait_for_health() {
    local elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT_SECONDS" ]; do
        if curl -sf "$GF_HEALTH_URL" >/dev/null 2>&1; then
            log "Grafana is healthy after ${elapsed}s"
            return 0
        fi
        if ! kill -0 "$GF_PID" 2>/dev/null; then
            log_error "Grafana process exited before becoming healthy"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    log_error "Grafana did not become healthy within ${MAX_WAIT_SECONDS}s"
    return 1
}

synchronize_password() {
    log "Synchronizing admin password for user: ${GF_USER}"

    if command -v grafana-cli >/dev/null 2>&1; then
        log "Using grafana-cli to reset admin password"
        if grafana-cli admin reset-admin-password "$GF_PASSWORD" >/dev/null 2>&1; then
            log "Password reset successful via grafana-cli"
            return 0
        else
            log "grafana-cli password reset failed, falling back to API"
        fi
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_error "Neither grafana-cli nor curl available for password reset"
        return 1
    fi

    local login_code
    login_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${GF_USER}\",\"password\":\"${GF_PASSWORD}\"}" \
        "$GF_HEALTH_URL" 2>/dev/null || echo "000")

    if [ "$login_code" != "200" ]; then
        log_error "Login failed with HTTP ${login_code}"
        return 1
    fi

    local csrf_token
    csrf_token=$(curl -s "$GF_HEALTH_URL" | grep -o '"csrfToken":"[^"]*"' | cut -d'"' -f4 || echo "")
    if [ -z "$csrf_token" ]; then
        log_error "Failed to obtain CSRF token"
        return 1
    fi

    local reset_code
    reset_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT \
        -H "Content-Type: application/json" \
        -H "X-Grafana-URL: http://localhost:3000" \
        -H "X-Grafana-CSRF-Token: ${csrf_token}" \
        -d "{\"password\":\"${GF_PASSWORD}\"}" \
        "${GF_HEALTH_URL%/health}/api/admin/users/current/password" 2>/dev/null || echo "000")

    if [ "$reset_code" = "200" ]; then
        log "Password reset successful via API"
        return 0
    else
        log_error "Password reset failed with HTTP ${reset_code}"
        return 1
    fi
}

forward_signals() {
    trap 'kill -TERM "$GF_PID" 2>/dev/null' TERM INT
    trap 'kill -QUIT "$GF_PID" 2>/dev/null' QUIT
    trap 'kill -USR1 "$GF_PID" 2>/dev/null' USR1
    trap 'kill -USR2 "$GF_PID" 2>/dev/null' USR2
}

main() {
    log "Initializing Grafana entrypoint"

    if ! start_grafana "$@"; then
        log_error "Failed to start Grafana"
        exit 1
    fi

    GF_PID=$!
    log "Grafana started with PID ${GF_PID}"

    forward_signals

    if ! wait_for_health; then
        log_error "Grafana failed health check"
        kill -TERM "$GF_PID" 2>/dev/null || true
        exit 1
    fi

    if ! synchronize_password; then
        log "Warning: password synchronization failed, using existing credentials"
    fi

    log "Waiting for Grafana process to exit"
    wait "$GF_PID"
    local exit_code=$?
    log "Grafana exited with code ${exit_code}"
    exit "$exit_code"
}

main "$@"
