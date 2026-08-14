#!/bin/bash
set -e

SECRETS_DIR="/run/secrets/swarm-shield"

decrypt_if_exists() {
    local name="$1"
    local enc_file="${SECRETS_DIR}/${name}.enc"
    local key_file="${SECRETS_DIR}/master.key"
    
    if [ -f "$enc_file" ] && [ -f "$key_file" ]; then
        local key
        key=$(cat "$key_file")
        openssl enc -d -aes-256-cbc -pbkdf2 -salt -pass pass:"$key" -in "$enc_file" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

export JWT_SECRET=$(decrypt_if_exists "jwt_secret")
export POSTGRES_PASSWORD=$(decrypt_if_exists "postgres_password")
export REDIS_PASSWORD=$(decrypt_if_exists "redis_password")
export GF_SECURITY_ADMIN_PASSWORD=$(decrypt_if_exists "grafana_password")
export POSTGRES_USER=$(cat "${SECRETS_DIR}/config.env" 2>/dev/null | grep POSTGRES_USER | cut -d= -f2 || echo "swarm")
export POSTGRES_DB=$(cat "${SECRETS_DIR}/config.env" 2>/dev/null | grep POSTGRES_DB | cut -d= -f2 || echo "swarm_shield")

exec /swarm-shield