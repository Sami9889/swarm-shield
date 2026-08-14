#!/bin/bash
# Decrypt a secret at runtime for use by services
set -e

SECRETS_DIR="${SECRETS_DIR:-/run/secrets/swarm-shield}"
ENCRYPTION_KEY_FILE="${SECRETS_DIR}/master.key"
SECRET_NAME="$1"

if [ -z "$SECRET_NAME" ]; then
    echo "Usage: $0 <secret_name>" >&2
    exit 1
fi

ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE" 2>/dev/null)
ENCRYPTED_FILE="${SECRETS_DIR}/${SECRET_NAME}.enc"

if [ -f "$ENCRYPTED_FILE" ] && [ -n "$ENCRYPTION_KEY" ]; then
    openssl enc -d -aes-256-cbc -pbkdf2 -salt -pass pass:"$ENCRYPTION_KEY" -in "$ENCRYPTED_FILE"
else
    echo ""
fi