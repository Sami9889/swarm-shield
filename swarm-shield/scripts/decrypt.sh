set -euo pipefail

SECRETS_DIR="${SECRETS_DIR:-/run/secrets/swarm-shield}"
ENCRYPTION_KEY_FILE="${SECRETS_DIR}/master.key"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <secret_name>" >&2
    echo "" >&2
    echo "Available secrets:" >&2
    if [ -d "$SECRETS_DIR" ]; then
        ls -1 "${SECRETS_DIR}"/*.enc 2>/dev/null | xargs -n1 basename | sed 's/.enc$//' >&2
    fi
    exit 1
fi

SECRET_NAME="$1"
ENCRYPTED_FILE="${SECRETS_DIR}/${SECRET_NAME}.enc"

if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo "Error: Encrypted secret not found: ${ENCRYPTED_FILE}" >&2
    exit 1
fi

if [ ! -f "$ENCRYPTION_KEY_FILE" ]; then
    echo "Error: Encryption key not found: ${ENCRYPTION_KEY_FILE}" >&2
    exit 1
fi

ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")

if [ -z "$ENCRYPTION_KEY" ]; then
    echo "Error: Encryption key is empty" >&2
    exit 1
fi

if ! openssl enc -d -aes-256-cbc -pbkdf2 -salt -pass pass:"$ENCRYPTION_KEY" -in "$ENCRYPTED_FILE" 2>/dev/null; then
    echo "Error: Failed to decrypt secret: ${SECRET_NAME}" >&2
    exit 1
fi
