#!/bin/bash
set -e

SECRETS_DIR="./secrets"
ENCRYPTION_KEY_FILE="${SECRETS_DIR}/master.key"

mkdir -p "$SECRETS_DIR"

encrypt_secret() {
    local name="$1"
    local value="$2"
    local outfile="${SECRETS_DIR}/${name}.enc"
    
    if [ -z "$value" ]; then
        echo "Skipping $name (empty value)"
        return
    fi
    
    echo -n "$value" | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:"$ENCRYPTION_KEY" -out "$outfile"
    echo "Encrypted $name -> $outfile"
}

# Generate or load master encryption key
if [ -f "$ENCRYPTION_KEY_FILE" ]; then
    ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")
    echo "Loaded existing master key"
else
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    echo "$ENCRYPTION_KEY" > "$ENCRYPTION_KEY_FILE"
    chmod 600 "$ENCRYPTION_KEY_FILE"
    echo "Generated new master key: $ENCRYPTION_KEY_FILE"
fi

echo ""
echo "=== Swarm Shield Setup ==="
echo "Set your credentials (passwords will be encrypted with AES-256-CBC)"
echo ""

read -p "JWT Secret (press Enter to generate): " JWT_SECRET
if [ -z "$JWT_SECRET" ]; then
    JWT_SECRET=$(openssl rand -hex 32)
    echo "Generated JWT Secret: $JWT_SECRET"
fi

read -p "PostgreSQL Password: " POSTGRES_PASSWORD
if [ -z "$POSTGRES_PASSWORD" ]; then
    POSTGRES_PASSWORD="swarm_password"
    echo "Using default: swarm_password"
fi

read -p "Redis Password (press Enter for no auth): " REDIS_PASSWORD

read -p "Grafana Admin Password: " GRAFANA_PASSWORD
if [ -z "$GRAFANA_PASSWORD" ]; then
    GRAFANA_PASSWORD="admin"
    echo "Using default: admin"
fi

read -p "PostgreSQL User [swarm]: " POSTGRES_USER
POSTGRES_USER=${POSTGRES_USER:-swarm}

read -p "PostgreSQL Database [swarm_shield]: " POSTGRES_DB
POSTGRES_DB=${POSTGRES_DB:-swarm_shield}

echo ""
echo "Encrypting credentials..."
encrypt_secret "jwt_secret" "$JWT_SECRET"
encrypt_secret "postgres_password" "$POSTGRES_PASSWORD"
encrypt_secret "redis_password" "$REDIS_PASSWORD"
encrypt_secret "grafana_password" "$GRAFANA_PASSWORD"

# Non-sensitive config
cat > "${SECRETS_DIR}/config.env" << EOF
POSTGRES_USER=$POSTGRES_USER
POSTGRES_DB=$POSTGRES_DB
PORT=8080
REDIS_ENABLED=true
POSTGRES_ENABLED=true
METRICS_ENABLED=true
EOF

echo ""
echo "=== Setup Complete ==="
echo "Credentials stored encrypted in: $SECRETS_DIR/"
echo "Master key: $ENCRYPTION_KEY_FILE (keep this safe!)"
echo ""
echo "To start services: docker compose -f deploy/docker-compose.yml --env-file secrets/config.env up -d"
