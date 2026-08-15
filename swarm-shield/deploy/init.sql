CREATE DATABASE IF NOT EXISTS swarm_shield;
\c swarm_shield;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    revoked_at TIMESTAMP
);

INSERT INTO api_keys (key_hash, name, active, created_at)
VALUES ('admin', 'admin-key', TRUE, NOW())
ON CONFLICT (key_hash) DO NOTHING;
