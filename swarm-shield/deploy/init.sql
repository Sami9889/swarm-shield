CREATE DATABASE IF NOT EXISTS swarm_shield;
\c swarm_shield;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

INSERT INTO api_keys (key_hash, name, active, created_at)
VALUES ('admin', 'admin-key', TRUE, NOW())
ON CONFLICT (key_hash) DO NOTHING;
