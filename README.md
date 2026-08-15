# Swarm Shield

A production-grade WebRTC P2P swarm mesh with adaptive PoW DDoS protection.

## Quick Start with Docker Compose

### 1. Set Up Encrypted Credentials

```bash
cd swarm-shield
./scripts/setup.sh
```

This will prompt you for:
- **JWT Secret** (or press Enter to auto-generate)
- **PostgreSQL Password**
- **Redis Password** (optional, press Enter for no auth)
- **Grafana Admin Password**

Credentials are encrypted with AES-256-CBC and stored in `secrets/`.

### 2. Start Services

**Using encrypted secrets (secure):**
```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

**Using plaintext .env (simpler):**
```bash
cp .env.example .env  # or use the one created by setup.sh
docker compose -f deploy/docker-compose.yml up -d
```

Or from npm:
```bash
npm run start:compose
```

## Service Access

| Service        | URL                        | Default Credentials             |
|----------------|----------------------------|---------------------------------|
| Swarm Shield API | http://localhost:8080      | N/A (set JWT_SECRET)            |
| Grafana        | http://localhost:3000        | admin / GRAFANA_PASSWORD        |
| Prometheus     | http://localhost:9091        | None                            |
| Redis          | localhost:6379               | REDIS_PASSWORD (optional)       |
| PostgreSQL     | localhost:5432               | POSTGRES_USER / POSTGRES_PASSWORD |

## Configuration

All credentials are set in the `.env` file or stored encrypted in `secrets/`.

### Credentials (set in .env)

- **JWT_SECRET** — Generate with: `openssl rand -hex 32`
- **POSTGRES_USER** — PostgreSQL username (default: `swarm`)
- **POSTGRES_PASSWORD** — PostgreSQL password (default: `swarm_password`)
- **REDIS_PASSWORD** — Redis auth password (empty = no auth)
- **GRAFANA_PASSWORD** — Grafana admin password (default: `admin`)

## Development

```bash
npm run dev      # Start Go server (from repo root)
npm run build    # Build Docker image
npm test         # Run tests
npm run lint     # Format and lint Go code
```

## Legal

**Copyright © 2026 Samrath Singh. All rights reserved.**

ABN: 72 925 087 373  
Point Cook, VIC, Australia

This project is open source and available under the Apache License 2.0.
See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome. Please ensure all commits are signed off and
follow the project's code style. For major changes, open an issue first
to discuss what you would like to change.

<environment_details>
Current time: 2026-08-15T10:59:36+00:00
Working directory: /workspace/1254b264-94a7-4c61-a6f4-5348c476bcdc/sessions/agent_538cbf09-2cf3-4ec7-8302-f57c5181d61b
Workspace root folder: /workspace/1254b264-94a7-4c61-a6f4-5348c476bcdc/sessions/agent_538cbf09-2cf3-4ec7-8302-f57c5181d61b
</environment_details>
