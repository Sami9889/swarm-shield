# Swarm Shield

A production-grade WebRTC P2P swarm mesh with adaptive PoW DDoS protection.

## Quick Start with Docker Compose

```bash
# Edit .env to set your credentials (JWT_SECRET, POSTGRES_PASSWORD, GRAFANA_PASSWORD)
vim .env

# Start all services (Redis, Postgres, Prometheus, Grafana, Swarm Shield)
npm run start:compose

# Or run from the swarm-shield directory directly
cd swarm-shield && npm run start:compose
```

## Service Access

| Service    | URL                        | Default Credentials      |
|------------|----------------------------|--------------------------|
| Swarm Shield API | http://localhost:8080      | N/A (set JWT_SECRET)     |
| Grafana    | http://localhost:3000        | admin / {GRAFANA_PASSWORD} |
| Prometheus | http://localhost:9091        | None                     |
| Redis      | localhost:6379               | {REDIS_PASSWORD} (optional) |
| PostgreSQL | localhost:5432               | swarm / {POSTGRES_PASSWORD} |

## Configuration

All credentials are set in the `.env` file. See `swarm-shield/.env` for available options.

### Default Credentials (set in .env)

- **PostgreSQL**: `POSTGRES_USER=swarm`, `POSTGRES_PASSWORD=swarm_password`, `POSTGRES_DB=swarm_shield`
- **Redis**: `REDIS_PASSWORD=` (empty = no auth)
- **Grafana**: `GF_SECURITY_ADMIN_PASSWORD` = value of `GRAFANA_PASSWORD` (default: `admin`)
- **JWT**: `JWT_SECRET=change-me-in-production`

### Important: Change Default Credentials

1. Generate a strong JWT secret: `openssl rand -hex 32`
2. Set strong passwords in `.env` for PostgreSQL and Grafana
3. Set a Redis password if needed: `REDIS_PASSWORD=your-strong-password`

## Development

```bash
npm run dev      # Start Go server (from repo root)
npm run build    # Build Docker image
npm test         # Run tests
npm run lint     # Format and lint Go code
```
