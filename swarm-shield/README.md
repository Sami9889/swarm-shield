# Swarm Shield Enterprise

Production-grade WebRTC P2P swarm mesh with adaptive PoW DDoS protection.

## Quick Install

```bash
# Clone the repository
git clone https://github.com/sami9889/swarm-shield.git
cd swarm-shield

# Run the installer
bash scripts/install.sh
```

## One-Command Setup

The installer will:
- Install Go 1.22+
- Install Node.js 20+
- Install Docker & Docker Compose
- Install Helm (for Kubernetes)
- Download Go dependencies
- Install npm dependencies
- Create `.env` configuration file

## npm Commands

```bash
npm run generate-api-key    # Generate swarm-... API key
npm run dev                 # Run locally with Go
npm run build               # Build Docker image
npm run start:compose       # Full stack via Docker Compose
npm run stop:compose        # Stop Docker Compose stack
npm run test                # Run Go tests
npm run lint                # Format and vet Go code
npm run helm:install        # Deploy to Kubernetes
npm run helm:upgrade        # Upgrade Kubernetes deployment
npm run helm:uninstall      # Remove from Kubernetes
```

## Quick Start

### Local Development
```bash
npm run dev
# Open http://localhost:8080
```

### Generate API Key
```bash
npm run generate-api-key
# Output: swarm-0f6b3ee00af4aaeba58296aac7a1cca4b0fc3ba12feb2d8d
```

### Docker Compose (Full Stack)
```bash
npm run start:compose
# Includes: swarm-shield + Redis + Postgres + Prometheus + Grafana
```

### Kubernetes
```bash
npm run helm:install
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/challenge` | GET | No | Get PoW challenge |
| `/api/verify` | POST | No | Verify PoW solution |
| `/api/auth/login` | POST | No | Sign in with API key |
| `/api/auth/keys` | GET | JWT | List API keys |
| `/api/auth/keys` | POST | JWT | Generate API key |
| `/api/data` | GET | API Key / JWT | Fetch data (P2P-first) |
| `/api/peers` | GET | No | List swarm peers |
| `/api/signal` | POST | No | WebRTC signaling |
| `/api/stats` | GET | No | Server statistics |
| `/ws` | WS | No | WebSocket signaling |
| `/healthz` | GET | No | Health check |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      swarm-shield                           │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   PoW       │  │   Auth       │  │   Rate Limiter   │  │
│  │   Engine    │  │   (JWT)      │  │   (Token Bucket) │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘  │
│         │                │                   │            │
│  ┌──────┴────────────────┴───────────────────┴─────────┐  │
│  │              Enterprise Middleware Chain              │  │
│  │  Metrics → Rate Limit → Auth → Handler              │  │
│  └───────────────────────┬─────────────────────────────┘  │
│                          │                                │
│  ┌─────────────┐  ┌──────┴──────┐  ┌──────────────────┐  │
│  │   WebRTC    │  │   P2P       │  │   PostgreSQL     │  │
│  │   Mesh      │  │   Mesh      │  │   (Persistence)  │  │
│  └─────────────┘  └─────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Listen port |
| `HOST` | `0.0.0.0` | Listen address |
| `JWT_SECRET` | auto-generated | JWT signing secret |
| `REDIS_ENABLED` | `false` | Enable Redis |
| `POSTGRES_ENABLED` | `false` | Enable PostgreSQL |
| `RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `METRICS_ENABLED` | `true` | Enable Prometheus metrics |

## License

MIT
