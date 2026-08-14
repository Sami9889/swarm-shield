# Stage 1: Build
FROM golang:1.22-alpine AS builder

# Install build dependencies.
RUN apk add --no-cache git ca-certificates tzdata openssl

WORKDIR /build

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source code.
COPY main.go ./
COPY internal/ ./internal/

# Build static binary with CGO disabled and full optimizations.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags=-static -buildid=" \
    -trimpath \
    -o /swarm-shield \
    main.go

# Stage 2: Minimal final image with shell for entrypoint
FROM alpine:3.19

# Install ca-certificates, tzdata, and openssl for secret decryption
RUN apk add --no-cache ca-certificates tzdata openssl

WORKDIR /app

# Copy CA certificates for TLS.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the static binary.
COPY --from=builder /swarm-shield /swarm-shield

# Copy entrypoint script.
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose ports.
EXPOSE 8080 9090

# Health check.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --spider -q http://localhost:8080/healthz || exit 1

# Entrypoint that decrypts secrets before starting.
ENTRYPOINT ["/entrypoint.sh"]
