# Stage 1: Build
FROM golang:1.22-alpine AS builder

# Install build dependencies.
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source code.
COPY main.go ./
COPY internal/ ./internal/

# Build static binary with CGO disabled.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags=-static" \
    -trimpath \
    -o /swarm-shield \
    main.go

# Stage 2: Scratch
FROM scratch

# Copy CA certificates for TLS.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary.
COPY --from=builder /swarm-shield /swarm-shield

# Expose the API port.
EXPOSE 8080

# Run as non-root user (nobody exists in scratch).
USER 65534:65534

# Health check.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/swarm-shield", "-healthcheck"] || exit 1

# Entrypoint.
ENTRYPOINT ["/swarm-shield"]
