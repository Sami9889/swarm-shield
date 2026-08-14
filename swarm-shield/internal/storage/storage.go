package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Store provides database operations for swarm-shield.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new database store.
func NewStore(databaseURL string, maxConns, idleConns int) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	poolConfig.MaxConns = int32(maxConns)
	poolConfig.MinConns = int32(idleConns)
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.New(context.Background(), poolConfig.ConnString())
	if err != nil {
		return nil, err
	}

	store := &Store{pool: pool}
	if err := store.migrate(context.Background()); err != nil {
		return nil, err
	}

	return store, nil
}

// Close closes the database connection pool.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Ping verifies database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// migrate runs database migrations.
func (s *Store) migrate(ctx context.Context) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS api_keys (
			id SERIAL PRIMARY KEY,
			key_hash VARCHAR(64) UNIQUE NOT NULL,
			name VARCHAR(255) NOT NULL,
			active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT NOW(),
			last_used_at TIMESTAMP,
			revoked_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id SERIAL PRIMARY KEY,
			event_type VARCHAR(100) NOT NULL,
			actor VARCHAR(255),
			api_key_prefix VARCHAR(64),
			endpoint VARCHAR(255),
			method VARCHAR(10),
			status INTEGER,
			duration_ms BIGINT,
			user_agent TEXT,
			ip_address VARCHAR(45),
			metadata JSONB,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS metrics_snapshots (
			id SERIAL PRIMARY KEY,
			total_requests BIGINT,
			pow_verified BIGINT,
			p2p_hits BIGINT,
			origin_hits BIGINT,
			peer_count INTEGER,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_api_key_prefix ON audit_logs(api_key_prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)`,
	}

	for _, stmt := range schema {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}

	return nil
}

// APIKey operations.

// SaveAPIKey persists an API key hash.
func (s *Store) SaveAPIKey(ctx context.Context, keyHash, name string) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO api_keys (key_hash, name) VALUES ($1, $2)",
		keyHash, name)
	return err
}

// RevokeAPIKey marks an API key as revoked.
func (s *Store) RevokeAPIKey(ctx context.Context, keyHash string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE api_keys SET active = FALSE, revoked_at = NOW() WHERE key_hash = $1",
		keyHash)
	return err
}

// UpdateAPIKeyLastUsed updates the last used timestamp.
func (s *Store) UpdateAPIKeyLastUsed(ctx context.Context, keyHash string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1",
		keyHash)
	return err
}

// Audit log operations.

// SaveAuditLog persists an audit log entry.
func (s *Store) SaveAuditLog(ctx context.Context, entry *AuditLogEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs 
		(event_type, actor, api_key_prefix, endpoint, method, status, duration_ms, user_agent, ip_address, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		entry.EventType, entry.Actor, entry.APIKeyPrefix, entry.Endpoint, entry.Method,
		entry.Status, entry.DurationMs, entry.UserAgent, entry.IPAddress, entry.Metadata)
	return err
}

// Metrics operations.

// SaveMetricsSnapshot saves a metrics snapshot.
func (s *Store) SaveMetricsSnapshot(ctx context.Context, snapshot *MetricsSnapshot) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO metrics_snapshots 
		(total_requests, pow_verified, p2p_hits, origin_hits, peer_count)
		VALUES ($1, $2, $3, $4, $5)`,
		snapshot.TotalRequests, snapshot.PoWVerified, snapshot.P2PHits,
		snapshot.OriginHits, snapshot.PeerCount)
	return err
}

// AuditLogEntry represents an audit log database entry.
type AuditLogEntry struct {
	EventType   string
	Actor       string
	APIKeyPrefix string
	Endpoint    string
	Method      string
	Status      int
	DurationMs  int64
	UserAgent   string
	IPAddress   string
	Metadata    map[string]interface{}
}

// MetricsSnapshot represents a metrics database snapshot.
type MetricsSnapshot struct {
	TotalRequests uint64
	PoWVerified   uint64
	P2PHits       uint64
	OriginHits    uint64
	PeerCount     int
}
