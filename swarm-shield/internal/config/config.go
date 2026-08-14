package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all enterprise configuration.
type Config struct {
	Server     ServerConfig
	Auth       AuthConfig
	CORS       CORSConfig
	WebSocket  WebSocketConfig
	Redis      RedisConfig
	Postgres   PostgresConfig
	RateLimit  RateLimitConfig
	Metrics    MetricsConfig
	TLS        TLSConfig
	Features   FeatureFlags
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host            string
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	MaxRequestSize  int64
	RequestTimeout  time.Duration
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	JWTSecret       string
	JWTExpiry       time.Duration
	Issuer          string
	Audience        string
	APIKeyRateLimit int
	EnableMTLS      bool
	MTLS            certConfig
}

// certConfig holds certificate paths.
type certConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	AllowedOrigins []string
}

// WebSocketConfig holds WebSocket configuration.
type WebSocketConfig struct {
	AllowedOrigins []string
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Enabled  bool
	Addr     string
	Password string
	DB       int
}

// PostgresConfig holds PostgreSQL connection configuration.
type PostgresConfig struct {
	Enabled    bool
	URL        string
	MaxConns   int
	IdleConns  int
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled           bool
	RequestsPerMinute int
	BurstSize         int
	TTL               time.Duration
}

// MetricsConfig holds metrics configuration.
type MetricsConfig struct {
	Enabled  bool
	Endpoint string
	Path     string
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

// FeatureFlags holds feature flags.
type FeatureFlags struct {
	EnableP2P       bool
	EnablePoW       bool
	EnableWebSocket bool
	EnableAuditLog  bool
	EnableMetrics   bool
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:            getEnv("HOST", "0.0.0.0"),
			Port:            getEnv("PORT", "8080"),
			ReadTimeout:     getDurationEnv("READ_TIMEOUT", 5*time.Second),
			WriteTimeout:    getDurationEnv("WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:     getDurationEnv("IDLE_TIMEOUT", 30*time.Second),
			MaxRequestSize:  getInt64Env("MAX_REQUEST_SIZE", 1<<20), // 1MB default.
			RequestTimeout:  getDurationEnv("REQUEST_TIMEOUT", 15*time.Second),
		},
		Auth: AuthConfig{
			JWTSecret:       os.Getenv("JWT_SECRET"),
			JWTExpiry:       getDurationEnv("JWT_EXPIRY", 24*time.Hour),
			Issuer:          getEnv("JWT_ISSUER", "swarm-shield"),
			Audience:        getEnv("JWT_AUDIENCE", "swarm-shield-api"),
			APIKeyRateLimit: getIntEnv("API_KEY_RATE_LIMIT", 100),
			EnableMTLS:      getBoolEnv("ENABLE_MTLS", false),
			MTLS: certConfig{
				CertFile: getEnv("MTLS_CERT_FILE", "/etc/certs/tls.crt"),
				KeyFile:  getEnv("MTLS_KEY_FILE", "/etc/certs/tls.key"),
				CAFile:   getEnv("MTLS_CA_FILE", "/etc/certs/ca.crt"),
			},
		},
		CORS: CORSConfig{
			AllowedOrigins: getStringSliceEnv("CORS_ALLOWED_ORIGINS", []string{"*"}),
		},
		WebSocket: WebSocketConfig{
			AllowedOrigins: getStringSliceEnv("WS_ALLOWED_ORIGINS", []string{"*"}),
		},
		Redis: RedisConfig{
			Enabled:  getBoolEnv("REDIS_ENABLED", false),
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       getIntEnv("REDIS_DB", 0),
		},
		Postgres: PostgresConfig{
			Enabled:   getBoolEnv("POSTGRES_ENABLED", false),
			URL:       os.Getenv("DATABASE_URL"),
			MaxConns:  getIntEnv("DB_MAX_CONNS", 25),
			IdleConns: getIntEnv("DB_IDLE_CONNS", 5),
		},
		RateLimit: RateLimitConfig{
			Enabled:           getBoolEnv("RATE_LIMIT_ENABLED", true),
			RequestsPerMinute: getIntEnv("RATE_LIMIT_RPM", 120),
			BurstSize:         getIntEnv("RATE_LIMIT_BURST", 20),
			TTL:               getDurationEnv("RATE_LIMIT_TTL", 1*time.Minute),
		},
		Metrics: MetricsConfig{
			Enabled:  getBoolEnv("METRICS_ENABLED", true),
			Endpoint: getEnv("METRICS_ENDPOINT", "0.0.0.0"),
			Path:     getEnv("METRICS_PATH", "/metrics"),
		},
		TLS: TLSConfig{
			Enabled:  getBoolEnv("TLS_ENABLED", false),
			CertFile: getEnv("TLS_CERT_FILE", "/etc/ssl/certs/tls.crt"),
			KeyFile:  getEnv("TLS_KEY_FILE", "/etc/ssl/private/tls.key"),
		},
		Features: FeatureFlags{
			EnableP2P:       getBoolEnv("FEATURE_P2P", true),
			EnablePoW:       getBoolEnv("FEATURE_POW", true),
			EnableWebSocket: getBoolEnv("FEATURE_WEBSOCKET", true),
			EnableAuditLog:  getBoolEnv("FEATURE_AUDIT_LOG", true),
			EnableMetrics:   getBoolEnv("FEATURE_METRICS", true),
		},
	}
}

// Addr returns the full server address.
func (c *Config) Addr() string {
	return c.Server.Host + ":" + c.Server.Port
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getIntEnv(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getInt64Env(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultVal
}

func getBoolEnv(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultVal
}

func getDurationEnv(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func getStringSliceEnv(key string, defaultVal []string) []string {
	if val := os.Getenv(key); val != "" {
		return strings.Split(val, ",")
	}
	return defaultVal
}
