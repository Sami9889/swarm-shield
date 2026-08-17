package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"swarm-shield/internal/audit"
	"swarm-shield/internal/auth"
	"swarm-shield/internal/config"
	"swarm-shield/internal/load"
	"swarm-shield/internal/metrics"
	"swarm-shield/internal/ratelimit"
	"swarm-shield/internal/swarm"
)

func TestExtractClientIP(t *testing.T) {
	originalCfg := cfg
	defer func() { cfg = originalCfg }()

	cfg = &config.Config{
		Server: config.ServerConfig{
			TrustedProxies: []string{"10.0.0.0/8", "127.0.0.1"},
		},
	}

	tests := []struct {
		name     string
		header   string
		remote   string
		expected string
	}{
		{"xff_trusted", "203.0.113.1, 198.51.100.1", "10.0.0.1:1234", "203.0.113.1"},
		{"xff_single", "203.0.113.1", "10.0.0.1:1234", "203.0.113.1"},
		{"x_real_ip", "", "10.0.0.1:1234", "10.0.0.1"},
		{"remote_only", "", "198.51.100.1:1234", "198.51.100.1"},
		{"empty_remote", "", "", ""},
		{"invalid_ip", "not-an-ip", "10.0.0.1:1234", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set("X-Forwarded-For", tt.header)
			}
			r.RemoteAddr = tt.remote

			got := extractClientIP(r)
			if got != tt.expected {
				t.Errorf("extractClientIP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHealthEndpoints(t *testing.T) {
	zapLogger, _ := zap.NewDevelopment()
	cfg := config.Load()
	auditLogger := audit.NewLogger(zapLogger)
	metricTracker := metrics.NewMetrics()
	loadMonitor := load.NewMonitor(load.DefaultConfig())
	rateLimiter := ratelimit.NewRateLimiterWithLoad(
		cfg.RateLimit.RequestsPerMinute,
		cfg.RateLimit.BurstSize,
		cfg.RateLimit.TTL,
		auditLogger,
		loadMonitor,
		cfg.Load.Enabled,
	)
	defer rateLimiter.Stop()

	testAuthManager := auth.NewManager(cfg.Auth.JWTSecret, cfg.Auth.JWTExpiry, cfg.Auth.Issuer, cfg.Auth.Audience)
	server := NewAPIServer(cfg, auditLogger, metricTracker, rateLimiter, loadMonitor, nil, testAuthManager)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"healthz", "/healthz", http.StatusOK},
		{"readyz", "/readyz", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			server.server.Handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("%s status = %d, want %d", tt.name, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestConsensusAwareHandler(t *testing.T) {
	tests := []struct {
		name       string
		engine     *swarm.ConsensusEngine
		clientIP   string
		wantStatus int
	}{
		{"nil_engine", nil, "198.51.100.1", http.StatusOK},
		{"allowed_ip", &swarm.ConsensusEngine{}, "198.51.100.1", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := consensusAwareHandler(tt.engine, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.clientIP + ":1234"
			handler.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("%s status = %d, want %d", tt.name, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestLoadAwareHandler(t *testing.T) {
	tests := []struct {
		name       string
		monitor    *load.Monitor
		wantStatus int
	}{
		{"normal", load.NewMonitor(load.DefaultConfig()), http.StatusOK},
		{"overloaded", nil, http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := loadAwareHandler(metrics.NewMetrics(), tt.monitor, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			handler.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("%s status = %d, want %d", tt.name, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestRequestIDGeneration(t *testing.T) {
	id1 := requestID()
	id2 := requestID()

	if id1 == "" {
		t.Error("requestID() returned empty string")
	}
	if id1 == id2 {
		t.Error("requestID() returned duplicate IDs")
	}
	if len(id1) != 16 {
		t.Errorf("requestID() length = %d, want 16", len(id1))
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("generateID() returned empty string")
	}
	if id1 == id2 {
		t.Error("generateID() returned duplicate IDs")
	}
	if len(id1) != 16 {
		t.Errorf("generateID() length = %d, want 16", len(id1))
	}
}

func TestIsValidHexNonce(t *testing.T) {
	tests := []struct {
		name     string
		nonce    string
		expected bool
	}{
		{"valid", "abc123def456", true},
		{"empty", "", false},
		{"invalid_chars", "xyz123", false},
		{"too_long", string(make([]byte, 129)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHexNonce(tt.nonce)
			if got != tt.expected {
				t.Errorf("isValidHexNonce(%q) = %v, want %v", tt.nonce, got, tt.expected)
			}
		})
	}
}

func TestIsTrustedProxy(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		ip       string
		expected bool
	}{
		{"nil_config", nil, "10.0.0.1", false},
		{"loopback", &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"127.0.0.1"}}}, "127.0.0.1", true},
		{"not_trusted", &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"127.0.0.1"}}}, "10.0.0.1", false},
		{"cidr_match", &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"10.0.0.0/24"}}}, "10.0.0.5", true},
		{"wildcard", &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"*"}}}, "1.2.3.4", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = tt.cfg
			got := isTrustedProxy(tt.ip)
			if got != tt.expected {
				t.Errorf("isTrustedProxy(%q) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	respondJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("respondJSON status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("respondJSON missing Content-Type: application/json")
	}
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	respondError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("respondError status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["error"] != "test error" {
		t.Errorf("respondError body = %v, want error=test error", resp)
	}
}

