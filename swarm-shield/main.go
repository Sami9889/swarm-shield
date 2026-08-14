package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"swarm-shield/internal/audit"
	"swarm-shield/internal/auth"
	"swarm-shield/internal/config"
	"swarm-shield/internal/metrics"
	"swarm-shield/internal/pow"
	"swarm-shield/internal/ratelimit"
	"swarm-shield/internal/security"
	"swarm-shield/internal/signaling"
	"swarm-shield/internal/storage"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		CheckOrigin:      checkWebSocketOrigin,
		EnableCompression: true,
	}

	// Enterprise singleton components.
	cfg           *config.Config
	logger        *zap.Logger
	auditLogger   *audit.Logger
	metricTracker *metrics.Metrics
	rateLimiter   *ratelimit.RateLimiter
	store         *storage.Store

	// Core components.
	validator      = pow.NewValidator()
	difficultyCalc = pow.NewDifficultyCalculator()
	signalingStore = signaling.NewSignalingStore(5 * time.Minute)
	authManager    *auth.Manager

	// Stats.
	totalRequests   uint64
	activePoWProofs uint64
	p2pHits         uint64
	originHits      uint64
)

// checkWebSocketOrigin validates WebSocket upgrade origins.
func checkWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	// Allow same-origin requests.
	if origin == "http://"+r.Host || origin == "https://"+r.Host {
		return true
	}

	// Check against configured allowed origins.
	if cfg != nil && cfg.WebSocket.AllowedOrigins != nil {
		for _, allowed := range cfg.WebSocket.AllowedOrigins {
			if allowed == "*" || allowed == origin {
				return true
			}
		}
	}

	logger.Warn("websocket origin rejected",
		zap.String("origin", origin),
		zap.String("remote", r.RemoteAddr),
	)
	return false
}

// APIServer represents the high-performance HTTP server.
type APIServer struct {
	server *http.Server
}

// NewAPIServer creates and configures the API server with enterprise security middleware.
func NewAPIServer(cfg *config.Config, auditLogger *audit.Logger, metricTracker *metrics.Metrics, rateLimiter *ratelimit.RateLimiter) *APIServer {
	mux := http.NewServeMux()

	s := &APIServer{
		server: &http.Server{
			Addr:         cfg.Addr(),
			Handler:      mux,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
			IdleTimeout:  cfg.Server.IdleTimeout,
			MaxHeaderBytes: 1 << 20, // 1MB max header size.
		},
	}

	// Build handlers.
	challengeHandler := http.HandlerFunc(s.handleChallenge)
	verifyHandler := http.HandlerFunc(s.handleVerify)
	registerHandler := http.HandlerFunc(s.handleRegister)
	signalHandler := http.HandlerFunc(s.handleSignal)
	peersHandler := http.HandlerFunc(s.handlePeers)
	loginHandler := http.HandlerFunc(s.handleLogin)
	keysHandler := authManager.AuthMiddleware(http.HandlerFunc(s.handleKeys))
	dataHandler := authManager.AuthMiddleware(rateLimiter.RateLimitMiddleware(http.HandlerFunc(s.handleData)))
	statsHandler := http.HandlerFunc(s.handleStats)
	wsHandler := http.HandlerFunc(s.handleWebSocket)
	healthHandler := http.HandlerFunc(s.handleHealth)

	// Security middleware chain.
	secureHeaders := security.SecureHeadersMiddleware
	cors := security.NewCORSMiddleware(cfg.CORS.AllowedOrigins).Middleware
	requestSizeLimit := security.RequestSizeMiddleware(cfg.Server.MaxRequestSize)
	timeout := security.TimeoutMiddleware(cfg.Server.RequestTimeout)
	recovery := security.RecoveryMiddleware
	requestID := security.RequestIDMiddleware

	// Apply middleware chain.
	mux.Handle("/api/challenge", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(challengeHandler)))))))
	mux.Handle("/api/verify", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(verifyHandler)))))))
	mux.Handle("/api/register", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(registerHandler)))))))
	mux.Handle("/api/signal", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(signalHandler)))))))
	mux.Handle("/api/peers", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(peersHandler)))))))
	mux.Handle("/api/auth/login", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(loginHandler)))))))
	mux.Handle("/api/auth/keys", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(keysHandler)))))))
	mux.Handle("/api/data", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(dataHandler)))))))
	mux.Handle("/api/stats", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(statsHandler)))))))
	mux.Handle("/ws", requestID(secureHeaders(cors(requestSizeLimit(timeout(metricTracker.Middleware(recovery(wsHandler))))))))
	mux.Handle("/healthz", requestID(secureHeaders(cors(healthHandler))))
	mux.Handle("/", requestID(secureHeaders(cors(http.FileServer(http.Dir("./public")))))

	return s
}

// Start begins listening for requests.
func (s *APIServer) Start() error {
	logger.Info("swarm-shield listening", zap.String("addr", s.server.Addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *APIServer) Shutdown(ctx context.Context) error {
	signalingStore.Stop()
	rateLimiter.Stop()
	return s.server.Shutdown(ctx)
}

// extractClientIP extracts the real client IP from the request.
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (first IP in chain).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		ip := strings.TrimSpace(ips[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Check X-Real-IP header.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// requestID returns a unique request ID for tracing.
func requestID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// handleChallenge issues a PoW challenge bound to the client IP.
func (s *APIServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientIP := extractClientIP(r)
	difficulty := difficultyCalc.CalculateDifficulty()
	challenge := validator.GenerateChallenge(difficulty, clientIP)

	logger.Debug("challenge issued",
		zap.String("token", challenge.Token),
		zap.Int("difficulty", difficulty),
		zap.String("client_ip", maskIP(clientIP)),
	)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token":      challenge.Token,
		"difficulty": difficulty,
		"timestamp":  challenge.IssuedAt.Unix(),
		"expiresIn":  60,
	})
}

// handleVerify validates a PoW solution with IP binding.
func (s *APIServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientIP := extractClientIP(r)

	var req struct {
		Token      string `json:"token"`
		Nonce      string `json:"nonce"`
		Difficulty int    `json:"difficulty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate nonce format (must be hex string).
	if !isValidHexNonce(req.Nonce) {
		respondError(w, http.StatusBadRequest, "invalid nonce format")
		return
	}

	if !validator.Verify(req.Token, req.Nonce, clientIP, req.Difficulty) {
		auditLogger.LogAuthFailure(clientIP, r.URL.Path, "invalid_pow")
		respondError(w, http.StatusForbidden, "invalid PoW solution")
		return
	}

	validator.ConsumeChallenge(req.Token)
	atomic.AddUint64(&activePoWProofs, 1)

	auditLogger.Log(nil, &audit.Event{
		ID:        requestID(),
		Type:      audit.EventPoWVerified,
		IPAddress: maskIP(clientIP),
		Status:    http.StatusOK,
	})

	respondJSON(w, http.StatusOK, map[string]string{
		"status": "accepted",
	})
}

// handleRegister registers a new peer in the signaling mesh.
func (s *APIServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		PeerID string `json:"peerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PeerID == "" {
		req.PeerID = generateID()
	}

	peer := signalingStore.RegisterPeer(req.PeerID)
	peers := signalingStore.GetRandomPeers(5, peer.ID)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"peerId":    peer.ID,
		"peers":     peers,
		"serverTime": time.Now().Unix(),
	})
}

// handleSignal processes WebRTC signaling messages.
func (s *APIServer) handleSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var msg signaling.SignalMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		respondError(w, http.StatusBadRequest, "invalid signal message")
		return
	}

	// Validate peer ID format.
	if msg.PeerID == "" || len(msg.PeerID) < 8 {
		respondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	switch msg.Type {
	case "offer":
		if msg.SDP == "" {
			respondError(w, http.StatusBadRequest, "missing SDP offer")
			return
		}
		signalingStore.UpdateOffer(msg.PeerID, msg.SDP)
	case "answer":
		if msg.SDP == "" {
			respondError(w, http.StatusBadRequest, "missing SDP answer")
			return
		}
		signalingStore.UpdateAnswer(msg.PeerID, msg.SDP)
	case "candidate":
		if msg.Candidate == "" {
			respondError(w, http.StatusBadRequest, "missing ICE candidate")
			return
		}
		signalingStore.AddICECandidate(msg.PeerID, msg.Candidate)
	default:
		respondError(w, http.StatusBadRequest, "unknown signal type")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// handlePeers returns the list of known peers for mesh discovery.
func (s *APIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := signalingStore.MarshalPeers()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"peers": peers,
		"count": len(peers),
	})
}

// handleLogin processes sign-in requests and returns a JWT.
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	// Rate limit login attempts per IP.
	if !rateLimiter.Allow("login:" + clientIP) {
		auditLogger.LogRateLimitHit("", clientIP, "/api/auth/login")
		respondError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}

	authManager.HandleLogin(w, r)
}

// handleKeys handles API key operations (GET list, POST generate).
func (s *APIServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := authManager.ListAPIKeys()
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"keys":  keys,
			"count": len(keys),
		})
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Name == "" {
			req.Name = "default"
		}
		key := authManager.GenerateAPIKey(req.Name)
		respondJSON(w, http.StatusCreated, map[string]string{
			"apiKey": key,
			"name":   req.Name,
		})
	default:
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleData serves the primary API payload with P2P mesh-first fallback.
func (s *APIServer) handleData(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	// Check if any connected peer can serve the requested data via P2P.
	peerID := r.URL.Query().Get("peer")
	if peerID != "" {
		if peer, exists := signalingStore.GetPeer(peerID); exists {
			if peer.WebRTCAnswer != nil || peer.WebRTCOffer != nil {
				atomic.AddUint64(&p2pHits, 1)
				respondJSON(w, http.StatusOK, map[string]string{
					"source":   "p2p",
					"peerId":   peer.ID,
					"message":  "data should have been retrieved via DataChannel",
					"payload":  "example-payload-via-p2p",
				})
				return
			}
		}
	}

	// Fallback: Serve from origin with PoW gate.
	authHeader := r.Header.Get("X-PoW-Token")
	nonceHeader := r.Header.Get("X-PoW-Nonce")
	difficultyHeader := r.Header.Get("X-PoW-Difficulty")

	if authHeader == "" || nonceHeader == "" || difficultyHeader == "" {
		difficulty := difficultyCalc.CalculateDifficulty()
		challenge := validator.GenerateChallenge(difficulty, clientIP)
		w.Header().Set("X-PoW-Challenge", challenge.Token)
		w.Header().Set("X-PoW-Difficulty", strconv.Itoa(difficulty))
		respondError(w, http.StatusTooEarly, "PoW challenge required")
		return
	}

	difficulty, _ := strconv.Atoi(difficultyHeader)
	if !validator.Verify(authHeader, nonceHeader, clientIP, difficulty) {
		respondError(w, http.StatusForbidden, "invalid PoW solution")
		return
	}

	validator.ConsumeChallenge(authHeader)
	atomic.AddUint64(&originHits, 1)

	payload := map[string]interface{}{
		"source":    "origin",
		"timestamp": time.Now().Unix(),
		"data":      "swarm-shield-origin-payload",
		"difficulty": difficulty,
	}

	respondJSON(w, http.StatusOK, payload)
}

// handleStats returns live server statistics.
func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"totalRequests":   atomic.LoadUint64(&totalRequests),
		"activePowProofs": atomic.LoadUint64(&activePoWProofs),
		"p2pHits":         atomic.LoadUint64(&p2pHits),
		"originHits":      atomic.LoadUint64(&originHits),
		"currentRPS":      difficultyCalc.GetCurrentRPS(),
		"currentDifficulty": difficultyCalc.CalculateDifficulty(),
		"peerCount":       signalingStore.PeerCount(),
	}
	respondJSON(w, http.StatusOK, stats)
}

// handleHealth is a simple health check endpoint.
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

// handleWebSocket upgrades to a WebSocket connection for real-time signaling.
func (s *APIServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Query().Get("peerId")
	if peerID == "" {
		peerID = generateID()
	}

	// Set WebSocket connection timeouts.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("websocket upgrade failed", zap.Error(err), zap.String("remote", r.RemoteAddr))
		return
	}
	defer conn.Close()

	// Set read/write deadlines.
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Send ping every 30s to keep connection alive.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := conn.WriteMessage(websocket.PingMessage, []byte("keepalive")); err != nil {
				return
			}
		}
	}()

	// Register peer.
	signalingStore.RegisterPeer(peerID)
	logger.Info("websocket connected", zap.String("peerId", peerID), zap.String("remote", r.RemoteAddr))

	// Read pump with max message size.
	conn.SetReadLimit(4096)
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Warn("websocket read error", zap.String("peerId", peerID), zap.Error(err))
			}
			break
		}

		var signal signaling.SignalMessage
		if err := json.Unmarshal(msg, &signal); err != nil {
			continue
		}
		signal.PeerID = peerID

		switch signal.Type {
		case "offer":
			signalingStore.UpdateOffer(peerID, signal.SDP)
		case "answer":
			signalingStore.UpdateAnswer(peerID, signal.SDP)
		case "candidate":
			signalingStore.AddICECandidate(peerID, signal.Candidate)
		}
	}

	signalingStore.RemovePeer(peerID)
	logger.Info("websocket disconnected", zap.String("peerId", peerID))
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// isValidHexNonce validates that a nonce is a valid hex string.
func isValidHexNonce(nonce string) bool {
	if nonce == "" {
		return false
	}
	for _, c := range nonce {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// maskIP masks an IP address for logging (preserves first 3 octets for IPv4).
func maskIP(ip string) string {
	if ip == "" {
		return ""
	}
	// Simple masking: show first 8 chars.
	if len(ip) > 8 {
		return ip[:8] + "****"
	}
	return "****"
}

// generateID creates a random 16-character hex identifier using crypto/rand.
func generateID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 16)))[:16]
	}
	return hex.EncodeToString(buf)
}

func main() {
	// Initialize logger.
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("[FATAL] failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Load configuration.
	cfg = config.Load()

	// Initialize audit logger.
	auditLogger = audit.NewLogger(logger)

	// Initialize metrics.
	metricTracker = metrics.NewMetrics()

	// Initialize auth manager.
	authManager = auth.NewManager(cfg.Auth.JWTSecret, cfg.Auth.JWTExpiry, cfg.Auth.Issuer, cfg.Auth.Audience)

	// Initialize rate limiter.
	rateLimiter = ratelimit.NewRateLimiter(
		cfg.RateLimit.RequestsPerMinute,
		cfg.RateLimit.BurstSize,
		cfg.RateLimit.TTL,
		auditLogger,
	)
	defer rateLimiter.Stop()

	// Initialize storage if enabled.
	var storageErr error
	if cfg.Postgres.Enabled && cfg.Postgres.URL != "" {
		store, storageErr = storage.NewStore(cfg.Postgres.URL, cfg.Postgres.MaxConns, cfg.Postgres.IdleConns)
		if storageErr != nil {
			logger.Warn("failed to initialize storage, running without persistence", zap.Error(storageErr))
		} else {
			defer store.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := store.Ping(ctx); err != nil {
				logger.Warn("database ping failed, running without persistence", zap.Error(err))
			}
			cancel()
		}
	}

	// Create server.
	server := NewAPIServer(cfg, auditLogger, metricTracker, rateLimiter)

	// Log system start.
	auditLogger.Log(nil, &audit.Event{
		ID:     generateID(),
		Type:   audit.EventSystemStart,
		Status: http.StatusOK,
	})

	logger.Info("swarm-shield starting",
		zap.String("addr", cfg.Addr()),
		zap.Bool("redis", cfg.Redis.Enabled),
		zap.Bool("postgres", cfg.Postgres.Enabled),
		zap.Bool("rateLimit", cfg.RateLimit.Enabled),
		zap.Bool("metrics", cfg.Metrics.Enabled),
	)

	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// Wait for interrupt signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	auditLogger.Log(nil, &audit.Event{
		ID:     generateID(),
		Type:   audit.EventSystemStop,
		Status: http.StatusOK,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", zap.Error(err))
	}
	logger.Info("server stopped")
}
