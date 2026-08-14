package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	"swarm-shield/internal/signaling"
	"swarm-shield/internal/storage"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
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

// APIServer represents the high-performance HTTP server.
type APIServer struct {
	server *http.Server
}

// NewAPIServer creates and configures the API server with enterprise middleware.
func NewAPIServer(cfg *config.Config, auditLogger *audit.Logger, metricTracker *metrics.Metrics, rateLimiter *ratelimit.RateLimiter) *APIServer {
	mux := http.NewServeMux()

	s := &APIServer{
		server: &http.Server{
			Addr:         cfg.Addr(),
			Handler:      mux,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
			IdleTimeout:  cfg.Server.IdleTimeout,
		},
	}

	// Build middleware chain.
	var challengeHandler http.Handler = http.HandlerFunc(s.handleChallenge)
	var verifyHandler http.Handler = http.HandlerFunc(s.handleVerify)
	var registerHandler http.Handler = http.HandlerFunc(s.handleRegister)
	var signalHandler http.Handler = http.HandlerFunc(s.handleSignal)
	var peersHandler http.Handler = http.HandlerFunc(s.handlePeers)
	var loginHandler http.Handler = http.HandlerFunc(s.handleLogin)
	var keysHandler http.Handler = authManager.AuthMiddleware(http.HandlerFunc(s.handleKeys))
	var dataHandler http.Handler = authManager.AuthMiddleware(http.HandlerFunc(s.handleData))
	var statsHandler http.Handler = http.HandlerFunc(s.handleStats)
	var wsHandler http.Handler = http.HandlerFunc(s.handleWebSocket)
	var healthHandler http.Handler = http.HandlerFunc(s.handleHealth)

	// Apply middleware chain.
	mux.Handle("/api/challenge", metricTracker.Middleware(challengeHandler))
	mux.Handle("/api/verify", metricTracker.Middleware(verifyHandler))
	mux.Handle("/api/register", metricTracker.Middleware(registerHandler))
	mux.Handle("/api/signal", metricTracker.Middleware(signalHandler))
	mux.Handle("/api/peers", metricTracker.Middleware(peersHandler))
	mux.Handle("/api/auth/login", metricTracker.Middleware(loginHandler))
	mux.Handle("/api/auth/keys", metricTracker.Middleware(keysHandler))
	mux.Handle("/api/data", metricTracker.Middleware(rateLimiter.RateLimitMiddleware(dataHandler)))
	mux.Handle("/api/stats", metricTracker.Middleware(statsHandler))
	mux.Handle("/ws", metricTracker.Middleware(wsHandler))
	mux.Handle("/healthz", healthHandler)
	mux.Handle("/", http.FileServer(http.Dir("./public")))

	return s
}

// Start begins listening for requests.
func (s *APIServer) Start() error {
	log.Printf("[INFO] swarm-shield listening on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *APIServer) Shutdown(ctx context.Context) error {
	signalingStore.Stop()
	return s.server.Shutdown(ctx)
}

// handleChallenge issues a PoW challenge to the requesting client.
func (s *APIServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	difficulty := difficultyCalc.CalculateDifficulty()
	challenge := validator.GenerateChallenge(difficulty)

	log.Printf("[DEBUG] challenge issued token=%s difficulty=%d", challenge.Token, difficulty)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token":      challenge.Token,
		"difficulty": difficulty,
		"timestamp":  challenge.IssuedAt.Unix(),
	})
}

// handleVerify validates a PoW solution submitted by a client.
func (s *APIServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Token     string `json:"token"`
		Nonce     string `json:"nonce"`
		Difficulty int    `json:"difficulty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !validator.Verify(req.Token, req.Nonce, req.Difficulty) {
		respondError(w, http.StatusForbidden, "invalid PoW solution")
		return
	}

	validator.ConsumeChallenge(req.Token)
	atomic.AddUint64(&activePoWProofs, 1)

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
		"peerId":   peer.ID,
		"peers":    peers,
		"serverTime": time.Now().Unix(),
	})
}

// handleSignal processes WebRTC signaling messages (SDP offers/answers, ICE candidates).
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

	switch msg.Type {
	case "offer":
		signalingStore.UpdateOffer(msg.PeerID, msg.SDP)
	case "answer":
		signalingStore.UpdateAnswer(msg.PeerID, msg.SDP)
	case "candidate":
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
// If a connected peer has the data cached, transfer is browser-to-browser (0% server bandwidth).
// Otherwise, after 1.5s timeout, solve PoW, fetch from origin, and broadcast to swarm.
func (s *APIServer) handleData(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&totalRequests, 1)
	difficultyCalc.RecordRequest()

	// Check if any connected peer can serve the requested data via P2P.
	peerID := r.URL.Query().Get("peer")
	if peerID != "" {
		if peer, exists := signalingStore.GetPeer(peerID); exists {
			if peer.WebRTCAnswer != nil || peer.WebRTCOffer != nil {
				// Peer is connected via WebRTC DataChannel.
				// In a full implementation, the client would have already attempted
				// P2P transfer before falling back here. This endpoint serves as
				// the origin-of-last-resort.
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
		challenge := validator.GenerateChallenge(difficulty)
		w.Header().Set("X-PoW-Challenge", challenge.Token)
		w.Header().Set("X-PoW-Difficulty", strconv.Itoa(difficulty))
		respondError(w, http.StatusTooEarly, "PoW challenge required")
		return
	}

	difficulty, _ := strconv.Atoi(difficultyHeader)
	if !validator.Verify(authHeader, nonceHeader, difficulty) {
		respondError(w, http.StatusForbidden, "invalid PoW solution")
		return
	}

	validator.ConsumeChallenge(authHeader)
	atomic.AddUint64(&originHits, 1)

	// In a real deployment, this would fetch from upstream origin.
	// For demonstration, return a generated payload.
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

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WARN] websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Register peer.
	signalingStore.RegisterPeer(peerID)
	log.Printf("[INFO] websocket connected peer=%s", peerID)

	// Read pump: process incoming signaling messages.
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WARN] websocket read error peer=%s: %v", peerID, err)
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
	log.Printf("[INFO] websocket disconnected peer=%s", peerID)
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

// generateID creates a random 16-character hex identifier using crypto/rand.
func generateID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails.
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
	authManager = auth.NewManager(cfg.Auth.JWTSecret, cfg.Auth.JWTExpiry)

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
