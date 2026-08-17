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
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"swarm-shield/internal/audit"
	"swarm-shield/internal/auth"
	"swarm-shield/internal/config"
	"swarm-shield/internal/load"
	"swarm-shield/internal/metrics"
	"swarm-shield/internal/pow"
	"swarm-shield/internal/ratelimit"
	"swarm-shield/internal/security"
	"swarm-shield/internal/signaling"
	"swarm-shield/internal/storage"
	"swarm-shield/internal/lang"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		CheckOrigin:      checkWebSocketOrigin,
		EnableCompression: true,
	}

	cfg           *config.Config
	logger        *zap.Logger
	auditLogger   *audit.Logger
	metricTracker *metrics.Metrics
	rateLimiter   *ratelimit.RateLimiter
	store         *storage.Store
	loadMonitor   *load.Monitor

	validator      = pow.NewValidator()
	difficultyCalc = pow.NewDifficultyCalculator()
	signalingStore = signaling.NewSignalingStore(5 * time.Minute)
	authManager    *auth.Manager

	totalRequests   uint64
	activePoWProofs uint64
	p2pHits         uint64
	originHits      uint64
)

func checkWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	if origin == "http://"+r.Host || origin == "https://"+r.Host {
		return true
	}

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

type APIServer struct {
	server *http.Server
}

func NewAPIServer(cfg *config.Config, auditLogger *audit.Logger, metricTracker *metrics.Metrics, rateLimiter *ratelimit.RateLimiter, loadMonitor *load.Monitor) *APIServer {
	mux := http.NewServeMux()

	s := &APIServer{
		server: &http.Server{
			Addr:         cfg.Addr(),
			Handler:      mux,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
			IdleTimeout:  cfg.Server.IdleTimeout,
			MaxHeaderBytes: 1 << 20,
		},
	}

	challengeHandler := http.HandlerFunc(s.handleChallenge)
	verifyHandler := http.HandlerFunc(s.handleVerify)
	registerHandler := http.HandlerFunc(s.handleRegister)
	signalHandler := http.HandlerFunc(s.handleSignal)
	peersHandler := http.HandlerFunc(s.handlePeers)
	loginHandler := http.HandlerFunc(s.handleLogin)
	keysHandler := authManager.AuthMiddleware(http.HandlerFunc(s.handleKeys))
	dataHandler := authManager.AuthMiddleware(rateLimiter.RateLimitMiddleware(loadAwareHandler(metricTracker, loadMonitor, http.HandlerFunc(s.handleData))))
	statsHandler := http.HandlerFunc(s.handleStats)
	wsHandler := http.HandlerFunc(s.handleWebSocket)
	healthHandler := http.HandlerFunc(s.handleHealth)

	secureHeaders := security.SecureHeadersMiddleware
	cors := security.NewCORSMiddleware(cfg.CORS.AllowedOrigins).Middleware
	requestSizeLimit := security.RequestSizeMiddleware(cfg.Server.MaxRequestSize)
	timeout := security.TimeoutMiddleware(cfg.Server.RequestTimeout)
	recovery := security.RecoveryMiddleware
	requestID := security.RequestIDMiddleware

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
	mux.Handle("/", requestID(secureHeaders(cors(http.FileServer(http.Dir("./public"))))))

	return s
}

func loadAwareHandler(metrics *metrics.Metrics, monitor *load.Monitor, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !monitor.AllowRequest() {
			metrics.LoadSheddingRejects.Inc()
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "server overloaded",
				"message": "server is under heavy load, retry later",
			})
			return
		}
		defer monitor.ReleaseConnection()

		next.ServeHTTP(w, r)

		if r.URL.Path == "/api/data" {
			monitor.RecordSuccess()
		}
	})
}

func (s *APIServer) Start() error {
	logger.Info("swarm-shield listening", zap.String("addr", s.server.Addr))
	return s.server.ListenAndServe()
}

func (s *APIServer) Shutdown(ctx context.Context) error {
	signalingStore.Stop()
	rateLimiter.Stop()
	return s.server.Shutdown(ctx)
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		ip := strings.TrimSpace(ips[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func requestID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

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

func (s *APIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := signalingStore.MarshalPeers()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"peers": peers,
		"count": len(peers),
	})
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	if !rateLimiter.Allow("login:" + clientIP) {
		auditLogger.LogRateLimitHit("", clientIP, "/api/auth/login")
		respondError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}

	authManager.HandleLogin(w, r)
}

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

func (s *APIServer) handleData(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

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

func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"totalRequests":    atomic.LoadUint64(&totalRequests),
		"activePowProofs": atomic.LoadUint64(&activePoWProofs),
		"p2pHits":          atomic.LoadUint64(&p2pHits),
		"originHits":       atomic.LoadUint64(&originHits),
		"currentRPS":       difficultyCalc.GetCurrentRPS(),
		"currentDifficulty": difficultyCalc.CalculateDifficulty(),
		"peerCount":        signalingStore.PeerCount(),
	}

	if loadMonitor != nil {
		for k, v := range loadMonitor.Stats() {
			stats[k] = v
		}
	}

	respondJSON(w, http.StatusOK, stats)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if loadMonitor != nil && loadMonitor.IsOverloaded() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "overloaded",
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *APIServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Query().Get("peerId")
	if peerID == "" {
		peerID = generateID()
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("websocket upgrade failed", zap.Error(err), zap.String("remote", r.RemoteAddr))
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := conn.WriteMessage(websocket.PingMessage, []byte("keepalive")); err != nil {
				return
			}
		}
	}()

	signalingStore.RegisterPeer(peerID)
	logger.Info("websocket connected", zap.String("peerId", peerID), zap.String("remote", r.RemoteAddr))

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

func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

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

func maskIP(ip string) string {
	if ip == "" {
		return ""
	}
	if len(ip) > 8 {
		return ip[:8] + "****"
	}
	return "****"
}

func generateID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 16)))[:16]
	}
	return hex.EncodeToString(buf)
}

func main() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("[FATAL] failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	cfg = config.Load()

	auditLogger = audit.NewLogger(logger)

	metricTracker = metrics.NewMetrics()

	loadMonitor = load.NewMonitor(load.DefaultConfig())

	authManager = auth.NewManager(cfg.Auth.JWTSecret, cfg.Auth.JWTExpiry, cfg.Auth.Issuer, cfg.Auth.Audience)

	difficultyCalc = pow.NewDifficultyCalculatorWithLoad(loadMonitor)

	rateLimiter = ratelimit.NewRateLimiterWithLoad(
		cfg.RateLimit.RequestsPerMinute,
		cfg.RateLimit.BurstSize,
		cfg.RateLimit.TTL,
		auditLogger,
		loadMonitor,
		cfg.Load.Enabled,
	)
	defer rateLimiter.Stop()

	policyRegistry := lang.NewRegistry()
	if err := policyRegistry.LoadDir("./policies"); err != nil {
		logger.Warn("failed to load SwarmScript policies", zap.Error(err))
	}

	var storageErr error
	if cfg.Postgres.Enabled && cfg.Postgres.URL != "" {
		store, storageErr = storage.NewStore(cfg.Postgres.URL, cfg.Postgres.MaxConns, cfg.Postgres.IdleConns)
		if storageErr != nil {
			logger.Warn("failed to initialize storage, running without persistence", zap.Error(err))
		} else {
			defer store.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := store.Ping(ctx); err != nil {
				logger.Warn("database ping failed, running without persistence", zap.Error(err))
			}
			cancel()
		}
	}

	server := NewAPIServer(cfg, auditLogger, metricTracker, rateLimiter, loadMonitor)
		loadMonitor,
		cfg.Load.Enabled,

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

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if metricTracker.ServerGoroutines != nil {
				metricTracker.ServerGoroutines.Set(float64(runtime.NumGoroutine()))
			}
			if loadMonitor != nil && metricTracker.CircuitBreakerState != nil {
				state := float64(loadMonitor.State())
				metricTracker.CircuitBreakerState.Set(state)
			}
		}
	}()

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
