package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	RequestsTotal            prometheus.Counter
	RequestDuration          prometheus.Histogram
	ActiveConnections        prometheus.Gauge
	PoWVerified              prometheus.Counter
	P2PConnections           prometheus.Gauge
	RateLimitHits            prometheus.Counter
	AuthFailures             prometheus.Counter
	ActivePeers              prometheus.Gauge
	OriginFetches            prometheus.Counter
	WebSocketMessages        prometheus.Counter
	CircuitBreakerState      prometheus.Gauge
	ServerGoroutines         prometheus.Gauge
	LoadSheddingRejects      prometheus.Counter
	ConsensusBlocks          prometheus.Counter
	ConsensusGossipMessages  prometheus.Counter
	ConsensusPeerScore       prometheus.Gauge
	ConsensusDecayedIPs      prometheus.Counter
	AuthJWTValidationFailures prometheus.Counter
	ConfigReloads            prometheus.Counter
	ActivePowChallenges      prometheus.Gauge
	RequestBodyBytes         prometheus.Histogram
	ResponseBodyBytes        prometheus.Histogram
	WebSocketDuration        prometheus.Histogram
	PowChallengeDuration     prometheus.Histogram
	BotDetected              prometheus.Counter
	APIVersionRequests       *prometheus.CounterVec
	JWTValidationFailures    *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	m := &Metrics{}

	m.RequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_requests_total",
		Help: "Total number of HTTP requests processed",
	})

	m.RequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "swarm_shield_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	})

	m.ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_active_connections",
		Help: "Number of active HTTP connections",
	})

	m.PoWVerified = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_pow_verified_total",
		Help: "Total number of verified PoW solutions",
	})

	m.P2PConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_p2p_connections",
		Help: "Number of active P2P connections",
	})

	m.RateLimitHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_rate_limit_hits_total",
		Help: "Total number of rate limit hits",
	})

	m.AuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_auth_failures_total",
		Help: "Total number of authentication failures",
	})

	m.ActivePeers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_active_peers",
		Help: "Number of active peers in the swarm mesh",
	})

	m.OriginFetches = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_origin_fetches_total",
		Help: "Total number of origin fetches",
	})

	m.WebSocketMessages = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_websocket_messages_total",
		Help: "Total number of WebSocket messages processed",
	})

	m.CircuitBreakerState = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_circuit_breaker_state",
		Help: "Circuit breaker state: 0=closed, 1=open, 2=half-open",
	})

	m.ServerGoroutines = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_server_goroutines",
		Help: "Current number of goroutines in the server process",
	})

	m.LoadSheddingRejects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_load_shedding_rejects_total",
		Help: "Total number of requests rejected due to server overload",
	})

	m.ConsensusBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_consensus_blocks_total",
		Help: "Total number of IPs blocked by consensus decision",
	})

	m.ConsensusGossipMessages = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_consensus_gossip_messages_total",
		Help: "Total number of gossip messages exchanged",
	})

	m.ConsensusPeerScore = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_consensus_peer_score",
		Help: "Current consensus peer score",
	})

	m.ConsensusDecayedIPs = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_consensus_decayed_ips_total",
		Help: "Total number of IPs whose reputation score was decayed",
	})

	m.AuthJWTValidationFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_auth_jwt_validation_failures_total",
		Help: "Total number of JWT validation failures",
	})

	m.ConfigReloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_config_reloads_total",
		Help: "Total number of configuration reloads",
	})

	m.ActivePowChallenges = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "swarm_shield_active_pow_challenges",
		Help: "Current number of active PoW challenges",
	})

	m.RequestBodyBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "swarm_shield_request_body_bytes",
		Help:    "HTTP request body size in bytes",
		Buckets: prometheus.ExponentialBuckets(64, 2, 10),
	})

	m.ResponseBodyBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "swarm_shield_response_body_bytes",
		Help:    "HTTP response body size in bytes",
		Buckets: prometheus.ExponentialBuckets(64, 2, 10),
	})

	m.WebSocketDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "swarm_shield_websocket_duration_seconds",
		Help:    "WebSocket connection duration in seconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	})

	m.PowChallengeDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "swarm_shield_pow_challenge_duration_seconds",
		Help:    "PoW challenge generation duration in seconds",
		Buckets: prometheus.DefBuckets,
	})

	m.BotDetected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "swarm_shield_bot_detected_total",
		Help: "Total number of bot-like requests detected",
	})

	m.APIVersionRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "swarm_shield_api_version_requests_total",
		Help: "Total requests by API version",
	}, []string{"version"})

	m.JWTValidationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "swarm_shield_auth_jwt_validation_failures_total",
		Help: "Total number of JWT validation failures by reason",
	}, []string{"reason"})

	return m
}
}

func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.ActiveConnections.Inc()
		m.RequestsTotal.Inc()

		if r.ContentLength > 0 {
			m.RequestBodyBytes.Observe(float64(r.ContentLength))
		}

		next.ServeHTTP(w, r)

		duration := time.Since(start).Seconds()
		m.RequestDuration.Observe(duration)
		m.ActiveConnections.Dec()
	})
}
