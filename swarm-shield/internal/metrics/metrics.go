package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	RequestsTotal      prometheus.Counter
	RequestDuration    prometheus.Histogram
	ActiveConnections  prometheus.Gauge
	PoWVerified        prometheus.Counter
	P2PConnections     prometheus.Gauge
	RateLimitHits      prometheus.Counter
	AuthFailures       prometheus.Counter
	ActivePeers        prometheus.Gauge
	OriginFetches      prometheus.Counter
	WebSocketMessages  prometheus.Counter
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

	return m
}

func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.ActiveConnections.Inc()
		m.RequestsTotal.Inc()

		next.ServeHTTP(w, r)

		duration := time.Since(start).Seconds()
		m.RequestDuration.Observe(duration)
		m.ActiveConnections.Dec()
	})
}
