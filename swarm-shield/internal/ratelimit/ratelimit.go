package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"swarm-shield/internal/audit"
	"swarm-shield/internal/load"
)

type RateLimiter struct {
	mu           sync.RWMutex
	buckets      map[string]*tokenBucket
	limit        int
	burst        int
	ttl          time.Duration
	audit        *audit.Logger
	stopChan     chan struct{}
	stopOnce     sync.Once
	loadMonitor  *load.Monitor
	adaptiveMode bool
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
	apiKey   string
}

func NewRateLimiter(limit, burst int, ttl time.Duration, audit *audit.Logger) *RateLimiter {
	return NewRateLimiterWithLoad(limit, burst, ttl, audit, nil, false)
}

func NewRateLimiterWithLoad(limit, burst int, ttl time.Duration, audit *audit.Logger, loadMonitor *load.Monitor, adaptiveMode bool) *RateLimiter {
	if limit <= 0 {
		limit = 120
	}
	if burst <= 0 {
		burst = 20
	}
	if ttl <= 0 {
		ttl = time.Minute
	}

	rl := &RateLimiter{
		buckets:      make(map[string]*tokenBucket),
		limit:        limit,
		burst:        burst,
		ttl:          ttl,
		audit:        audit,
		stopChan:     make(chan struct{}),
		loadMonitor:  loadMonitor,
		adaptiveMode: adaptiveMode,
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) effectiveLimit() int {
	if !rl.adaptiveMode || rl.loadMonitor == nil || !rl.loadMonitor.IsOverloaded() {
		return rl.limit
	}

	maxConns := float64(rl.loadMonitor.MaxActiveConnections())
	if maxConns <= 0 {
		maxConns = 10000
	}

	overloadFactor := float64(rl.loadMonitor.ActiveConnections()) / maxConns
	if overloadFactor > 1.0 {
		overloadFactor = 1.0
	}

	reduced := int(float64(rl.limit) * (1.0 - overloadFactor*0.5))
	if reduced < 1 {
		reduced = 1
	}
	return reduced
}

func (rl *RateLimiter) Allow(apiKey string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[apiKey]

	if !exists {
		rl.buckets[apiKey] = &tokenBucket{
			tokens:   float64(rl.burst),
			lastTime: now,
			apiKey:   apiKey,
		}
		return true
	}

	elapsed := now.Sub(bucket.lastTime).Seconds()
	effectiveLimit := float64(rl.effectiveLimit())
	refillRate := effectiveLimit / 60.0
	bucket.tokens += elapsed * refillRate
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}
	bucket.lastTime = now

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	if rl.audit != nil {
		rl.audit.LogRateLimitHit(apiKey, "", "")
	}
	return false
}

func (rl *RateLimiter) GetRemaining(apiKey string) float64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.buckets[apiKey]
	if !exists {
		return float64(rl.burst)
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastTime).Seconds()
	refillRate := float64(rl.effectiveLimit()) / 60.0
	tokens := bucket.tokens + elapsed*refillRate
	if tokens > float64(rl.burst) {
		tokens = float64(rl.burst)
	}
	return tokens
}

func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*tokenBucket)
}

func (rl *RateLimiter) KeyCount() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.buckets)
}

func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopChan)
	})
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for apiKey, bucket := range rl.buckets {
				if now.Sub(bucket.lastTime) > rl.ttl*2 {
					delete(rl.buckets, apiKey)
				}
			}
			if rl.limit > 0 && len(rl.buckets) > rl.limit*10 {
				rl.evictOldest()
			}
			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

func (rl *RateLimiter) evictOldest() {
	if len(rl.buckets) == 0 {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	for apiKey, bucket := range rl.buckets {
		if oldestKey == "" || bucket.lastTime.Before(oldestTime) {
			oldestKey = apiKey
			oldestTime = bucket.lastTime
		}
	}
	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
	}
}

func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) > 7 {
				apiKey = authHeader[7:]
			}
		}

		if len(apiKey) > 256 {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error": "invalid API key length"}`, http.StatusBadRequest)
			return
		}

		if apiKey != "" && !rl.Allow(apiKey) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	}
}
