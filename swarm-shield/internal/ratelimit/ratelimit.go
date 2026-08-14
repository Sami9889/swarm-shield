package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"swarm-shield/internal/audit"
)

// RateLimiter provides per-API-key rate limiting using token bucket algorithm.
type RateLimiter struct {
	mu       sync.RWMutex
	buckets  map[string]*tokenBucket
	limit    int
	burst    int
	ttl      time.Duration
	audit    *audit.Logger
	stopChan chan struct{}
	stopOnce sync.Once
}

// tokenBucket represents a rate limit token bucket.
type tokenBucket struct {
	tokens   float64
	lastTime time.Time
	apiKey   string
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(limit, burst int, ttl time.Duration, audit *audit.Logger) *RateLimiter {
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
		buckets:  make(map[string]*tokenBucket),
		limit:    limit,
		burst:    burst,
		ttl:      ttl,
		audit:    audit,
		stopChan: make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks if a request is allowed for the given API key.
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

	// Refill tokens based on time elapsed.
	elapsed := now.Sub(bucket.lastTime).Seconds()
	refillRate := float64(rl.limit) / 60.0 // tokens per second
	bucket.tokens += elapsed * refillRate
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}
	bucket.lastTime = now

	// Check if request is allowed.
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	// Rate limited.
	if rl.audit != nil {
		rl.audit.LogRateLimitHit(apiKey, "", "")
	}
	return false
}

// GetRemaining returns the remaining tokens for an API key.
func (rl *RateLimiter) GetRemaining(apiKey string) float64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.buckets[apiKey]
	if !exists {
		return float64(rl.burst)
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastTime).Seconds()
	refillRate := float64(rl.limit) / 60.0
	tokens := bucket.tokens + elapsed*refillRate
	if tokens > float64(rl.burst) {
		tokens = float64(rl.burst)
	}
	return tokens
}

// Reset clears all rate limit buckets.
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*tokenBucket)
}

// Stop stops the cleanup loop.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopChan)
	})
}

// cleanupLoop periodically removes expired buckets.
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
			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

// RateLimitMiddleware creates HTTP middleware for rate limiting.
func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Try to extract from Authorization header.
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) > 7 {
				apiKey = authHeader[7:]
			}
		}

		if apiKey != "" && !rl.Allow(apiKey) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
