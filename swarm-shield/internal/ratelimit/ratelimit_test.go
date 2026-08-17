package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"swarm-shield/internal/audit"
)

func TestRateLimiter_Allow(t *testing.T) {
	auditLogger := audit.NewLogger(nil)
	limiter := NewRateLimiter(10, 5, time.Minute, auditLogger)
	defer limiter.Stop()

	tests := []struct {
		name     string
		apiKey   string
		allowed  bool
	}{
		{"first_request_allowed", "key1", true},
		{"second_request_allowed", "key1", true},
		{"different_key_allowed", "key2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := limiter.Allow(tt.apiKey)
			if got != tt.allowed {
				t.Errorf("Allow(%q) = %v, want %v", tt.apiKey, got, tt.allowed)
			}
		})
	}
}

func TestRateLimiter_GetRemaining(t *testing.T) {
	auditLogger := audit.NewLogger(nil)
	limiter := NewRateLimiter(10, 5, time.Minute, auditLogger)
	defer limiter.Stop()

	limiter.Allow("key1")
	remaining := limiter.GetRemaining("key1")
	if remaining >= 5.0 {
		t.Errorf("GetRemaining() = %v, want < 5.0", remaining)
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	auditLogger := audit.NewLogger(nil)
	limiter := NewRateLimiter(10, 5, time.Minute, auditLogger)
	defer limiter.Stop()

	limiter.Allow("key1")
	limiter.Reset()

	remaining := limiter.GetRemaining("key1")
	if remaining != 5.0 {
		t.Errorf("GetRemaining() after reset = %v, want 5.0", remaining)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	auditLogger := audit.NewLogger(nil)
	limiter := NewRateLimiter(1000, 100, time.Minute, auditLogger)
	defer limiter.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			apiKey := fmt.Sprintf("key-%d", id%10)
			limiter.Allow(apiKey)
			limiter.GetRemaining(apiKey)
		}(i)
	}
	wg.Wait()
}

func TestRateLimiter_KeyCount(t *testing.T) {
	auditLogger := audit.NewLogger(nil)
	limiter := NewRateLimiter(10, 5, time.Minute, auditLogger)
	defer limiter.Stop()

	if limiter.KeyCount() != 0 {
		t.Errorf("KeyCount() = %d, want 0", limiter.KeyCount())
	}

	limiter.Allow("key1")
	limiter.Allow("key2")
	if limiter.KeyCount() != 2 {
		t.Errorf("KeyCount() = %d, want 2", limiter.KeyCount())
	}
}
