package load

import (
	"runtime"
	"sync"
	"time"
)

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

type Monitor struct {
	mu                   sync.RWMutex
	state                CircuitState
	openedAt             time.Time
	lastSuccess          time.Time
	failureThreshold     int
	failureCount         int
	successThreshold     int
	successCount         int
	halfOpenMaxRequests  int
	halfOpenRequests     int
	cooldown             time.Duration
	requestTimeout       time.Duration
	maxActiveConnections int
	activeConnections    int32
	goroutineLimit       int
	goroutineWarn        int
	stopChan             chan struct{}
	stopOnce             sync.Once
}

type Config struct {
	FailureThreshold     int
	SuccessThreshold     int
	Cooldown             time.Duration
	RequestTimeout       time.Duration
	MaxActiveConnections int
	HalfOpenMaxRequests  int
	GoroutineLimit       int
	GoroutineWarn        int
}

func DefaultConfig() Config {
	return Config{
		FailureThreshold:     5,
		SuccessThreshold:     2,
		Cooldown:             5 * time.Second,
		RequestTimeout:       500 * time.Millisecond,
		MaxActiveConnections: 10000,
		HalfOpenMaxRequests:  10,
		GoroutineLimit:       50000,
		GoroutineWarn:        20000,
	}
}

func NewMonitor(cfg Config) *Monitor {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = DefaultConfig().FailureThreshold
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = DefaultConfig().SuccessThreshold
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultConfig().Cooldown
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultConfig().RequestTimeout
	}
	if cfg.MaxActiveConnections <= 0 {
		cfg.MaxActiveConnections = DefaultConfig().MaxActiveConnections
	}
	if cfg.HalfOpenMaxRequests <= 0 {
		cfg.HalfOpenMaxRequests = DefaultConfig().HalfOpenMaxRequests
	}
	if cfg.GoroutineLimit <= 0 {
		cfg.GoroutineLimit = DefaultConfig().GoroutineLimit
	}
	if cfg.GoroutineWarn <= 0 {
		cfg.GoroutineWarn = DefaultConfig().GoroutineWarn
	}

	m := &Monitor{
		failureThreshold:     cfg.FailureThreshold,
		successThreshold:     cfg.SuccessThreshold,
		cooldown:             cfg.Cooldown,
		requestTimeout:       cfg.RequestTimeout,
		maxActiveConnections: cfg.MaxActiveConnections,
		halfOpenMaxRequests:  cfg.HalfOpenMaxRequests,
		goroutineLimit:       cfg.GoroutineLimit,
		goroutineWarn:        cfg.GoroutineWarn,
		stopChan:             make(chan struct{}),
	}
	go m.monitorLoop()
	return m
}

func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
}

func (m *Monitor) AllowRequest() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == CircuitOpen {
		if time.Since(m.openedAt) >= m.cooldown {
			m.state = CircuitHalfOpen
			m.halfOpenRequests = 0
			m.successCount = 0
		}
	}

	if m.state == CircuitOpen {
		return false
	}

	if m.state == CircuitHalfOpen {
		if m.halfOpenRequests >= m.halfOpenMaxRequests {
			return false
		}
		m.halfOpenRequests++
	}

	if int32(m.activeConnections) >= int32(m.maxActiveConnections) {
		return false
	}

	m.activeConnections++
	return true
}

func (m *Monitor) RecordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == CircuitHalfOpen {
		m.successCount++
		if m.successCount >= m.successThreshold {
			m.state = CircuitClosed
			m.failureCount = 0
			m.halfOpenRequests = 0
		}
	} else if m.state == CircuitClosed {
		m.failureCount = 0
	}

	m.activeConnections = maxInt32(m.activeConnections-1, 0)
	m.lastSuccess = time.Now()
}

func (m *Monitor) RecordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == CircuitHalfOpen {
		m.state = CircuitOpen
		m.openedAt = time.Now()
		m.halfOpenRequests = 0
		m.successCount = 0
		m.failureCount = 0
	} else if m.state == CircuitClosed {
		m.failureCount++
		if m.failureCount >= m.failureThreshold {
			m.state = CircuitOpen
			m.openedAt = time.Now()
		}
	}

	m.activeConnections = maxInt32(m.activeConnections-1, 0)
}

func (m *Monitor) ReleaseConnection() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeConnections = maxInt32(m.activeConnections-1, 0)
}

func maxInt32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

func (m *Monitor) State() CircuitState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Monitor) ActiveConnections() int32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeConnections
}

func (m *Monitor) IsOverloaded() bool {
	m.mu.RLock()
	state := m.state
	active := m.activeConnections
	goroutines := runtime.NumGoroutine()
	m.mu.RUnlock()

	if state == CircuitOpen {
		return true
	}

	if active >= int32(m.maxActiveConnections) {
		return true
	}

	if goroutines >= m.goroutineLimit {
		return true
	}

	return false
}

func (m *Monitor) MaxActiveConnections() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxActiveConnections
}
	m.mu.RLock()
	state := m.state
	active := m.activeConnections
	failures := m.failureCount
	successes := m.successCount
	m.mu.RUnlock()

	stateStr := "closed"
	switch state {
	case CircuitOpen:
		stateStr = "open"
	case CircuitHalfOpen:
		stateStr = "half-open"
	}

	return map[string]interface{}{
		"state":               stateStr,
		"activeConnections":   active,
		"failureCount":        failures,
		"successCount":        successes,
		"goroutines":          runtime.NumGoroutine(),
		"maxActiveConnections": m.maxActiveConnections,
		"goroutineLimit":      m.goroutineLimit,
		"overloaded":          m.IsOverloaded(),
	}
}

func (m *Monitor) monitorLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			goroutines := runtime.NumGoroutine()
			if goroutines >= m.goroutineWarn && goroutines < m.goroutineLimit {
				m.mu.Lock()
				if m.state == CircuitClosed {
					m.failureCount++
					if m.failureCount >= m.failureThreshold {
						m.state = CircuitOpen
						m.openedAt = time.Now()
					}
				}
				m.mu.Unlock()
			}
		case <-m.stopChan:
			return
		}
	}
}
