package load

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMonitor_AllowRequest(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*Monitor)
		wantAllowed bool
	}{
		{
			name:        "initial_allowed",
			setup:       func(*Monitor) {},
			wantAllowed: true,
		},
		{
			name: "overloaded",
			setup: func(m *Monitor) {
				m.maxActiveConnections = 0
			},
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMonitor(DefaultConfig())
			tt.setup(m)

			got := m.AllowRequest()
			if got != tt.wantAllowed {
				t.Errorf("AllowRequest() = %v, want %v", got, tt.wantAllowed)
			}
			if got {
				m.RecordSuccess()
			}
		})
	}
}

func TestMonitor_RecordFailure(t *testing.T) {
	m := NewMonitor(DefaultConfig())
	m.failureThreshold = 2

	m.AllowRequest()
	m.RecordFailure()
	if m.State() != CircuitClosed {
		t.Errorf("State() = %v, want CircuitClosed", m.State())
	}

	m.AllowRequest()
	m.RecordFailure()
	if m.State() != CircuitOpen {
		t.Errorf("State() = %v, want CircuitOpen", m.State())
	}
}

func TestMonitor_RecordSuccess(t *testing.T) {
	m := NewMonitor(DefaultConfig())
	m.failureThreshold = 1
	m.successThreshold = 2
	m.cooldown = 0

	m.AllowRequest()
	m.RecordFailure()
	if m.State() != CircuitOpen {
		t.Errorf("State() = %v, want CircuitOpen", m.State())
	}

	m.AllowRequest()
	m.RecordSuccess()
	if m.State() != CircuitHalfOpen {
		t.Errorf("State() = %v, want CircuitHalfOpen", m.State())
	}

	m.AllowRequest()
	m.RecordSuccess()
	if m.State() != CircuitClosed {
		t.Errorf("State() = %v, want CircuitClosed", m.State())
	}
}

func TestMonitor_IsOverloaded(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Monitor)
		expected bool
	}{
		{
			name:     "normal",
			setup:    func(*Monitor) {},
			expected: false,
		},
		{
			name: "circuit_open",
			setup: func(m *Monitor) {
				m.mu.Lock()
				m.state = CircuitOpen
				m.mu.Unlock()
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMonitor(DefaultConfig())
			tt.setup(m)

			got := m.IsOverloaded()
			if got != tt.expected {
				t.Errorf("IsOverloaded() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMonitor_ActiveConnections(t *testing.T) {
	m := NewMonitor(DefaultConfig())

	if m.ActiveConnections() != 0 {
		t.Errorf("ActiveConnections() = %d, want 0", m.ActiveConnections())
	}

	m.AllowRequest()
	if m.ActiveConnections() != 1 {
		t.Errorf("ActiveConnections() = %d, want 1", m.ActiveConnections())
	}

	m.RecordSuccess()
	if m.ActiveConnections() != 0 {
		t.Errorf("ActiveConnections() = %d, want 0", m.ActiveConnections())
	}
}

func TestMonitor_ConcurrentAccess(t *testing.T) {
	m := NewMonitor(DefaultConfig())
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.AllowRequest()
			m.RecordSuccess()
			m.RecordFailure()
			m.IsOverloaded()
			m.ActiveConnections()
			m.State()
		}()
	}
	wg.Wait()
}

func TestMonitor_GoroutineWarn(t *testing.T) {
	m := NewMonitor(DefaultConfig())
	m.goroutineWarn = runtime.NumGoroutine() - 1
	m.failureThreshold = 1

	time.Sleep(200 * time.Millisecond)
	if m.State() != CircuitOpen {
		t.Errorf("State() = %v, want CircuitOpen", m.State())
	}
}
