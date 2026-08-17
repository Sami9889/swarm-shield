package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"

	"swarm-shield/internal/load"
)

type Challenge struct {
	Token      string
	Difficulty int
	IssuedAt   time.Time
	ClientIP   string
	ExpiresAt  time.Time
}

type Validator struct {
	mu         sync.RWMutex
	challenges map[string]*Challenge
	dedup      map[string]time.Time
}

func NewValidator() *Validator {
	v := &Validator{challenges: make(map[string]*Challenge), dedup: make(map[string]time.Time)}
	go v.cleanupLoop()
	return v
}

func (v *Validator) GenerateChallenge(difficulty int, clientIP string) (*Challenge, error) {
	if difficulty < 1 {
		difficulty = 1
	}
	if difficulty > 6 {
		difficulty = 6
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate challenge token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)
	now := time.Now()

	ch := &Challenge{
		Token:      token,
		Difficulty: difficulty,
		IssuedAt:   now,
		ClientIP:   clientIP,
		ExpiresAt:  now.Add(60 * time.Second),
	}

	v.mu.Lock()
	v.challenges[token] = ch
	v.mu.Unlock()

	return ch, nil
}

func (v *Validator) Verify(token, nonce, clientIP string, difficulty int) bool {
	if difficulty < 1 || difficulty > 6 {
		return false
	}

	dedupKey := token + ":" + nonce
	v.mu.RLock()
	if _, exists := v.dedup[dedupKey]; exists {
		v.mu.RUnlock()
		return false
	}
	v.mu.RUnlock()

	v.mu.RLock()
	challenge, exists := v.challenges[token]
	v.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(challenge.ExpiresAt) {
		v.mu.Lock()
		delete(v.challenges, token)
		v.mu.Unlock()
		return false
	}

	if challenge.ClientIP != "" && clientIP != "" && challenge.ClientIP != clientIP {
		return false
	}

	data := []byte(token + nonce)
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])

	for i := 0; i < difficulty && i < len(hashHex); i++ {
		if hashHex[i] != '0' {
			return false
		}
	}

	v.mu.Lock()
	v.dedup[dedupKey] = time.Now()
	v.mu.Unlock()

	return true
}

func (v *Validator) ConsumeChallenge(token string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.challenges[token]; exists {
		delete(v.challenges, token)
		return true
	}
	return false
}

func (v *Validator) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		v.mu.Lock()
		for token, ch := range v.challenges {
			if now.After(ch.ExpiresAt) {
				delete(v.challenges, token)
			}
		}
		for key, t := range v.dedup {
			if now.Sub(t) > 5*time.Minute {
				delete(v.dedup, key)
			}
		}
		v.mu.Unlock()
	}
}

type DifficultyCalculator struct {
	mu          sync.RWMutex
	rpsBuckets  []uint64
	bucketSize  time.Duration
	windowSize  time.Duration
	lastTick    time.Time
	loadMonitor *load.Monitor
}

func NewDifficultyCalculator() *DifficultyCalculator {
	dc := &DifficultyCalculator{
		rpsBuckets:  make([]uint64, 0),
		bucketSize:  1 * time.Second,
		windowSize:  5 * time.Second,
		lastTick:   time.Now(),
	}
	go dc.tickerLoop()
	return dc
}

func NewDifficultyCalculatorWithLoad(monitor *load.Monitor) *DifficultyCalculator {
	dc := &DifficultyCalculator{
		rpsBuckets:  make([]uint64, 0),
		bucketSize:  1 * time.Second,
		windowSize:  5 * time.Second,
		lastTick:   time.Now(),
		loadMonitor: monitor,
	}
	go dc.tickerLoop()
	return dc
}

func (dc *DifficultyCalculator) RecordRequest() {
	now := time.Now()
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if len(dc.rpsBuckets) == 0 || now.Sub(dc.lastTick) >= dc.bucketSize {
		dc.rpsBuckets = append(dc.rpsBuckets, 1)
		dc.lastTick = now
	} else {
		dc.rpsBuckets[len(dc.rpsBuckets)-1]++
	}
}

func (dc *DifficultyCalculator) CalculateDifficulty() int {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	var total uint64
	for _, count := range dc.rpsBuckets {
		total += count
	}

	rps := float64(total) / dc.windowSize.Seconds()

	difficulty := 1
	switch {
	case rps < 100:
		difficulty = 1
	case rps < 500:
		difficulty = 2
	case rps < 1000:
		difficulty = 3
	case rps < 5000:
		difficulty = 4
	case rps < 20000:
		difficulty = 5
	default:
		difficulty = 6
	}

	if dc.loadMonitor != nil && dc.loadMonitor.IsOverloaded() {
		difficulty = difficulty + 2
		if difficulty > 6 {
			difficulty = 6
		}
	}

	return difficulty
}

func (dc *DifficultyCalculator) GetCurrentRPS() float64 {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	var total uint64
	for _, count := range dc.rpsBuckets {
		total += count
	}

	return float64(total) / dc.windowSize.Seconds()
}

func (dc *DifficultyCalculator) tickerLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		dc.mu.Lock()
		cutoff := now.Add(-dc.windowSize * 2)
		var keep []uint64
		for i := range dc.rpsBuckets {
			bucketTime := dc.lastTick.Add(time.Duration(len(dc.rpsBuckets)-1-i) * dc.bucketSize * -1)
			if bucketTime.After(cutoff) {
				keep = append(keep, dc.rpsBuckets[i])
			}
		}
		dc.rpsBuckets = keep
		if len(dc.rpsBuckets) > 0 {
			dc.lastTick = now
		}
		dc.mu.Unlock()
	}
}

func EstimateNonceSpace(difficulty int) float64 {
	return math.Pow(16, float64(difficulty))
}
