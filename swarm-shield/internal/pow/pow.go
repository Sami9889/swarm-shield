package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"
)

// Challenge represents an active PoW challenge issued to a client.
type Challenge struct {
	Token     string
	Difficulty int
	IssuedAt   time.Time
}

// Validator validates PoW solutions and manages challenge lifecycle.
type Validator struct {
	mu         sync.RWMutex
	challenges map[string]*Challenge
}

// NewValidator creates a new PoW validator with background cleanup.
func NewValidator() *Validator {
	v := &Validator{challenges: make(map[string]*Challenge)}
	go v.cleanupLoop()
	return v
}

// GenerateChallenge creates a new random challenge token with the given difficulty.
func (v *Validator) GenerateChallenge(difficulty int) *Challenge {
	if difficulty < 1 {
		difficulty = 1
	}
	if difficulty > 6 {
		difficulty = 6
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		panic(fmt.Sprintf("failed to generate challenge token: %v", err))
	}

	ch := &Challenge{
		Token:      hex.EncodeToString(token),
		Difficulty: difficulty,
		IssuedAt:   time.Now(),
	}

	v.mu.Lock()
	v.challenges[ch.Token] = ch
	v.mu.Unlock()

	return ch
}

// Verify checks whether a nonce satisfies the PoW difficulty for the given token.
// The proof is: SHA-256(token + nonce) must start with `difficulty` zero hex characters.
func (v *Validator) Verify(token, nonce string, difficulty int) bool {
	if difficulty < 1 || difficulty > 6 {
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
	return true
}

// ConsumeChallenge removes a challenge after successful use to prevent replay.
func (v *Validator) ConsumeChallenge(token string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.challenges[token]; exists {
		delete(v.challenges, token)
		return true
	}
	return false
}

// cleanupLoop periodically removes stale challenges older than 60 seconds.
func (v *Validator) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		v.mu.Lock()
		for token, ch := range v.challenges {
			if now.Sub(ch.IssuedAt) > 60*time.Second {
				delete(v.challenges, token)
			}
		}
		v.mu.Unlock()
	}
}

// DifficultyCalculator computes required leading-zero difficulty based on observed RPS.
type DifficultyCalculator struct {
	mu          sync.RWMutex
	rpsBuckets  []uint64
	bucketSize  time.Duration
	windowSize  time.Duration
	lastTick    time.Time
}

// NewDifficultyCalculator creates a calculator backed by a rolling 5-second window.
func NewDifficultyCalculator() *DifficultyCalculator {
	dc := &DifficultyCalculator{
		rpsBuckets: make([]uint64, 0),
		bucketSize: 1 * time.Second,
		windowSize: 5 * time.Second,
		lastTick:   time.Now(),
	}
	go dc.tickerLoop()
	return dc
}

// RecordRequest increments the counter for the current time bucket.
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

// CalculateDifficulty returns a difficulty level from 1 to 6 based on recent RPS.
//   - < 100 RPS: difficulty 1
//   - 100-500 RPS: difficulty 2
//   - 500-1,000 RPS: difficulty 3
//   - 1,000-5,000 RPS: difficulty 4
//   - 5,000-20,000 RPS: difficulty 5
//   - > 20,000 RPS: difficulty 6
func (dc *DifficultyCalculator) CalculateDifficulty() int {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-dc.windowSize)

	var total uint64
	for _, count := range dc.rpsBuckets {
		total += count
	}

	rps := float64(total) / dc.windowSize.Seconds()

	switch {
	case rps < 100:
		return 1
	case rps < 500:
		return 2
	case rps < 1000:
		return 3
	case rps < 5000:
		return 4
	case rps < 20000:
		return 5
	default:
		return 6
	}
}

// GetCurrentRPS returns the current requests-per-second estimate.
func (dc *DifficultyCalculator) GetCurrentRPS() float64 {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-dc.windowSize)

	var total uint64
	for _, count := range dc.rpsBuckets {
		total += count
	}

	return float64(total) / dc.windowSize.Seconds()
}

// tickerLoop prunes old buckets every second.
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

// EstimateNonceSpace estimates the number of nonces needed on average for a given difficulty.
// Difficulty d means the first d hex characters must be zero, so 16^d attempts on average.
func EstimateNonceSpace(difficulty int) float64 {
	return math.Pow(16, float64(difficulty))
}
