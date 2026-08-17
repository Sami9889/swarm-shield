package swarm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type TrustLevel int

const (
	TrustObserver TrustLevel = iota
	TrustVoter
	TrustValidator
)

type ReputationScorer struct {
	mu          sync.RWMutex
	config      ConsensusConfig
	reputations map[string]*ReputationEntry
	secretKey   []byte
}

type ReputationEntry struct {
	IP              string
	Score           float64
	RequestPattern  float64
	PoWCompliance   float64
	ConnectionScore float64
	BehavioralHash  string
	LastUpdated     time.Time
	LastDecay       time.Time
	Blocked         bool
	BlockCount      int
}

type RequestMetrics struct {
	RequestRate        int
	PoWVerified        bool
	ConnectionDuration time.Duration
	BehavioralData     string
}

func (r RequestMetrics) BehavioralFingerprint() string {
	return r.BehavioralData
}

func NewReputationScorer(config ConsensusConfig, secretKey []byte) *ReputationScorer {
	if config.MaxScore == 0 {
		config.MaxScore = 1.0
	}
	if config.MinScore == 0 {
		config.MinScore = 0.0
	}
	if config.Threshold == 0 {
		config.Threshold = 0.75
	}
	if config.DecayRate == 0 {
		config.DecayRate = 0.95
	}
	if config.DecayInterval == 0 {
		config.DecayInterval = 5 * time.Minute
	}
	if config.MaxReputations == 0 {
		config.MaxReputations = 1000000
	}

	return &ReputationScorer{
		config:      config,
		reputations: make(map[string]*ReputationEntry),
		secretKey:   secretKey,
	}
}

func (rs *ReputationScorer) Score(ip string, metrics RequestMetrics) float64 {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if metrics.RequestRate < 0 {
		metrics.RequestRate = 0
	}
	if metrics.ConnectionDuration < 0 {
		metrics.ConnectionDuration = 0
	}

	if len(rs.reputations) >= 1_000_000 {
		rs.evictOldest()
	}

	entry, exists := rs.reputations[ip]
	if !exists {
		entry = &ReputationEntry{
			IP:         ip,
			Score:      rs.config.MaxScore,
			LastUpdated: time.Now(),
			LastDecay:  time.Now(),
		}
		rs.reputations[ip] = entry
	}

	entry.RequestPattern = rs.scoreRequestPattern(metrics)
	entry.PoWCompliance = rs.scorePoWCompliance(metrics)
	entry.ConnectionScore = rs.scoreConnectionBehavior(metrics)
	entry.BehavioralHash = rs.computeBehavioralHash(metrics)

	newScore := entry.RequestPattern*0.4 + entry.PoWCompliance*0.35 + entry.ConnectionScore*0.25
	if newScore > rs.config.MaxScore {
		newScore = rs.config.MaxScore
	}
	if newScore < rs.config.MinScore {
		newScore = rs.config.MinScore
	}

	entry.Score = entry.Score*0.7 + newScore*0.3
	if entry.Score > rs.config.MaxScore {
		entry.Score = rs.config.MaxScore
	}
	if entry.Score < rs.config.MinScore {
		entry.Score = rs.config.MinScore
	}
	entry.LastUpdated = time.Now()

	return entry.Score
}

func (rs *ReputationScorer) scoreRequestPattern(metrics RequestMetrics) float64 {
	if metrics.RequestRate <= 0 {
		return 1.0
	}
	if metrics.RequestRate > 1000 {
		return 0.0
	}
	score := 1.0 - (float64(metrics.RequestRate) / 1000.0)
	if score < 0.0 {
		score = 0.0
	}
	return score
}

func (rs *ReputationScorer) scorePoWCompliance(metrics RequestMetrics) float64 {
	if !metrics.PoWVerified {
		return 0.5
	}
	return 1.0
}

func (rs *ReputationScorer) scoreConnectionBehavior(metrics RequestMetrics) float64 {
	if metrics.ConnectionDuration < 0 {
		return 0.5
	}
	if metrics.ConnectionDuration < 100*time.Millisecond {
		return 0.5
	}
	if metrics.ConnectionDuration > 5*time.Minute {
		return 1.0
	}
	score := float64(metrics.ConnectionDuration) / float64(5*time.Minute)
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func (rs *ReputationScorer) computeBehavioralHash(metrics RequestMetrics) string {
	data := metrics.BehavioralFingerprint()
	h := hmac.New(sha256.New, rs.secretKey)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func (rs *ReputationScorer) Decay() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	for ip, entry := range rs.reputations {
		if now.Sub(entry.LastDecay) > rs.config.DecayInterval {
			entry.Score = entry.Score*rs.config.DecayRate + rs.config.MaxScore*(1-rs.config.DecayRate)
			if entry.Score > rs.config.MaxScore {
				entry.Score = rs.config.MaxScore
			}
			if entry.Score < rs.config.MinScore {
				entry.Score = rs.config.MinScore
			}
			entry.LastDecay = now
			if entry.Blocked && entry.Score > rs.config.Threshold {
				entry.Blocked = false
			}
		}
	}
}

func (rs *ReputationScorer) Recover(ip string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if entry, exists := rs.reputations[ip]; exists {
		entry.Score = rs.config.MaxScore * 0.8
		entry.Blocked = false
		entry.BlockCount = 0
		entry.LastUpdated = time.Now()
	}
}

func (rs *ReputationScorer) IsBlocked(ip string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if entry, exists := rs.reputations[ip]; exists {
		return entry.Blocked
	}
	return false
}

func (rs *ReputationScorer) GetScore(ip string) float64 {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if entry, exists := rs.reputations[ip]; exists {
		return entry.Score
	}
	return rs.config.MaxScore
}

func (rs *ReputationScorer) Block(ip string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if entry, exists := rs.reputations[ip]; exists {
		entry.Blocked = true
		entry.BlockCount++
		if entry.BlockCount < 0 {
			entry.BlockCount = int(^uint(0) >> 1)
		}
		entry.LastUpdated = time.Now()
	}
}

func (rs *ReputationScorer) MarshalEntry(ip string) *ReputationEntry {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if entry, exists := rs.reputations[ip]; exists {
		e := *entry
		return &e
	}
	return nil
}

func (rs *ReputationScorer) evictOldest() {
	if len(rs.reputations) == 0 {
		return
	}
	var oldestIP string
	var oldestTime time.Time
	for ip, entry := range rs.reputations {
		if oldestIP == "" || entry.LastUpdated.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.LastUpdated
		}
	}
	if oldestIP != "" {
		delete(rs.reputations, oldestIP)
	}
}

func (rs *ReputationScorer) UpdateFromGossip(update ScoreUpdate) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if err := rs.verifySignature(update); err != nil {
		return err
	}

	now := time.Now()
	if update.Timestamp.After(now.Add(5*time.Minute)) || update.Timestamp.Before(now.Add(-5*time.Minute)) {
		return fmt.Errorf("timestamp outside clock skew window")
	}

	entry, exists := rs.reputations[update.IP]
	if !exists {
		entry = &ReputationEntry{
			IP:         update.IP,
			Score:      rs.config.MaxScore,
			LastUpdated: now,
			LastDecay:  now,
		}
		rs.reputations[update.IP] = entry
	}

	if update.Score > rs.config.MaxScore {
		update.Score = rs.config.MaxScore
	}
	if update.Score < rs.config.MinScore {
		update.Score = rs.config.MinScore
	}

	oldScore := entry.Score
	entry.Score = oldScore*0.6 + update.Score*0.4
	if entry.Score > rs.config.MaxScore {
		entry.Score = rs.config.MaxScore
	}
	if entry.Score < rs.config.MinScore {
		entry.Score = rs.config.MinScore
	}
	entry.LastUpdated = now
	entry.LastDecay = now
	return nil
}

func (rs *ReputationScorer) verifySignature(update ScoreUpdate) error {
	if len(update.Signature) == 0 {
		return fmt.Errorf("missing signature")
	}
	data, err := signingPayload(update)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	mac := hmac.New(sha256.New, rs.secretKey)
	mac.Write(data)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, update.Signature) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
