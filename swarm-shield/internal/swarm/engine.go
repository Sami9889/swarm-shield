package swarm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"swarm-shield/internal/audit"
	"swarm-shield/internal/metrics"
	"swarm-shield/internal/ratelimit"
)

var ErrSwarmDisabled = errors.New("swarm consensus engine is disabled")

type ConsensusEngine struct {
	config      ConsensusConfig
	scorer      *ReputationScorer
	gossip      *GossipProtocol
	metrics     *metrics.Metrics
	audit       *audit.Logger
	rateLimiter *ratelimit.RateLimiter
	secretKey   []byte
	peerID      string
	stopChan    chan struct{}
	stopOnce    sync.Once
	decayTicker *time.Ticker
}

func NewConsensusEngine(config ConsensusConfig, secretKey []byte, m *metrics.Metrics, a *audit.Logger, rl *ratelimit.RateLimiter) *ConsensusEngine {
	if !config.Enabled {
		return nil
	}

	peerID := generatePeerID()
	scorer := NewReputationScorer(config, secretKey)
	gossip := NewGossipProtocol(config, secretKey, m)

	return &ConsensusEngine{
		config:      config,
		scorer:      scorer,
		gossip:      gossip,
		metrics:     m,
		audit:       a,
		rateLimiter: rl,
		secretKey:   secretKey,
		peerID:      peerID,
		stopChan:    make(chan struct{}),
	}
}

func (c *ConsensusEngine) Start() {
	if c == nil {
		return
	}

	c.gossip.Start()
	c.decayTicker = time.NewTicker(c.config.DecayInterval)
	go c.decayLoop()
}

func (c *ConsensusEngine) Stop() {
	if c == nil {
		return
	}

	c.stopOnce.Do(func() {
		close(c.stopChan)
	})
	if c.decayTicker != nil {
		c.decayTicker.Stop()
	}
	c.gossip.Stop()
}

func (c *ConsensusEngine) decayLoop() {
	for {
		select {
		case <-c.decayTicker.C:
			c.scorer.Decay()
		case <-c.stopChan:
			return
		}
	}
}

func (c *ConsensusEngine) RecordObservation(ip string, rm RequestMetrics) {
	if c == nil {
		return
	}

	score := c.scorer.Score(ip, rm)
	if score < c.config.Threshold {
		c.scorer.Block(ip)
		if c.metrics != nil && c.metrics.ConsensusBlocks != nil {
			c.metrics.ConsensusBlocks.Inc()
		}
		if c.audit != nil {
			c.audit.Log(nil, &audit.Event{
				ID:        generateEventID(),
				Type:      "consensus_block",
				IPAddress: ip,
				Status:    http.StatusForbidden,
			})
		}
	}

	update := c.gossip.CreateScoreUpdate(ip, score, c.peerID)
	c.gossip.PropagateUpdate(update)
	if c.metrics != nil && c.metrics.ConsensusGossipMessages != nil {
		c.metrics.ConsensusGossipMessages.Inc()
	}
}

func (c *ConsensusEngine) CheckConsensus(ip string) bool {
	if c == nil {
		return false
	}

	if c.scorer.IsBlocked(ip) {
		return true
	}

	if c.rateLimiter != nil {
		if !c.rateLimiter.Allow("consensus:" + ip) {
			return true
		}
	}

	return false
}

func (c *ConsensusEngine) GetScore(ip string) float64 {
	if c == nil {
		return 0.0
	}
	return c.scorer.GetScore(ip)
}

func (c *ConsensusEngine) Recover(ip string) {
	if c == nil {
		return
	}
	c.scorer.Recover(ip)
}

func (c *ConsensusEngine) AddPeer(id, address string, trustLevel TrustLevel, key []byte) {
	if c == nil {
		return
	}
	c.gossip.AddPeer(id, address, trustLevel, key)
}

func (c *ConsensusEngine) HandleGossipMessage(data []byte) error {
	if c == nil {
		return ErrSwarmDisabled
	}
	var update ScoreUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		return err
	}
	c.scorer.UpdateFromGossip(update)
	c.gossip.RecordSuccess(update.PeerID)
	return nil
}

func (c *ConsensusEngine) Stats() map[string]interface{} {
	if c == nil {
		return nil
	}

	return map[string]interface{}{
		"peerId":    c.peerID,
		"peerCount": c.gossip.PeerCount(),
		"enabled":   c.config.Enabled,
		"threshold": c.config.Threshold,
	}
}

func generatePeerID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102-150405")))[:16]
	}
	return hex.EncodeToString(buf)
}

func generateEventID() string {
	return time.Now().Format("20060102-150405-") + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[int(time.Now().UnixNano())%len(letters)]
	}
	return string(b)
}
