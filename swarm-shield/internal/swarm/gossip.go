package swarm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"swarm-shield/internal/metrics"
)

type ScoreUpdate struct {
	IP        string    `json:"ip"`
	Score     float64   `json:"score"`
	Timestamp time.Time `json:"timestamp"`
	PeerID    string    `json:"peerId"`
	Signature []byte    `json:"signature"`
}

func signingPayload(update ScoreUpdate) ([]byte, error) {
	return json.Marshal(struct {
		IP    string    `json:"ip"`
		Score float64   `json:"score"`
		TS    time.Time `json:"ts"`
		Peer  string    `json:"peer"`
	}{
		IP:    update.IP,
		Score: update.Score,
		TS:    update.Timestamp,
		Peer:  update.PeerID,
	})
}

type GossipProtocol struct {
	mu          sync.RWMutex
	peers       map[string]*PeerInfo
	config      ConsensusConfig
	secretKey   []byte
	metrics     *metrics.Metrics
	stopChan    chan struct{}
	stopOnce    sync.Once
	backoffMap  map[string]time.Time
}

type PeerInfo struct {
	ID         string
	Address    string
	TrustLevel TrustLevel
	LastSeen   time.Time
	FailCount  int
	Backoff    time.Duration
	Key        []byte
}

func NewGossipProtocol(config ConsensusConfig, secretKey []byte, m *metrics.Metrics) *GossipProtocol {
	if config.MaxPeers == 0 {
		config.MaxPeers = 1000
	}
	return &GossipProtocol{
		peers:      make(map[string]*PeerInfo),
		config:     config,
		secretKey:  secretKey,
		metrics:    m,
		stopChan:   make(chan struct{}),
		backoffMap: make(map[string]time.Time),
	}
}

func (g *GossipProtocol) Start() {
	if g.config.GossipInterval <= 0 {
		g.config.GossipInterval = 2 * time.Second
	}
	if g.config.AntiEntropyInterval <= 0 {
		g.config.AntiEntropyInterval = 30 * time.Second
	}
	go g.gossipLoop()
	go g.antiEntropyLoop()
}

func (g *GossipProtocol) Stop() {
	g.stopOnce.Do(func() {
		close(g.stopChan)
	})
}

func (g *GossipProtocol) AddPeer(id, address string, trustLevel TrustLevel, key []byte) {
	if len(key) < 32 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.config.MaxPeers > 0 && len(g.peers) >= g.config.MaxPeers {
		return
	}
	g.peers[id] = &PeerInfo{
		ID:         id,
		Address:    address,
		TrustLevel: trustLevel,
		LastSeen:   time.Now(),
		Key:        key,
	}
}

func (g *GossipProtocol) RemovePeer(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.peers, id)
	delete(g.backoffMap, id)
}

func (g *GossipProtocol) gossipLoop() {
	ticker := time.NewTicker(g.config.GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.propagate()
		case <-g.stopChan:
			return
		}
	}
}

func (g *GossipProtocol) antiEntropyLoop() {
	ticker := time.NewTicker(g.config.AntiEntropyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.antiEntropy()
		case <-g.stopChan:
			return
		}
	}
}

func (g *GossipProtocol) propagate() {
	g.mu.RLock()
	available := make([]*PeerInfo, 0, len(g.peers))
	for _, p := range g.peers {
		if g.isPeerAvailable(p) {
			available = append(available, p)
		}
	}
	g.mu.RUnlock()

	for _, p := range available {
		g.sendKeepalive(p)
	}
}

func (g *GossipProtocol) antiEntropy() {
	g.mu.RLock()
	available := make([]*PeerInfo, 0, len(g.peers))
	for _, p := range g.peers {
		if g.isPeerAvailable(p) {
			available = append(available, p)
		}
	}
	g.mu.RUnlock()

	for _, p := range available {
		g.requestSync(p)
	}
}

func (g *GossipProtocol) isPeerAvailable(p *PeerInfo) bool {
	if time.Since(p.LastSeen) > g.config.PeerTimeout {
		return false
	}
	if until, hasBackoff := g.backoffMap[p.ID]; hasBackoff && time.Now().Before(until) {
		return false
	}
	return true
}

func (g *GossipProtocol) sendKeepalive(p *PeerInfo) {
	g.mu.Lock()
	p.LastSeen = time.Now()
	g.mu.Unlock()
}

func (g *GossipProtocol) requestSync(p *PeerInfo) {
	g.mu.Lock()
	p.LastSeen = time.Now()
	g.mu.Unlock()
}

func (g *GossipProtocol) RecordFailure(peerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if p, exists := g.peers[peerID]; exists {
		p.FailCount++
		if p.Backoff == 0 {
			p.Backoff = 1 * time.Second
		} else {
			p.Backoff *= 2
			if p.Backoff > 30*time.Second {
				p.Backoff = 30 * time.Second
			}
		}
		g.backoffMap[peerID] = time.Now().Add(p.Backoff)
		p.LastSeen = time.Now()
	}
}

func (g *GossipProtocol) RecordSuccess(peerID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if p, exists := g.peers[peerID]; exists {
		p.FailCount = 0
		p.Backoff = 0
		delete(g.backoffMap, peerID)
		p.LastSeen = time.Now()
	}
}

func signingPayload(update ScoreUpdate) ([]byte, error) {
	return json.Marshal(struct {
		IP    string    `json:"ip"`
		Score float64   `json:"score"`
		TS    time.Time `json:"ts"`
		Peer  string    `json:"peer"`
	}{
		IP:    update.IP,
		Score: update.Score,
		TS:    update.Timestamp,
		Peer:  update.PeerID,
	})
}

func (g *GossipProtocol) CreateScoreUpdate(ip string, score float64, peerID string) ScoreUpdate {
	timestamp := time.Now()
	update := ScoreUpdate{
		IP:        ip,
		Score:     score,
		Timestamp: timestamp,
		PeerID:    peerID,
	}
	payload, err := signingPayload(update)
	if err == nil {
		mac := hmac.New(sha256.New, g.secretKey)
		mac.Write(payload)
		update.Signature = mac.Sum(nil)
	}
	return update
}

func (g *GossipProtocol) PeerCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.peers)
}

func (g *GossipProtocol) PropagateUpdate(update ScoreUpdate) {
	g.mu.RLock()
	available := make([]*PeerInfo, 0, len(g.peers))
	for _, p := range g.peers {
		if g.isPeerAvailable(p) {
			available = append(available, p)
		}
	}
	g.mu.RUnlock()

	for _, p := range available {
		g.sendUpdate(p, update)
	}
}

func (g *GossipProtocol) sendUpdate(p *PeerInfo, update ScoreUpdate) {
	data, err := json.Marshal(update)
	if err != nil {
		return
	}
	if len(data) > 8192 {
		g.RecordFailure(p.ID)
		return
	}
	g.mu.Lock()
	p.LastSeen = time.Now()
	g.mu.Unlock()
}

