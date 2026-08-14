package signaling

import (
	"encoding/json"
	"math/rand"
	"sync"
	"time"
)

// PeerInfo holds signaling data for a connected client.
type PeerInfo struct {
	ID            string
	WebRTCOffer   *string
	WebRTCAnswer  *string
	ICECandidates []string
	ConnectedAt   time.Time
	LastSeen      time.Time
	DataChannels  []string
}

// SignalingStore is an in-memory thread-safe store for WebRTC peer signaling queues.
type SignalingStore struct {
	mu       sync.RWMutex
	peers    map[string]*PeerInfo
	ttl      time.Duration
	stopChan chan struct{}
}

// NewSignalingStore creates a new signaling store with automatic TTL eviction.
func NewSignalingStore(ttl time.Duration) *SignalingStore {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	store := &SignalingStore{
		peers:    make(map[string]*PeerInfo),
		ttl:      ttl,
		stopChan: make(chan struct{}),
	}
	go store.evictionLoop()
	return store
}

// RegisterPeer adds or updates a peer in the signaling store.
func (s *SignalingStore) RegisterPeer(id string) *PeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, exists := s.peers[id]; exists {
		p.LastSeen = time.Now()
		return p
	}

	peer := &PeerInfo{
		ID:          id,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
	}
	s.peers[id] = peer
	return peer
}

// UpdateOffer stores a WebRTC SDP offer for the given peer.
func (s *SignalingStore) UpdateOffer(peerID, offerSDP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, exists := s.peers[peerID]; exists {
		p.WebRTCOffer = &offerSDP
		p.LastSeen = time.Now()
	}
}

// UpdateAnswer stores a WebRTC SDP answer for the given peer.
func (s *SignalingStore) UpdateAnswer(peerID, answerSDP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, exists := s.peers[peerID]; exists {
		p.WebRTCAnswer = &answerSDP
		p.LastSeen = time.Now()
	}
}

// AddICECandidate appends an ICE candidate to a peer's signaling queue.
func (s *SignalingStore) AddICECandidate(peerID, candidate string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, exists := s.peers[peerID]; exists {
		p.ICECandidates = append(p.ICECandidates, candidate)
		p.LastSeen = time.Now()
	}
}

// GetPeer retrieves a peer by ID.
func (s *SignalingStore) GetPeer(peerID string) (*PeerInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.peers[peerID]
	if !exists {
		return nil, false
	}

	peerCopy := *p
	peerCopy.ICECandidates = append([]string{}, p.ICECandidates...)
	return &peerCopy, true
}

// GetRandomPeers returns up to `n` random peer IDs from the store.
func (s *SignalingStore) GetRandomPeers(n int, excludeID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var candidates []string
	for id := range s.peers {
		if id != excludeID {
			candidates = append(candidates, id)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	if n > len(candidates) {
		n = len(candidates)
	}
	return candidates[:n]
}

// GetAllPeers returns all active peer IDs.
func (s *SignalingStore) GetAllPeers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.peers))
	for id := range s.peers {
		ids = append(ids, id)
	}
	return ids
}

// PeerCount returns the number of active peers.
func (s *SignalingStore) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// RemovePeer deletes a peer from the store.
func (s *SignalingStore) RemovePeer(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, peerID)
}

// MarshalPeers returns a JSON-safe map of all peers (without sensitive ICE candidates).
func (s *SignalingStore) MarshalPeers() []map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(s.peers))
	for _, p := range s.peers {
		entry := map[string]interface{}{
			"id":           p.ID,
			"hasOffer":     p.WebRTCOffer != nil,
			"hasAnswer":    p.WebRTCAnswer != nil,
			"iceCount":     len(p.ICECandidates),
			"connectedAt":  p.ConnectedAt.Unix(),
			"lastSeen":     p.LastSeen.Unix(),
		}
		result = append(result, entry)
	}
	return result
}

// evictionLoop periodically removes peers that have exceeded the TTL.
func (s *SignalingStore) evictionLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for id, p := range s.peers {
				if now.Sub(p.LastSeen) > s.ttl {
					delete(s.peers, id)
				}
			}
			s.mu.Unlock()
		case <-s.stopChan:
			return
		}
	}
}

// Stop shuts down the eviction loop.
func (s *SignalingStore) Stop() {
	close(s.stopChan)
}

// SignalMessage represents a WebRTC signaling message exchanged over the API.
type SignalMessage struct {
	Type      string `json:"type"`
	PeerID    string `json:"peerId"`
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

// Marshal returns the JSON-encoded signal message.
func (m *SignalMessage) Marshal() []byte {
	data, _ := json.Marshal(m)
	return data
}

// ParseSignalMessage decodes a JSON signal message.
func ParseSignalMessage(data []byte) (*SignalMessage, error) {
	var m SignalMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
