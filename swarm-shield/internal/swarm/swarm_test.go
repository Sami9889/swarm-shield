package swarm

import (
	"fmt"
	"testing"
	"time"
)

func TestReputationScorer_Score(t *testing.T) {
	config := ConsensusConfig{
		Enabled:      true,
		MaxScore:     1.0,
		MinScore:     0.0,
		Threshold:    0.75,
		DecayRate:    0.95,
		DecayInterval: 5 * time.Minute,
	}
	scorer := NewReputationScorer(config, []byte("test-secret"))

	tests := []struct {
		name           string
		ip             string
		metrics        RequestMetrics
		wantMinScore   float64
		wantMaxScore   float64
	}{
		{
			name:     "high_rate_low_score",
			ip:       "198.51.100.1",
			metrics:  RequestMetrics{RequestRate: 1000, PoWVerified: false, ConnectionDuration: 50 * time.Millisecond},
			wantMinScore: 0.0,
			wantMaxScore: 0.4,
		},
		{
			name:     "low_rate_high_score",
			ip:       "198.51.100.2",
			metrics:  RequestMetrics{RequestRate: 10, PoWVerified: true, ConnectionDuration: 10 * time.Minute},
			wantMinScore: 0.85,
			wantMaxScore: 1.0,
		},
		{
			name:     "negative_metrics_clamped",
			ip:       "198.51.100.3",
			metrics:  RequestMetrics{RequestRate: -10, PoWVerified: false, ConnectionDuration: -1 * time.Minute},
			wantMinScore: 0.0,
			wantMaxScore: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scorer.Score(tt.ip, tt.metrics)
			if score < tt.wantMinScore || score > tt.wantMaxScore {
				t.Errorf("Score() = %v, want between %v and %v", score, tt.wantMinScore, tt.wantMaxScore)
			}
		})
	}
}

func TestReputationScorer_Decay(t *testing.T) {
	config := ConsensusConfig{
		Enabled:       true,
		MaxScore:      1.0,
		MinScore:      0.0,
		Threshold:     0.75,
		DecayRate:     0.95,
		DecayInterval: 1 * time.Millisecond,
	}
	scorer := NewReputationScorer(config, []byte("test-secret"))

	scorer.Score("198.51.100.1", RequestMetrics{RequestRate: 1000, PoWVerified: false, ConnectionDuration: 50 * time.Millisecond})
	scoreBefore := scorer.GetScore("198.51.100.1")

	time.Sleep(2 * time.Millisecond)
	scorer.Decay()
	scoreAfter := scorer.GetScore("198.51.100.1")

	if scoreAfter <= scoreBefore {
		t.Errorf("Decay() did not increase score: before=%v, after=%v", scoreBefore, scoreAfter)
	}
}

func TestReputationScorer_Recover(t *testing.T) {
	config := ConsensusConfig{
		Enabled:       true,
		MaxScore:      1.0,
		MinScore:      0.0,
		Threshold:     0.75,
		DecayRate:     0.95,
		DecayInterval: 5 * time.Minute,
	}
	scorer := NewReputationScorer(config, []byte("test-secret"))

	scorer.Score("198.51.100.1", RequestMetrics{RequestRate: 1000, PoWVerified: false, ConnectionDuration: 50 * time.Millisecond})
	scorer.Block("198.51.100.1")

	if !scorer.IsBlocked("198.51.100.1") {
		t.Error("IP should be blocked")
	}

	scorer.Recover("198.51.100.1")
	if scorer.IsBlocked("198.51.100.1") {
		t.Error("IP should not be blocked after recover")
	}
	if scorer.GetScore("198.51.100.1") < 0.7 {
		t.Errorf("Score after recover = %v, want >= 0.7", scorer.GetScore("198.51.100.1"))
	}
}

func TestReputationScorer_BlockCountOverflow(t *testing.T) {
	config := ConsensusConfig{
		Enabled:       true,
		MaxScore:      1.0,
		MinScore:      0.0,
		Threshold:     0.75,
		DecayRate:     0.95,
		DecayInterval: 5 * time.Minute,
	}
	scorer := NewReputationScorer(config, []byte("test-secret"))

	scorer.Score("198.51.100.1", RequestMetrics{RequestRate: 1000, PoWVerified: false, ConnectionDuration: 50 * time.Millisecond})
	for i := 0; i < 10000; i++ {
		scorer.Block("198.51.100.1")
	}
	if scorer.MarshalEntry("198.51.100.1").BlockCount < 0 {
		t.Error("BlockCount overflowed")
	}
}

func TestReputationScorer_MaxEntries(t *testing.T) {
	config := ConsensusConfig{
		Enabled:         true,
		MaxScore:        1.0,
		MinScore:        0.0,
		Threshold:       0.75,
		DecayRate:       0.95,
		DecayInterval:   5 * time.Minute,
		MaxReputations:  100,
	}
	scorer := NewReputationScorer(config, []byte("test-secret"))

	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i%256)
		scorer.Score(ip, RequestMetrics{RequestRate: 10, PoWVerified: true, ConnectionDuration: time.Minute})
	}

	if len(scorer.reputations) > 100 {
		t.Errorf("reputations map size = %d, want <= 100", len(scorer.reputations))
	}
}

func TestGossipProtocol_AddPeer(t *testing.T) {
	config := ConsensusConfig{
		Enabled:    true,
		MaxPeers:   10,
	}
	gossip := NewGossipProtocol(config, []byte("test-secret"), nil)

	gossip.AddPeer("peer1", "addr1", TrustVoter, []byte("12345678901234567890123456789012"))
	if gossip.PeerCount() != 1 {
		t.Errorf("PeerCount() = %d, want 1", gossip.PeerCount())
	}

	gossip.AddPeer("peer2", "addr2", TrustObserver, []byte("short"))
	if gossip.PeerCount() != 1 {
		t.Errorf("PeerCount() = %d, want 1 (short key rejected)", gossip.PeerCount())
	}
}

func TestGossipProtocol_MaxPeers(t *testing.T) {
	config := ConsensusConfig{
		Enabled:  true,
		MaxPeers: 2,
	}
	gossip := NewGossipProtocol(config, []byte("test-secret"), nil)

	gossip.AddPeer("peer1", "addr1", TrustVoter, []byte("12345678901234567890123456789012"))
	gossip.AddPeer("peer2", "addr2", TrustVoter, []byte("12345678901234567890123456789012"))
	gossip.AddPeer("peer3", "addr3", TrustVoter, []byte("12345678901234567890123456789012"))

	if gossip.PeerCount() != 2 {
		t.Errorf("PeerCount() = %d, want 2", gossip.PeerCount())
	}
}
