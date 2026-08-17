package pow

import (
	"testing"
	"time"
)

func TestValidator_GenerateChallenge(t *testing.T) {
	v := NewValidator()
	challenge, err := v.GenerateChallenge(3, "198.51.100.1")
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}
	if challenge.Token == "" {
		t.Error("GenerateChallenge() token is empty")
	}
	if challenge.Difficulty != 3 {
		t.Errorf("GenerateChallenge() difficulty = %d, want 3", challenge.Difficulty)
	}
	if challenge.ClientIP != "198.51.100.1" {
		t.Errorf("GenerateChallenge() clientIP = %v, want 198.51.100.1", challenge.ClientIP)
	}
	if time.Now().After(challenge.ExpiresAt) {
		t.Error("GenerateChallenge() expiration is in the past")
	}
}

func TestValidator_Verify(t *testing.T) {
	v := NewValidator()
	challenge, err := v.GenerateChallenge(2, "198.51.100.1")
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}

	tests := []struct {
		name     string
		token    string
		nonce    string
		clientIP string
		difficulty int
		want     bool
	}{
		{"valid", challenge.Token, "abc123def456", "198.51.100.1", 2, true},
		{"wrong_difficulty", challenge.Token, "abc123def456", "198.51.100.1", 3, false},
		{"wrong_ip", challenge.Token, "abc123def456", "198.51.100.2", 2, false},
		{"invalid_token", "invalid", "abc123def456", "198.51.100.1", 2, false},
		{"empty_nonce", challenge.Token, "", "198.51.100.1", 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.Verify(tt.token, tt.nonce, tt.clientIP, tt.difficulty)
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidator_ConsumeChallenge(t *testing.T) {
	v := NewValidator()
	challenge, err := v.GenerateChallenge(2, "198.51.100.1")
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}

	if !v.ConsumeChallenge(challenge.Token) {
		t.Error("ConsumeChallenge() = false, want true")
	}
	if v.ConsumeChallenge(challenge.Token) {
		t.Error("ConsumeChallenge() = true, want false")
	}
}

func TestValidator_ExpiredChallenge(t *testing.T) {
	v := NewValidator()
	challenge, err := v.GenerateChallenge(2, "198.51.100.1")
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}

	challenge.ExpiresAt = time.Now().Add(-1 * time.Minute)
	v.mu.Lock()
	v.challenges[challenge.Token] = challenge
	v.mu.Unlock()

	if v.Verify(challenge.Token, "abc123def456", "198.51.100.1", 2) {
		t.Error("Verify() = true for expired challenge, want false")
	}
}

func TestDifficultyCalculator_CalculateDifficulty(t *testing.T) {
	dc := NewDifficultyCalculator()

	tests := []struct {
		name   string
		rps    float64
		overloaded bool
		want   int
	}{
		{"low_rps", 50, false, 1},
		{"medium_rps", 1000, false, 3},
		{"high_rps", 5000, false, 4},
		{"overloaded_boost", 1000, true, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < int(tt.rps); i++ {
				dc.RecordRequest()
			}
			got := dc.CalculateDifficulty()
			if got != tt.want {
				t.Errorf("CalculateDifficulty() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIsValidHexNonce(t *testing.T) {
	tests := []struct {
		name     string
		nonce    string
		expected bool
	}{
		{"valid", "abc123def456", true},
		{"empty", "", false},
		{"invalid_chars", "xyz123", false},
		{"too_long", string(make([]byte, 129)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHexNonce(tt.nonce)
			if got != tt.expected {
				t.Errorf("isValidHexNonce(%q) = %v, want %v", tt.nonce, got, tt.expected)
			}
		})
	}
}
