package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	BearerPrefix = "Bearer "
	APIKeyPrefix = "swarm-"
)

// APIKey represents a registered API key.
type APIKey struct {
	Key       string
	Name      string
	CreatedAt time.Time
	LastUsed  time.Time
	Active    bool
}

// Claims represents JWT claims.
type Claims struct {
	APIKey string `json:"apiKey"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}

// Manager handles API key and JWT operations.
type Manager struct {
	mu         sync.RWMutex
	apiKeys    map[string]*APIKey
	jwtSecret  []byte
	jwtTTL     time.Duration
	issuer     string
	audience   string
}

// NewManager creates a new auth manager.
func NewManager(jwtSecret string, jwtTTL time.Duration, issuer, audience string) *Manager {
	if jwtSecret == "" {
		jwtSecret = generateDefaultSecret()
	}
	if jwtTTL == 0 {
		jwtTTL = 24 * time.Hour
	}
	if issuer == "" {
		issuer = "swarm-shield"
	}
	if audience == "" {
		audience = "swarm-shield-api"
	}

	m := &Manager{
		apiKeys:   make(map[string]*APIKey),
		jwtSecret: []byte(jwtSecret),
		jwtTTL:    jwtTTL,
		issuer:    issuer,
		audience:  audience,
	}
	return m
}

// GenerateAPIKey creates a new API key.
func (m *Manager) GenerateAPIKey(name string) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Sprintf("failed to generate API key: %v", err))
	}

	rawSum := sha256.Sum256(raw)
	key := APIKeyPrefix + hex.EncodeToString(rawSum[:16])

	m.mu.Lock()
	m.apiKeys[key] = &APIKey{
		Key:       key,
		Name:      name,
		CreatedAt: time.Now(),
		Active:    true,
	}
	m.mu.Unlock()

	return key
}

// ValidateAPIKey checks if an API key is valid and active.
func (m *Manager) ValidateAPIKey(key string) bool {
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return false
	}

	m.mu.RLock()
	apiKey, exists := m.apiKeys[key]
	m.mu.RUnlock()

	if !exists || !apiKey.Active {
		return false
	}

	apiKey.LastUsed = time.Now()
	return true
}

// RevokeAPIKey deactivates an API key.
func (m *Manager) RevokeAPIKey(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if apiKey, exists := m.apiKeys[key]; exists {
		apiKey.Active = false
	}
}

// ListAPIKeys returns all registered API keys (without exposing full keys).
func (m *Manager) ListAPIKeys() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(m.apiKeys))
	for _, k := range m.apiKeys {
		entry := map[string]interface{}{
			"name":      k.Name,
			"prefix":    k.Key[:12],
			"active":    k.Active,
			"createdAt": k.CreatedAt.Unix(),
			"lastUsed":  k.LastUsed.Unix(),
		}
		result = append(result, entry)
	}
	return result
}

// GenerateJWT creates a JWT token for a valid API key.
func (m *Manager) GenerateJWT(apiKey string) (string, error) {
	claims := Claims{
		APIKey: apiKey,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    m.issuer,
			Subject:   apiKey,
			Audience:  jwt.ClaimStrings{m.audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// ValidateJWT validates a JWT token and returns the claims.
func (m *Manager) ValidateJWT(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Validate issuer.
		if claims.Issuer != m.issuer {
			return nil, fmt.Errorf("invalid issuer")
		}
		// Validate audience.
		if len(claims.Audience) == 0 || claims.Audience[0] != m.audience {
			return nil, fmt.Errorf("invalid audience")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// AuthMiddleware creates an HTTP middleware that requires valid authentication.
// Accepts either:
//   - X-API-Key header with a valid API key
//   - Authorization: Bearer <JWT> header
func (m *Manager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try API key first.
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" && m.ValidateAPIKey(apiKey) {
			next.ServeHTTP(w, r)
			return
		}

		// Try Bearer JWT.
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, BearerPrefix) {
			tokenString := strings.TrimPrefix(authHeader, BearerPrefix)
			if _, err := m.ValidateJWT(tokenString); err == nil {
				next.ServeHTTP(w, r)
				return
			}
		}

		respondError(w, http.StatusUnauthorized, "missing or invalid authentication")
	})
}

// LoginRequest represents a sign-in request.
type LoginRequest struct {
	APIKey string `json:"apiKey"`
}

// LoginResponse represents a sign-in response.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expiresIn"`
	Type      string `json:"type"`
}

// HandleLogin processes a sign-in request and returns a JWT.
func (m *Manager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !m.ValidateAPIKey(req.APIKey) {
		respondError(w, http.StatusUnauthorized, "invalid API key")
		return
	}

	token, err := m.GenerateJWT(req.APIKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	respondJSON(w, http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresIn: int64(m.jwtTTL.Seconds()),
		Type:      "Bearer",
	})
}

func generateDefaultSecret() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Sprintf("failed to generate JWT secret: %v", err))
	}
	return hex.EncodeToString(raw)
}

func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
