package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	BearerPrefix = "Bearer "
	APIKeyPrefix = "swarm-"
)

var apiKeyRegexp = regexp.MustCompile("^[a-f0-9]+$")

type APIKey struct {
	Key       string
	Name      string
	Role      string
	CreatedAt time.Time
	LastUsed  time.Time
	Active    bool
}

type Claims struct {
	APIKey string `json:"apiKey"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type Manager struct {
	mu         sync.RWMutex
	apiKeys    map[string]*APIKey
	jwtSecret  []byte
	jwtTTL     time.Duration
	issuer     string
	audience   string
}

func NewManager(jwtSecret string, jwtTTL time.Duration, issuer, audience string) (*Manager, error) {
	if jwtSecret == "" {
		var err error
		jwtSecret, err = generateDefaultSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
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
	return m, nil
}

func (m *Manager) GenerateAPIKey(name string) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
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

func (m *Manager) ValidateAPIKey(key string) bool {
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return false
	}
	if len(key) > 256 {
		return false
	}
	if !apiKeyRegexp.MatchString(key[len(APIKeyPrefix):]) {
		return false
	}

	m.mu.Lock()
	apiKey, exists := m.apiKeys[key]
	if !exists || !apiKey.Active {
		m.mu.Unlock()
		return false
	}
	apiKey.LastUsed = time.Now()
	m.mu.Unlock()
	return true
}

func (m *Manager) RevokeAPIKey(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if apiKey, exists := m.apiKeys[key]; exists {
		apiKey.Active = false
	}
}

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

func (m *Manager) GenerateJWT(apiKey string) (string, error) {
	m.mu.RLock()
	key, exists := m.apiKeys[apiKey]
	m.mu.RUnlock()
	if !exists {
		key = &APIKey{Key: apiKey, Role: ""}
	}

	claims := Claims{
		APIKey: apiKey,
		Name:   key.Name,
		Role:   key.Role,
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
		if claims.Issuer != m.issuer {
			return nil, fmt.Errorf("invalid issuer")
		}
		if len(claims.Audience) == 0 || claims.Audience[0] != m.audience {
			return nil, fmt.Errorf("invalid audience")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (m *Manager) AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			m.mu.RLock()
			key, exists := m.apiKeys[apiKey]
			m.mu.RUnlock()
			if exists && key.Active && key.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, BearerPrefix) {
			tokenString := strings.TrimPrefix(authHeader, BearerPrefix)
			claims, err := m.ValidateJWT(tokenString)
			if err == nil && claims.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}
		}

		respondError(w, http.StatusForbidden, "admin authorization required")
	})
}

func (m *Manager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" && m.ValidateAPIKey(apiKey) {
			next.ServeHTTP(w, r)
			return
		}

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

type LoginRequest struct {
	APIKey string `json:"apiKey"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expiresIn"`
	Type      string `json:"type"`
}

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

func generateDefaultSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
