package audit

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

type EventType string

const (
	EventLogin           EventType = "login"
	EventLogout          EventType = "logout"
	EventAPICall         EventType = "api_call"
	EventAPIKeyCreated   EventType = "api_key_created"
	EventAPIKeyRevoked   EventType = "api_key_revoked"
	EventPoWVerified     EventType = "pow_verified"
	EventP2PConnect      EventType = "p2p_connect"
	EventP2PDisconnect   EventType = "p2p_disconnect"
	EventRateLimitHit    EventType = "rate_limit_hit"
	EventAuthFailure     EventType = "auth_failure"
	EventSystemStart     EventType = "system_start"
	EventSystemStop      EventType = "system_stop"
)

type Event struct {
	ID        string            `json:"id"`
	Type      EventType         `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Actor     string            `json:"actor,omitempty"`
	APIKey    string            `json:"apiKey,omitempty"`
	PeerID    string            `json:"peerId,omitempty"`
	Endpoint  string            `json:"endpoint,omitempty"`
	Method    string            `json:"method,omitempty"`
	Status    int               `json:"status,omitempty"`
	Duration  int64             `json:"durationMs,omitempty"`
	UserAgent string            `json:"userAgent,omitempty"`
	IPAddress string            `json:"ipAddress,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Logger struct {
	logger *zap.Logger
}

func NewLogger(logger *zap.Logger) *Logger {
	return &Logger{logger: logger}
}

func (l *Logger) Log(ctx context.Context, event *Event) {
	event.Timestamp = time.Now().UTC()

	fields := []zap.Field{
		zap.String("audit_id", event.ID),
		zap.String("type", string(event.Type)),
		zap.String("timestamp", event.Timestamp.Format(time.RFC3339Nano)),
	}

	if event.Actor != "" {
		fields = append(fields, zap.String("actor", event.Actor))
	}
	if event.APIKey != "" {
		fields = append(fields, zap.String("apiKey", maskAPIKey(event.APIKey)))
	}
	if event.PeerID != "" {
		fields = append(fields, zap.String("peerId", event.PeerID))
	}
	if event.Endpoint != "" {
		fields = append(fields, zap.String("endpoint", event.Endpoint))
	}
	if event.Method != "" {
		fields = append(fields, zap.String("method", event.Method))
	}
	if event.Status != 0 {
		fields = append(fields, zap.Int("status", event.Status))
	}
	if event.Duration > 0 {
		fields = append(fields, zap.Int64("durationMs", event.Duration))
	}
	if event.UserAgent != "" {
		fields = append(fields, zap.String("userAgent", event.UserAgent))
	}
	if event.IPAddress != "" {
		fields = append(fields, zap.String("ipAddress", maskIP(event.IPAddress)))
	}

	l.logger.Info("audit", fields...)

	_ = ctx
	_, _ = json.Marshal(event)
}

func (l *Logger) LogLogin(actor, apiKey, ipAddress, userAgent string, success bool, status int) {
	l.Log(nil, &Event{
		ID:        generateEventID(),
		Type:      EventLogin,
		Actor:     actor,
		APIKey:    apiKey,
		Status:    status,
		UserAgent: userAgent,
		IPAddress: ipAddress,
		Metadata: map[string]string{
			"success": boolToString(success),
		},
	})
}

func (l *Logger) LogAPICall(actor, apiKey, endpoint, method, ipAddress, userAgent string, status int, duration int64) {
	l.Log(nil, &Event{
		ID:        generateEventID(),
		Type:      EventAPICall,
		Actor:     actor,
		APIKey:    apiKey,
		Endpoint:  endpoint,
		Method:    method,
		Status:    status,
		Duration:  duration,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
}

func (l *Logger) LogRateLimitHit(apiKey, ipAddress, endpoint string) {
	l.Log(nil, &Event{
		ID:        generateEventID(),
		Type:      EventRateLimitHit,
		APIKey:    apiKey,
		Endpoint:  endpoint,
		IPAddress: ipAddress,
		Status:    429,
	})
}

func (l *Logger) LogAuthFailure(ipAddress, endpoint, reason string) {
	l.Log(nil, &Event{
		ID:        generateEventID(),
		Type:      EventAuthFailure,
		Endpoint:  endpoint,
		IPAddress: ipAddress,
		Status:    401,
		Metadata: map[string]string{
			"reason": reason,
		},
	})
}

func generateEventID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().Format("20060102-150405-") + fmt.Sprintf("%08x", time.Now().UnixNano()&0xFFFFFFFF)
	}
	return time.Now().Format("20060102-150405-") + hex.EncodeToString(buf)
}

func maskAPIKey(key string) string {
	if len(key) <= 12 {
		return "***"
	}
	return key[:12] + "..."
}

func maskIP(ip string) string {
	if len(ip) <= 8 {
		return ip
	}
	return ip[:8] + "..."
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = letters[int(time.Now().UnixNano())%len(letters)]
		}
		return string(b)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}
