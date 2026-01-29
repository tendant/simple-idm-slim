package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Session represents an authentication session.
type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastSeenAt *time.Time
	Metadata   json.RawMessage
}

// SessionMetadata holds optional session context.
type SessionMetadata struct {
	IP                string `json:"ip,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
	FingerprintHash   string `json:"fingerprint_hash,omitempty"`
	FingerprintIP     string `json:"fingerprint_ip,omitempty"`
	FingerprintUA     string `json:"fingerprint_ua,omitempty"`
}

// IsValid checks if the session is valid (not expired and not revoked).
func (s *Session) IsValid() bool {
	if s.RevokedAt != nil {
		return false
	}
	return time.Now().Before(s.ExpiresAt)
}

// TokenPair represents the access and refresh token pair.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}
