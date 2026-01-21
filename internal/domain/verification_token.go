package domain

import (
	"time"

	"github.com/google/uuid"
)

type VerificationTokenKind string

const (
	TokenKindEmailVerification VerificationTokenKind = "email_verification"
	TokenKindPasswordReset     VerificationTokenKind = "password_reset"
)

type VerificationToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	Kind       VerificationTokenKind
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	Metadata   []byte
}

func (t *VerificationToken) IsValid() bool {
	return t.ConsumedAt == nil && time.Now().Before(t.ExpiresAt)
}
