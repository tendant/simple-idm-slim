package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents the account.
type User struct {
	ID                   uuid.UUID
	Email                string
	Username             *string
	EmailVerified        bool
	Name                 *string
	FailedLoginAttempts  int
	LockedUntil          *time.Time
	MFAEnabled           bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            *time.Time
}

// IsLocked returns true if the account is currently locked.
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// UserPassword stores password credentials separately from user profile.
type UserPassword struct {
	UserID            uuid.UUID
	PasswordHash      string
	PasswordUpdatedAt time.Time
}

// UserIdentity stores external identities (Google, etc.).
type UserIdentity struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Provider        string
	ProviderSubject string
	Email           *string
	CreatedAt       time.Time
}

// IdentityProvider constants
const (
	ProviderGoogle = "google"
)
