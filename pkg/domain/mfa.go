package domain

import (
	"time"

	"github.com/google/uuid"
)

// MFAMethod represents the type of MFA method
type MFAMethod string

const (
	// MFAMethodTOTP represents Time-based One-Time Password authentication
	MFAMethodTOTP MFAMethod = "totp"
	// MFAMethodSMS represents SMS-based authentication (future support)
	MFAMethodSMS MFAMethod = "sms"
)

// MFASecret represents an encrypted MFA secret for a user
type MFASecret struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Method          MFAMethod
	SecretEncrypted string     // AES-256-GCM encrypted TOTP secret
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// MFARecoveryCode represents a hashed recovery code for MFA backup access
type MFARecoveryCode struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CodeHash  string     // Argon2id hashed recovery code
	UsedAt    *time.Time
	CreatedAt time.Time
}

// IsUsed returns true if the recovery code has been used
func (c *MFARecoveryCode) IsUsed() bool {
	return c.UsedAt != nil
}

// MFASetupResponse contains data returned when setting up MFA
type MFASetupResponse struct {
	Secret        string   // Base32 TOTP secret (for manual entry)
	QRCodeDataURI string   // QR code as data:image/png;base64,...
	RecoveryCodes []string // Plain text recovery codes (shown once)
}
