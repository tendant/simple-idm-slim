package domain

import "errors"

// Authentication errors
var (
	ErrUserNotFound              = errors.New("user not found")
	ErrUserAlreadyExists         = errors.New("user already exists")
	ErrUsernameAlreadyExists     = errors.New("username already exists")
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrAccountLocked             = errors.New("account locked due to too many failed login attempts")
	ErrSessionNotFound           = errors.New("session not found")
	ErrSessionExpired            = errors.New("session expired")
	ErrSessionRevoked            = errors.New("session revoked")
	ErrSessionFingerprint        = errors.New("session fingerprint mismatch - possible token theft")
	ErrInvalidToken              = errors.New("invalid token")
	ErrIdentityNotFound          = errors.New("identity not found")
	ErrIdentityAlreadyLinked     = errors.New("identity already linked to another user")
	ErrVerificationTokenNotFound = errors.New("verification token not found")
	ErrVerificationTokenExpired  = errors.New("verification token expired")
	ErrVerificationTokenConsumed = errors.New("verification token already used")
	ErrVerificationTokenInvalid  = errors.New("invalid verification token")
)

// Validation errors
var (
	ErrInvalidEmail     = errors.New("invalid email address")
	ErrInvalidUsername  = errors.New("invalid username format")
	ErrWeakPassword     = errors.New("password does not meet requirements")
	ErrEmailNotVerified = errors.New("email not verified")
)

// MFA errors
var (
	ErrMFARequired         = errors.New("multi-factor authentication required")
	ErrMFANotEnabled       = errors.New("MFA is not enabled for this account")
	ErrMFAAlreadyEnabled   = errors.New("MFA is already enabled")
	ErrInvalidMFACode      = errors.New("invalid MFA code")
	ErrInvalidRecoveryCode = errors.New("invalid or already used recovery code")
	ErrMFAChallengeExpired = errors.New("MFA challenge expired")
)
