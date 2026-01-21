package domain

import "errors"

// Authentication errors
var (
	ErrUserNotFound              = errors.New("user not found")
	ErrUserAlreadyExists         = errors.New("user already exists")
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrSessionNotFound           = errors.New("session not found")
	ErrSessionExpired            = errors.New("session expired")
	ErrSessionRevoked            = errors.New("session revoked")
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
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrWeakPassword    = errors.New("password does not meet requirements")
	ErrEmailNotVerified = errors.New("email not verified")
)
