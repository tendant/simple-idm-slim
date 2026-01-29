package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

const (
	// Token lengths
	refreshTokenLen = 32

	// Default token lifetimes
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// SessionConfig holds session configuration.
type SessionConfig struct {
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	JWTSecret            []byte
	Issuer               string
	FingerprintEnabled   bool
	DetectReuseEnabled   bool
}

// SessionService handles session management (the IssueSession function from the design).
type SessionService struct {
	config   SessionConfig
	sessions *repository.SessionsRepository
	users    *repository.UsersRepository
}

// NewSessionService creates a new session service.
func NewSessionService(config SessionConfig, sessions *repository.SessionsRepository, users *repository.UsersRepository) *SessionService {
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
	return &SessionService{
		config:   config,
		sessions: sessions,
		users:    users,
	}
}

// AccessTokenTTL returns the access token TTL.
func (s *SessionService) AccessTokenTTL() time.Duration {
	return s.config.AccessTokenTTL
}

// RefreshTokenTTL returns the refresh token TTL.
func (s *SessionService) RefreshTokenTTL() time.Duration {
	return s.config.RefreshTokenTTL
}

// IssueSessionOpts holds options for session issuance.
type IssueSessionOpts struct {
	// IP address of the client
	IP string
	// User agent of the client
	UserAgent string
	// Request is the HTTP request (for fingerprinting)
	Request *http.Request
	// MFAVerified indicates whether MFA was verified for this session
	MFAVerified bool
}

// AccessTokenClaims represents the claims in an access token.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	MFAVerified   bool   `json:"mfa_verified,omitempty"`
}

// IssueSession creates a new session and returns access/refresh tokens.
// This is the single entry point for session creation - all auth methods use this.
func (s *SessionService) IssueSession(ctx context.Context, userID uuid.UUID, opts IssueSessionOpts) (*domain.TokenPair, error) {
	// Get user for token claims
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	// Generate refresh token (opaque, stored hashed)
	refreshToken, err := GenerateToken(refreshTokenLen)
	if err != nil {
		return nil, err
	}
	refreshTokenHash := HashToken(refreshToken)

	// Create session in database
	sessionID := uuid.New()
	session := &domain.Session{
		ID:        sessionID,
		UserID:    userID,
		TokenHash: refreshTokenHash,
		CreatedAt: now,
		ExpiresAt: now.Add(s.config.RefreshTokenTTL),
	}

	// Store metadata and fingerprint if provided
	if opts.IP != "" || opts.UserAgent != "" || opts.Request != nil {
		metadata := domain.SessionMetadata{
			IP:        opts.IP,
			UserAgent: opts.UserAgent,
		}

		// Add fingerprint if enabled and request provided
		if s.config.FingerprintEnabled && opts.Request != nil {
			fp := GenerateFingerprint(opts.Request)
			metadata.FingerprintHash = fp.Hash
			metadata.FingerprintIP = fp.IPAddress
			metadata.FingerprintUA = fp.UserAgent
		}

		metadataJSON, _ := json.Marshal(metadata)
		session.Metadata = metadataJSON
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}

	// Generate access token (JWT)
	accessTokenExpiry := now.Add(s.config.AccessTokenTTL)
	name := ""
	if user.Name != nil {
		name = *user.Name
	}
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiry),
			Issuer:    s.config.Issuer,
			ID:        sessionID.String(),
		},
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          name,
		MFAVerified:   !user.MFAEnabled || opts.MFAVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(s.config.JWTSecret)
	if err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenTTL.Seconds()),
		ExpiresAt:    accessTokenExpiry,
	}, nil
}

// RefreshSession refreshes an access token using a refresh token.
func (s *SessionService) RefreshSession(ctx context.Context, refreshToken string, opts IssueSessionOpts) (*domain.TokenPair, error) {
	tokenHash := HashToken(refreshToken)

	// Find session by token hash
	session, err := s.sessions.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// Check if session is valid
	if !session.IsValid() {
		if session.RevokedAt != nil {
			return nil, domain.ErrSessionRevoked
		}
		return nil, domain.ErrSessionExpired
	}

	// Validate fingerprint if enabled
	if s.config.FingerprintEnabled && opts.Request != nil && len(session.Metadata) > 0 {
		var metadata domain.SessionMetadata
		if err := json.Unmarshal(session.Metadata, &metadata); err == nil && metadata.FingerprintHash != "" {
			currentFp := GenerateFingerprint(opts.Request)

			// Check if fingerprint matches
			if metadata.FingerprintHash != currentFp.Hash {
				// Fingerprint mismatch - possible token theft
				if s.config.DetectReuseEnabled {
					// Revoke the session for security
					_ = s.sessions.Revoke(ctx, session.ID)
					return nil, domain.ErrSessionFingerprint
				}
			}
		}
	}

	// Update last seen
	_ = s.sessions.UpdateLastSeen(ctx, session.ID)

	// Get user for new access token
	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	// Generate new access token
	now := time.Now()
	accessTokenExpiry := now.Add(s.config.AccessTokenTTL)
	name := ""
	if user.Name != nil {
		name = *user.Name
	}
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   session.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiry),
			Issuer:    s.config.Issuer,
			ID:        session.ID.String(),
		},
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          name,
		MFAVerified:   !user.MFAEnabled || opts.MFAVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(s.config.JWTSecret)
	if err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Return same refresh token
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenTTL.Seconds()),
		ExpiresAt:    accessTokenExpiry,
	}, nil
}

// RevokeSession revokes a session by refresh token.
func (s *SessionService) RevokeSession(ctx context.Context, refreshToken string) error {
	tokenHash := HashToken(refreshToken)
	return s.sessions.RevokeByTokenHash(ctx, tokenHash)
}

// RevokeAllSessions revokes all sessions for a user.
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	return s.sessions.RevokeAllByUserID(ctx, userID)
}

// ValidateAccessToken validates an access token and returns the claims.
func (s *SessionService) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.ErrInvalidToken
		}
		return s.config.JWTSecret, nil
	})
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	return claims, nil
}

// GetUserIDFromToken extracts the user ID from an access token.
func (s *SessionService) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
	claims, err := s.ValidateAccessToken(tokenString)
	if err != nil {
		return uuid.Nil, err
	}

	return uuid.Parse(claims.Subject)
}
