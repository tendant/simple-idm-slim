package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/repository"
)

type VerificationConfig struct {
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration
}

type VerificationService struct {
	config VerificationConfig
	db     *sql.DB
	tokens *repository.VerificationTokensRepository
	users  *repository.UsersRepository
}

type CreateVerificationTokenOpts struct {
	IP        string
	UserAgent string
}

func NewVerificationService(
	config VerificationConfig,
	db *sql.DB,
	tokens *repository.VerificationTokensRepository,
	users *repository.UsersRepository,
) *VerificationService {
	return &VerificationService{
		config: config,
		db:     db,
		tokens: tokens,
		users:  users,
	}
}

// CreateEmailVerificationToken creates a new email verification token for a user.
// It revokes any existing active tokens of the same kind before creating a new one.
func (s *VerificationService) CreateEmailVerificationToken(
	ctx context.Context,
	userID uuid.UUID,
	opts CreateVerificationTokenOpts,
) (string, error) {
	return s.createToken(ctx, userID, domain.TokenKindEmailVerification, s.config.EmailVerificationTTL, opts)
}

// CreatePasswordResetToken creates a new password reset token for a user.
// It revokes any existing active tokens of the same kind before creating a new one.
func (s *VerificationService) CreatePasswordResetToken(
	ctx context.Context,
	userID uuid.UUID,
	opts CreateVerificationTokenOpts,
) (string, error) {
	return s.createToken(ctx, userID, domain.TokenKindPasswordReset, s.config.PasswordResetTTL, opts)
}

func (s *VerificationService) createToken(
	ctx context.Context,
	userID uuid.UUID,
	kind domain.VerificationTokenKind,
	ttl time.Duration,
	opts CreateVerificationTokenOpts,
) (string, error) {
	rawToken, err := GenerateToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	tokenHash := HashToken(rawToken)

	metadata := map[string]string{
		"ip":         opts.IP,
		"user_agent": opts.UserAgent,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	token := &domain.VerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		Kind:      kind,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		Metadata:  metadataJSON,
	}

	// Revoke existing tokens and create new one in a transaction
	err = repository.Tx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.tokens.RevokeActiveTokensTx(ctx, tx, userID, kind); err != nil {
			return fmt.Errorf("failed to revoke active tokens: %w", err)
		}
		if err := s.tokens.CreateTx(ctx, tx, token); err != nil {
			return fmt.Errorf("failed to create token: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return rawToken, nil
}

// VerifyEmailToken validates an email verification token and marks the user's email as verified.
// It returns the user ID if successful.
func (s *VerificationService) VerifyEmailToken(ctx context.Context, rawToken string) (uuid.UUID, error) {
	tokenHash := HashToken(rawToken)

	token, err := s.tokens.GetByTokenHash(ctx, tokenHash, domain.TokenKindEmailVerification)
	if err != nil {
		return uuid.Nil, domain.ErrVerificationTokenInvalid
	}

	if !token.IsValid() {
		if token.ConsumedAt != nil {
			return uuid.Nil, domain.ErrVerificationTokenConsumed
		}
		return uuid.Nil, domain.ErrVerificationTokenExpired
	}

	// Mark user as verified and consume token in a transaction
	err = repository.Tx(ctx, s.db, func(tx *sql.Tx) error {
		// Mark token as consumed
		if err := s.tokens.MarkConsumedTx(ctx, tx, token.ID); err != nil {
			return fmt.Errorf("failed to consume token: %w", err)
		}

		// Update user's email_verified field
		query := `UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1`
		if _, err := tx.ExecContext(ctx, query, token.UserID); err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}

		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	return token.UserID, nil
}

// ValidatePasswordResetToken validates a password reset token without consuming it.
// It returns the user ID if the token is valid.
func (s *VerificationService) ValidatePasswordResetToken(ctx context.Context, rawToken string) (uuid.UUID, error) {
	tokenHash := HashToken(rawToken)

	token, err := s.tokens.GetByTokenHash(ctx, tokenHash, domain.TokenKindPasswordReset)
	if err != nil {
		return uuid.Nil, domain.ErrVerificationTokenInvalid
	}

	if !token.IsValid() {
		if token.ConsumedAt != nil {
			return uuid.Nil, domain.ErrVerificationTokenConsumed
		}
		return uuid.Nil, domain.ErrVerificationTokenExpired
	}

	return token.UserID, nil
}

// ConsumePasswordResetToken marks a password reset token as consumed.
func (s *VerificationService) ConsumePasswordResetToken(ctx context.Context, rawToken string) error {
	tokenHash := HashToken(rawToken)

	token, err := s.tokens.GetByTokenHash(ctx, tokenHash, domain.TokenKindPasswordReset)
	if err != nil {
		return domain.ErrVerificationTokenInvalid
	}

	if !token.IsValid() {
		if token.ConsumedAt != nil {
			return domain.ErrVerificationTokenConsumed
		}
		return domain.ErrVerificationTokenExpired
	}

	return s.tokens.MarkConsumed(ctx, token.ID)
}
