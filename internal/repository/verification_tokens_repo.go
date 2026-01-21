package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/domain"
)

// VerificationTokensRepository handles verification token persistence.
type VerificationTokensRepository struct {
	db *sql.DB
}

// NewVerificationTokensRepository creates a new verification tokens repository.
func NewVerificationTokensRepository(db *sql.DB) *VerificationTokensRepository {
	return &VerificationTokensRepository{db: db}
}

// Create creates a new verification token.
func (r *VerificationTokensRepository) Create(ctx context.Context, token *domain.VerificationToken) error {
	return r.CreateTx(ctx, r.db, token)
}

// CreateTx creates a new verification token within a transaction.
func (r *VerificationTokensRepository) CreateTx(ctx context.Context, q Querier, token *domain.VerificationToken) error {
	query := `
		INSERT INTO verification_tokens (id, user_id, token_hash, kind, created_at, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := q.ExecContext(ctx, query,
		token.ID, token.UserID, token.TokenHash, token.Kind,
		token.CreatedAt, token.ExpiresAt, token.Metadata,
	)
	return err
}

// GetByTokenHash retrieves a verification token by token hash and kind.
func (r *VerificationTokensRepository) GetByTokenHash(ctx context.Context, tokenHash string, kind domain.VerificationTokenKind) (*domain.VerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, kind, created_at, expires_at, consumed_at, metadata
		FROM verification_tokens
		WHERE token_hash = $1 AND kind = $2
	`
	token := &domain.VerificationToken{}
	err := r.db.QueryRowContext(ctx, query, tokenHash, kind).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.Kind,
		&token.CreatedAt, &token.ExpiresAt, &token.ConsumedAt, &token.Metadata,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrVerificationTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return token, nil
}

// MarkConsumed marks a verification token as consumed.
func (r *VerificationTokensRepository) MarkConsumed(ctx context.Context, tokenID uuid.UUID) error {
	return r.MarkConsumedTx(ctx, r.db, tokenID)
}

// MarkConsumedTx marks a verification token as consumed within a transaction.
func (r *VerificationTokensRepository) MarkConsumedTx(ctx context.Context, q Querier, tokenID uuid.UUID) error {
	query := `
		UPDATE verification_tokens
		SET consumed_at = NOW()
		WHERE id = $1 AND consumed_at IS NULL
	`
	result, err := q.ExecContext(ctx, query, tokenID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrVerificationTokenNotFound
	}
	return nil
}

// RevokeActiveTokens revokes (marks as consumed) all active tokens of a specific kind for a user.
func (r *VerificationTokensRepository) RevokeActiveTokens(ctx context.Context, userID uuid.UUID, kind domain.VerificationTokenKind) error {
	return r.RevokeActiveTokensTx(ctx, r.db, userID, kind)
}

// RevokeActiveTokensTx revokes all active tokens within a transaction.
func (r *VerificationTokensRepository) RevokeActiveTokensTx(ctx context.Context, q Querier, userID uuid.UUID, kind domain.VerificationTokenKind) error {
	query := `
		UPDATE verification_tokens
		SET consumed_at = NOW()
		WHERE user_id = $1 AND kind = $2 AND consumed_at IS NULL AND expires_at > NOW()
	`
	_, err := q.ExecContext(ctx, query, userID, kind)
	return err
}
