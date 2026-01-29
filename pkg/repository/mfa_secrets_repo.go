package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// MFASecretsRepository handles database operations for MFA secrets
type MFASecretsRepository struct {
	db *sql.DB
}

// NewMFASecretsRepository creates a new MFA secrets repository
func NewMFASecretsRepository(db *sql.DB) *MFASecretsRepository {
	return &MFASecretsRepository{db: db}
}

// Create inserts a new MFA secret
func (r *MFASecretsRepository) Create(ctx context.Context, secret *domain.MFASecret) error {
	query := `
		INSERT INTO mfa_secrets (id, user_id, method, secret_encrypted, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(ctx, query,
		secret.ID,
		secret.UserID,
		secret.Method,
		secret.SecretEncrypted,
		secret.CreatedAt,
		secret.LastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create MFA secret: %w", err)
	}
	return nil
}

// GetByUserIDAndMethod retrieves an MFA secret by user ID and method
func (r *MFASecretsRepository) GetByUserIDAndMethod(ctx context.Context, userID uuid.UUID, method domain.MFAMethod) (*domain.MFASecret, error) {
	query := `
		SELECT id, user_id, method, secret_encrypted, created_at, last_used_at
		FROM mfa_secrets
		WHERE user_id = $1 AND method = $2
	`

	secret := &domain.MFASecret{}
	err := r.db.QueryRowContext(ctx, query, userID, method).Scan(
		&secret.ID,
		&secret.UserID,
		&secret.Method,
		&secret.SecretEncrypted,
		&secret.CreatedAt,
		&secret.LastUsedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrMFANotEnabled
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA secret: %w", err)
	}
	return secret, nil
}

// UpdateLastUsed updates the last used timestamp for an MFA secret
func (r *MFASecretsRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE mfa_secrets
		SET last_used_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to update MFA secret last used: %w", err)
	}
	return nil
}

// Delete removes an MFA secret by user ID and method
func (r *MFASecretsRepository) Delete(ctx context.Context, userID uuid.UUID, method domain.MFAMethod) error {
	query := `
		DELETE FROM mfa_secrets
		WHERE user_id = $1 AND method = $2
	`
	_, err := r.db.ExecContext(ctx, query, userID, method)
	if err != nil {
		return fmt.Errorf("failed to delete MFA secret: %w", err)
	}
	return nil
}

// DeleteAllByUserID removes all MFA secrets for a user
func (r *MFASecretsRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		DELETE FROM mfa_secrets
		WHERE user_id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete all MFA secrets: %w", err)
	}
	return nil
}
