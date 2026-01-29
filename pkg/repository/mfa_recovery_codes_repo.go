package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// MFARecoveryCodesRepository handles database operations for MFA recovery codes
type MFARecoveryCodesRepository struct {
	db *sql.DB
}

// NewMFARecoveryCodesRepository creates a new MFA recovery codes repository
func NewMFARecoveryCodesRepository(db *sql.DB) *MFARecoveryCodesRepository {
	return &MFARecoveryCodesRepository{db: db}
}

// CreateBatch inserts multiple recovery codes in a single transaction
func (r *MFARecoveryCodesRepository) CreateBatch(ctx context.Context, codes []*domain.MFARecoveryCode) error {
	if len(codes) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, code := range codes {
		_, err := stmt.ExecContext(ctx,
			code.ID,
			code.UserID,
			code.CodeHash,
			code.UsedAt,
			code.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert recovery code: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByCodeHash retrieves a recovery code by its hash
func (r *MFARecoveryCodesRepository) GetByCodeHash(ctx context.Context, codeHash string) (*domain.MFARecoveryCode, error) {
	query := `
		SELECT id, user_id, code_hash, used_at, created_at
		FROM mfa_recovery_codes
		WHERE code_hash = $1
	`

	code := &domain.MFARecoveryCode{}
	err := r.db.QueryRowContext(ctx, query, codeHash).Scan(
		&code.ID,
		&code.UserID,
		&code.CodeHash,
		&code.UsedAt,
		&code.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrInvalidRecoveryCode
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery code: %w", err)
	}
	return code, nil
}

// MarkUsed marks a recovery code as used
func (r *MFARecoveryCodesRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE mfa_recovery_codes
		SET used_at = NOW()
		WHERE id = $1 AND used_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark recovery code as used: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return domain.ErrInvalidRecoveryCode
	}

	return nil
}

// CountUnused returns the number of unused recovery codes for a user
func (r *MFARecoveryCodesRepository) CountUnused(ctx context.Context, userID uuid.UUID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM mfa_recovery_codes
		WHERE user_id = $1 AND used_at IS NULL
	`

	var count int
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count unused recovery codes: %w", err)
	}
	return count, nil
}

// DeleteAllByUserID removes all recovery codes for a user
func (r *MFARecoveryCodesRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		DELETE FROM mfa_recovery_codes
		WHERE user_id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete all recovery codes: %w", err)
	}
	return nil
}
