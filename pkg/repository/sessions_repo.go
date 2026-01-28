package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// SessionsRepository handles session persistence.
type SessionsRepository struct {
	db *sql.DB
}

// NewSessionsRepository creates a new sessions repository.
func NewSessionsRepository(db *sql.DB) *SessionsRepository {
	return &SessionsRepository{db: db}
}

// Create creates a new session.
func (r *SessionsRepository) Create(ctx context.Context, session *domain.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, tenant_id, token_hash, created_at, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.TenantID, session.TokenHash,
		session.CreatedAt, session.ExpiresAt, session.Metadata,
	)
	return err
}

// GetByID retrieves a session by ID.
func (r *SessionsRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, token_hash, created_at, expires_at, revoked_at, last_seen_at, metadata
		FROM sessions
		WHERE id = $1
	`
	session := &domain.Session{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID, &session.UserID, &session.TenantID, &session.TokenHash,
		&session.CreatedAt, &session.ExpiresAt, &session.RevokedAt,
		&session.LastSeenAt, &session.Metadata,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

// GetByTokenHash retrieves a session by token hash.
func (r *SessionsRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, token_hash, created_at, expires_at, revoked_at, last_seen_at, metadata
		FROM sessions
		WHERE token_hash = $1 AND revoked_at IS NULL
	`
	session := &domain.Session{}
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&session.ID, &session.UserID, &session.TenantID, &session.TokenHash,
		&session.CreatedAt, &session.ExpiresAt, &session.RevokedAt,
		&session.LastSeenAt, &session.Metadata,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

// GetByUserID retrieves all active sessions for a user.
func (r *SessionsRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, token_hash, created_at, expires_at, revoked_at, last_seen_at, metadata
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*domain.Session
	for rows.Next() {
		session := &domain.Session{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.TenantID, &session.TokenHash,
			&session.CreatedAt, &session.ExpiresAt, &session.RevokedAt,
			&session.LastSeenAt, &session.Metadata,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// Revoke revokes a session.
func (r *SessionsRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}

// RevokeByTokenHash revokes a session by token hash.
func (r *SessionsRepository) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE token_hash = $1 AND revoked_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, tokenHash)
	return err
}

// RevokeAllByUserID revokes all sessions for a user.
func (r *SessionsRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// UpdateLastSeen updates the last_seen_at timestamp.
func (r *SessionsRepository) UpdateLastSeen(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE sessions
		SET last_seen_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// UpdateMetadata updates session metadata.
func (r *SessionsRepository) UpdateMetadata(ctx context.Context, id uuid.UUID, metadata json.RawMessage) error {
	query := `
		UPDATE sessions
		SET metadata = $2
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id, metadata)
	return err
}

// DeleteExpired deletes expired sessions older than the given duration.
func (r *SessionsRepository) DeleteExpired(ctx context.Context, olderThan time.Duration) (int64, error) {
	query := `
		DELETE FROM sessions
		WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1)
	`
	cutoff := time.Now().Add(-olderThan)
	result, err := r.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetByUserIDAndTenant retrieves all active sessions for a user in a specific tenant.
func (r *SessionsRepository) GetByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, token_hash, created_at, expires_at, revoked_at, last_seen_at, metadata
		FROM sessions
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*domain.Session
	for rows.Next() {
		session := &domain.Session{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.TenantID, &session.TokenHash,
			&session.CreatedAt, &session.ExpiresAt, &session.RevokedAt,
			&session.LastSeenAt, &session.Metadata,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// RevokeAllByUserIDAndTenant revokes all sessions for a user in a specific tenant.
func (r *SessionsRepository) RevokeAllByUserIDAndTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, userID, tenantID)
	return err
}
