package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/domain"
)

// UsersRepository handles user persistence.
type UsersRepository struct {
	db *sql.DB
}

// NewUsersRepository creates a new users repository.
func NewUsersRepository(db *sql.DB) *UsersRepository {
	return &UsersRepository{db: db}
}

// Create creates a new user.
func (r *UsersRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.Name, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

// CreateTx creates a new user within a transaction.
func (r *UsersRepository) CreateTx(ctx context.Context, tx *sql.Tx, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.Name, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

// GetByID retrieves a user by ID.
func (r *UsersRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, email_verified, name, failed_login_attempts, locked_until,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`
	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.EmailVerified, &user.Name,
		&user.FailedLoginAttempts, &user.LockedUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetByEmail retrieves a user by email.
func (r *UsersRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, email_verified, name, failed_login_attempts, locked_until,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`
	user := &domain.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.EmailVerified, &user.Name,
		&user.FailedLoginAttempts, &user.LockedUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// Update updates a user.
func (r *UsersRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users
		SET email = $2, email_verified = $3, name = $4,
		    failed_login_attempts = $5, locked_until = $6, updated_at = $7
		WHERE id = $1 AND deleted_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.Name,
		user.FailedLoginAttempts, user.LockedUntil, time.Now(),
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

// IncrementFailedLoginAttempts increments the failed login attempts counter.
func (r *UsersRepository) IncrementFailedLoginAttempts(ctx context.Context, userID uuid.UUID, lockoutDuration time.Duration, maxAttempts int) error {
	query := `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE
		        WHEN failed_login_attempts + 1 >= $2 THEN NOW() + $3::interval
		        ELSE locked_until
		    END,
		    updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, userID, maxAttempts, lockoutDuration)
	return err
}

// ResetFailedLoginAttempts resets the failed login attempts and clears lockout.
func (r *UsersRepository) ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users
		SET failed_login_attempts = 0,
		    locked_until = NULL,
		    updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// SoftDelete soft-deletes a user.
func (r *UsersRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET deleted_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
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
		return domain.ErrUserNotFound
	}
	return nil
}

// Delete permanently deletes a user and all related data.
// This will cascade delete credentials, identities, sessions, and verification tokens
// based on database foreign key constraints.
func (r *UsersRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

// ExistsByEmail checks if a user exists by email.
func (r *UsersRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, email).Scan(&exists)
	return exists, err
}
