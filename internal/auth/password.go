package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/repository"
	"golang.org/x/crypto/argon2"
)

// Argon2 parameters (OWASP recommended)
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
)

// PasswordService handles password authentication.
type PasswordService struct {
	db        *sql.DB
	users     *repository.UsersRepository
	creds     *repository.CredentialsRepository
}

// NewPasswordService creates a new password service.
func NewPasswordService(db *sql.DB, users *repository.UsersRepository, creds *repository.CredentialsRepository) *PasswordService {
	return &PasswordService{
		db:    db,
		users: users,
		creds: creds,
	}
}

// Register creates a new user with password credentials.
func (s *PasswordService) Register(ctx context.Context, email, password, name string) (*domain.User, error) {
	// Check if user already exists
	exists, err := s.users.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		EmailVerified: false,
		Name:          &name,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	cred := &domain.UserPassword{
		UserID:            user.ID,
		PasswordHash:      hash,
		PasswordUpdatedAt: now,
	}

	// Create user and credentials in a transaction
	err = repository.Tx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.users.CreateTx(ctx, tx, user); err != nil {
			return err
		}
		return s.creds.CreateTx(ctx, tx, cred)
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Authenticate verifies email and password, returns user ID on success.
func (s *PasswordService) Authenticate(ctx context.Context, email, password string) (uuid.UUID, error) {
	// Find user by email
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return uuid.Nil, domain.ErrInvalidCredentials
		}
		return uuid.Nil, err
	}

	// Get password credentials
	cred, err := s.creds.GetByUserID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return uuid.Nil, domain.ErrInvalidCredentials
		}
		return uuid.Nil, err
	}

	// Verify password
	if !VerifyPassword(password, cred.PasswordHash) {
		return uuid.Nil, domain.ErrInvalidCredentials
	}

	return user.ID, nil
}

// GetUserByEmail retrieves a user by email address.
func (s *PasswordService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.users.GetByEmail(ctx, email)
}

// ChangePassword changes a user's password.
func (s *PasswordService) ChangePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	return s.creds.Update(ctx, &domain.UserPassword{
		UserID:       userID,
		PasswordHash: hash,
	})
}

// HashPassword hashes a password using Argon2id.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := randomBytes(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encode as: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	encoded := encodeArgon2Hash(hash, salt, argon2Time, argon2Memory, argon2Threads)
	return encoded, nil
}

// VerifyPassword verifies a password against an Argon2id hash.
func VerifyPassword(password, encodedHash string) bool {
	hash, salt, time, memory, threads, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return false
	}

	computed := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))
	return constantTimeCompare(hash, computed)
}
