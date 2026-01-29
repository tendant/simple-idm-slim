package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
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
	db                   *sql.DB
	users                *repository.UsersRepository
	creds                *repository.CredentialsRepository
	policy               *PasswordPolicy
	strictEmailValidation bool
	blockDisposableEmail bool
}

// NewPasswordService creates a new password service.
func NewPasswordService(db *sql.DB, users *repository.UsersRepository, creds *repository.CredentialsRepository, policy *PasswordPolicy, strictEmailValidation, blockDisposableEmail bool) *PasswordService {
	return &PasswordService{
		db:                   db,
		users:                users,
		creds:                creds,
		policy:               policy,
		strictEmailValidation: strictEmailValidation,
		blockDisposableEmail: blockDisposableEmail,
	}
}

// Register creates a new user with password credentials.
func (s *PasswordService) Register(ctx context.Context, email, password, name string, username *string) (*domain.User, error) {
	// Validate and normalize email
	if err := ValidateEmail(email, s.strictEmailValidation, s.blockDisposableEmail); err != nil {
		return nil, err
	}
	email = NormalizeEmail(email)

	// Validate password against policy
	if s.policy != nil {
		if err := s.policy.ValidatePassword(password); err != nil {
			return nil, err
		}
	}

	// Sanitize name
	name = SanitizeName(name)

	// Check if user already exists by email
	exists, err := s.users.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserAlreadyExists
	}

	// Validate and check username if provided
	if username != nil && *username != "" {
		// Validate username format
		if err := ValidateUsername(*username); err != nil {
			return nil, err
		}

		// Check if username already exists
		exists, err := s.users.ExistsByUsername(ctx, *username)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, domain.ErrUsernameAlreadyExists
		}
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
		Username:      username,
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

// Authenticate verifies identifier (email or username) and password, returns user ID on success.
// Implements account lockout after 5 failed attempts with 15-minute lockout duration.
func (s *PasswordService) Authenticate(ctx context.Context, identifier, password string) (uuid.UUID, error) {
	const (
		maxFailedAttempts = 5
		lockoutDuration   = 15 * time.Minute
	)

	// Find user by email or username
	user, err := s.users.GetByEmailOrUsername(ctx, identifier)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return uuid.Nil, domain.ErrInvalidCredentials
		}
		return uuid.Nil, err
	}

	// Check if account is currently locked
	if user.IsLocked() {
		return uuid.Nil, domain.ErrAccountLocked
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
		// Increment failed login attempts
		_ = s.users.IncrementFailedLoginAttempts(ctx, user.ID, lockoutDuration, maxFailedAttempts)
		return uuid.Nil, domain.ErrInvalidCredentials
	}

	// Successful login - reset failed attempts
	if user.FailedLoginAttempts > 0 || user.LockedUntil != nil {
		_ = s.users.ResetFailedLoginAttempts(ctx, user.ID)
	}

	return user.ID, nil
}

// GetUserByEmail retrieves a user by email address.
func (s *PasswordService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.users.GetByEmail(ctx, email)
}

// GetUserByID retrieves a user by ID.
func (s *PasswordService) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.users.GetByID(ctx, userID)
}

// ChangePassword changes a user's password.
func (s *PasswordService) ChangePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	// Validate password against policy
	if s.policy != nil {
		if err := s.policy.ValidatePassword(newPassword); err != nil {
			return err
		}
	}

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
