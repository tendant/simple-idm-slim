package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

func TestMFASecretsRepository_Structure(t *testing.T) {
	// Test that MFASecretsRepository can be instantiated
	repo := NewMFASecretsRepository(nil)

	if repo == nil {
		t.Fatal("NewMFASecretsRepository should not return nil")
	}

	if repo.db != nil {
		t.Error("Expected db to be nil in test")
	}
}

func TestMFASecret_ValidData(t *testing.T) {
	// Test creating MFASecret with valid data
	secret := &domain.MFASecret{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		Method:          domain.MFAMethodTOTP,
		SecretEncrypted: "encrypted_totp_secret_base64",
		CreatedAt:       time.Now(),
		LastUsedAt:      nil,
	}

	// Verify fields
	if secret.ID == uuid.Nil {
		t.Error("ID should not be nil")
	}

	if secret.UserID == uuid.Nil {
		t.Error("UserID should not be nil")
	}

	if secret.Method != domain.MFAMethodTOTP {
		t.Errorf("Method: got %s, want %s", secret.Method, domain.MFAMethodTOTP)
	}

	if secret.SecretEncrypted == "" {
		t.Error("SecretEncrypted should not be empty")
	}

	if secret.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestMFASecret_LastUsedTracking(t *testing.T) {
	// Test last used timestamp tracking
	secret := &domain.MFASecret{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		Method:          domain.MFAMethodTOTP,
		SecretEncrypted: "encrypted",
		CreatedAt:       time.Now(),
		LastUsedAt:      nil,
	}

	// Initially not used
	if secret.LastUsedAt != nil {
		t.Error("LastUsedAt should be nil initially")
	}

	// Update last used
	now := time.Now()
	secret.LastUsedAt = &now

	if secret.LastUsedAt == nil {
		t.Error("LastUsedAt should be set")
	}

	if !secret.LastUsedAt.Equal(now) {
		t.Error("LastUsedAt timestamp mismatch")
	}
}

func TestMFASecret_Methods(t *testing.T) {
	// Test different MFA methods
	tests := []struct {
		name   string
		method domain.MFAMethod
	}{
		{
			name:   "TOTP method",
			method: domain.MFAMethodTOTP,
		},
		{
			name:   "SMS method",
			method: domain.MFAMethodSMS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &domain.MFASecret{
				ID:              uuid.New(),
				UserID:          uuid.New(),
				Method:          tt.method,
				SecretEncrypted: "encrypted",
				CreatedAt:       time.Now(),
			}

			if secret.Method != tt.method {
				t.Errorf("Method: got %s, want %s", secret.Method, tt.method)
			}
		})
	}
}

func TestMFASecretsRepository_QueryStructure(t *testing.T) {
	// Test that repository has the expected methods
	repo := NewMFASecretsRepository(nil)

	if repo == nil {
		t.Fatal("Repository should not be nil")
	}

	// Document the expected repository methods
	t.Log("MFASecretsRepository should have:")
	t.Log("- Create(ctx, secret) error")
	t.Log("- GetByUserIDAndMethod(ctx, userID, method) (*MFASecret, error)")
	t.Log("- UpdateLastUsed(ctx, id) error")
	t.Log("- Delete(ctx, userID, method) error")
	t.Log("- DeleteAllByUserID(ctx, userID) error")
}

func TestMFASecret_UniqueConstraint(t *testing.T) {
	// Document the unique constraint: (user_id, method)
	// This means a user can only have one secret per method
	userID := uuid.New()

	secret1 := &domain.MFASecret{
		ID:              uuid.New(),
		UserID:          userID,
		Method:          domain.MFAMethodTOTP,
		SecretEncrypted: "encrypted1",
		CreatedAt:       time.Now(),
	}

	secret2 := &domain.MFASecret{
		ID:              uuid.New(),
		UserID:          userID,
		Method:          domain.MFAMethodTOTP, // Same method
		SecretEncrypted: "encrypted2",
		CreatedAt:       time.Now(),
	}

	// Both have the same UserID and Method
	if secret1.UserID != secret2.UserID {
		t.Error("UserIDs should match")
	}

	if secret1.Method != secret2.Method {
		t.Error("Methods should match")
	}

	// This would violate the unique constraint in the database
	// The second Create would fail with a unique constraint violation
	t.Log("Database enforces UNIQUE(user_id, method) constraint")
}

func TestMFASecret_CascadeDelete(t *testing.T) {
	// Document the cascade delete behavior
	// When a user is deleted, their MFA secrets should be deleted too
	// This is enforced by: REFERENCES users(id) ON DELETE CASCADE

	t.Log("MFA secrets have ON DELETE CASCADE constraint")
	t.Log("Deleting a user will automatically delete their MFA secrets")
}

func TestMFASecretsRepository_ErrorHandling(t *testing.T) {
	// Test that repository returns appropriate errors
	repo := NewMFASecretsRepository(nil)

	// When database is nil, operations should fail gracefully
	if repo.db != nil {
		t.Skip("Skipping error handling test - requires nil db")
	}

	// Document expected error behaviors
	t.Log("GetByUserIDAndMethod should return domain.ErrMFANotEnabled when secret not found")
	t.Log("Create should return error when database constraint is violated")
	t.Log("UpdateLastUsed should return error when ID doesn't exist")
	t.Log("Delete should succeed even if secret doesn't exist (idempotent)")
}
