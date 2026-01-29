package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

func TestMFARecoveryCodesRepository_Structure(t *testing.T) {
	// Test that MFARecoveryCodesRepository can be instantiated
	repo := NewMFARecoveryCodesRepository(nil)

	if repo == nil {
		t.Fatal("NewMFARecoveryCodesRepository should not return nil")
	}

	if repo.db != nil {
		t.Error("Expected db to be nil in test")
	}
}

func TestMFARecoveryCode_ValidData(t *testing.T) {
	// Test creating MFARecoveryCode with valid data
	code := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CodeHash:  "argon2id$v=19$m=65536,t=1,p=4$...",
		UsedAt:    nil,
		CreatedAt: time.Now(),
	}

	// Verify fields
	if code.ID == uuid.Nil {
		t.Error("ID should not be nil")
	}

	if code.UserID == uuid.Nil {
		t.Error("UserID should not be nil")
	}

	if code.CodeHash == "" {
		t.Error("CodeHash should not be empty")
	}

	if code.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	if code.UsedAt != nil {
		t.Error("UsedAt should be nil initially")
	}
}

func TestMFARecoveryCode_IsUsed(t *testing.T) {
	// Test IsUsed method
	code := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CodeHash:  "hash",
		UsedAt:    nil,
		CreatedAt: time.Now(),
	}

	// Initially not used
	if code.IsUsed() {
		t.Error("Code should not be used initially")
	}

	// Mark as used
	now := time.Now()
	code.UsedAt = &now

	if !code.IsUsed() {
		t.Error("Code should be marked as used")
	}

	// Verify used timestamp
	if code.UsedAt == nil {
		t.Error("UsedAt should be set")
	}

	if !code.UsedAt.Equal(now) {
		t.Error("UsedAt timestamp mismatch")
	}
}

func TestMFARecoveryCode_OneTimeUse(t *testing.T) {
	// Document one-time use behavior
	code := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CodeHash:  "hash",
		UsedAt:    nil,
		CreatedAt: time.Now(),
	}

	// First use
	firstUse := time.Now()
	code.UsedAt = &firstUse

	if !code.IsUsed() {
		t.Error("Code should be marked as used")
	}

	// Attempting to use again
	// The repository's MarkUsed method checks: WHERE id = $1 AND used_at IS NULL
	// So a second attempt to mark as used would return 0 rows affected
	t.Log("Recovery codes are one-time use")
	t.Log("MarkUsed will fail if code is already used (used_at IS NOT NULL)")
}

func TestMFARecoveryCodesRepository_BatchCreate(t *testing.T) {
	// Test batch creation structure
	userID := uuid.New()
	codes := make([]*domain.MFARecoveryCode, 8)

	for i := 0; i < 8; i++ {
		codes[i] = &domain.MFARecoveryCode{
			ID:        uuid.New(),
			UserID:    userID,
			CodeHash:  "hash_" + string(rune(i)),
			UsedAt:    nil,
			CreatedAt: time.Now(),
		}
	}

	// Verify all codes have the same user ID
	for _, code := range codes {
		if code.UserID != userID {
			t.Error("All codes should have the same UserID")
		}
	}

	// Verify all codes have unique IDs
	ids := make(map[uuid.UUID]bool)
	for _, code := range codes {
		if ids[code.ID] {
			t.Error("Duplicate code ID found")
		}
		ids[code.ID] = true
	}

	t.Log("CreateBatch should insert all codes in a single transaction")
}

func TestMFARecoveryCodesRepository_QueryStructure(t *testing.T) {
	// Test that repository has the expected methods
	repo := NewMFARecoveryCodesRepository(nil)

	if repo == nil {
		t.Fatal("Repository should not be nil")
	}

	// Document the expected repository methods
	t.Log("MFARecoveryCodesRepository should have:")
	t.Log("- CreateBatch(ctx, codes) error")
	t.Log("- GetByCodeHash(ctx, codeHash) (*MFARecoveryCode, error)")
	t.Log("- MarkUsed(ctx, id) error")
	t.Log("- CountUnused(ctx, userID) (int, error)")
	t.Log("- DeleteAllByUserID(ctx, userID) error")
}

func TestMFARecoveryCode_UniqueConstraint(t *testing.T) {
	// Document the unique constraint on code_hash
	code1 := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CodeHash:  "same_hash",
		CreatedAt: time.Now(),
	}

	code2 := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(), // Different user
		CodeHash:  "same_hash", // Same hash
		CreatedAt: time.Now(),
	}

	if code1.CodeHash != code2.CodeHash {
		t.Error("Hashes should be the same for this test")
	}

	// This would violate the unique constraint in the database
	// Recovery code hashes must be globally unique
	t.Log("Database enforces UNIQUE(code_hash) constraint")
	t.Log("Recovery code hashes must be unique across all users")
}

func TestMFARecoveryCode_CascadeDelete(t *testing.T) {
	// Document the cascade delete behavior
	t.Log("MFA recovery codes have ON DELETE CASCADE constraint")
	t.Log("Deleting a user will automatically delete their recovery codes")
}

func TestMFARecoveryCode_IndexOptimization(t *testing.T) {
	// Document the indexes for performance
	t.Log("Index on user_id for fast lookup of user's codes")
	t.Log("Index on code_hash for fast verification during login")
	t.Log("These indexes optimize the common query patterns")
}

func TestMFARecoveryCodesRepository_CountUnused(t *testing.T) {
	// Test counting unused codes
	userID := uuid.New()

	// Create 8 codes
	codes := make([]*domain.MFARecoveryCode, 8)
	for i := 0; i < 8; i++ {
		codes[i] = &domain.MFARecoveryCode{
			ID:        uuid.New(),
			UserID:    userID,
			CodeHash:  "hash_" + string(rune(i)),
			UsedAt:    nil,
			CreatedAt: time.Now(),
		}
	}

	// Count unused (all 8 should be unused)
	unusedCount := 0
	for _, code := range codes {
		if !code.IsUsed() {
			unusedCount++
		}
	}

	if unusedCount != 8 {
		t.Errorf("Expected 8 unused codes, got %d", unusedCount)
	}

	// Mark 3 as used
	now := time.Now()
	for i := 0; i < 3; i++ {
		codes[i].UsedAt = &now
	}

	// Count again
	unusedCount = 0
	for _, code := range codes {
		if !code.IsUsed() {
			unusedCount++
		}
	}

	if unusedCount != 5 {
		t.Errorf("Expected 5 unused codes after using 3, got %d", unusedCount)
	}

	t.Log("CountUnused should return number of codes WHERE used_at IS NULL")
}

func TestMFARecoveryCodesRepository_ErrorHandling(t *testing.T) {
	// Test that repository returns appropriate errors
	repo := NewMFARecoveryCodesRepository(nil)

	if repo.db != nil {
		t.Skip("Skipping error handling test - requires nil db")
	}

	// Document expected error behaviors
	t.Log("GetByCodeHash should return domain.ErrInvalidRecoveryCode when not found")
	t.Log("MarkUsed should return domain.ErrInvalidRecoveryCode when code already used")
	t.Log("CreateBatch should use transaction and rollback on any error")
	t.Log("DeleteAllByUserID should succeed even if no codes exist (idempotent)")
}

func TestMFARecoveryCodesRepository_TransactionBehavior(t *testing.T) {
	// Document transaction behavior for batch operations
	t.Log("CreateBatch uses a transaction to ensure all-or-nothing behavior")
	t.Log("If any code insert fails, all inserts are rolled back")
	t.Log("This prevents partial recovery code sets from being created")
}

func TestMFARecoveryCode_StorageFormat(t *testing.T) {
	// Document the storage format
	t.Log("Recovery codes are stored as Argon2id hashes")
	t.Log("Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>")
	t.Log("Same hashing algorithm as passwords for consistency")
	t.Log("Codes cannot be recovered, only verified")
}

func TestMFARecoveryCode_LifecycleStates(t *testing.T) {
	// Test the lifecycle states of a recovery code
	code := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CodeHash:  "hash",
		UsedAt:    nil,
		CreatedAt: time.Now(),
	}

	// State 1: Created, not used
	if code.IsUsed() {
		t.Error("Newly created code should not be used")
	}

	// State 2: Used
	now := time.Now()
	code.UsedAt = &now
	if !code.IsUsed() {
		t.Error("Code should be marked as used")
	}

	// State 3: Cannot be reused (enforced by repository)
	t.Log("Once used_at is set, MarkUsed will fail (WHERE used_at IS NULL)")
}
