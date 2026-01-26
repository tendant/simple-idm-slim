package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUser_UsernameField(t *testing.T) {
	tests := []struct {
		name     string
		username *string
		wantNil  bool
	}{
		{
			name:     "username is nil",
			username: nil,
			wantNil:  true,
		},
		{
			name:     "username is set",
			username: stringPtr("testuser"),
			wantNil:  false,
		},
		{
			name:     "username is empty string",
			username: stringPtr(""),
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{
				ID:       uuid.New(),
				Email:    "test@example.com",
				Username: tt.username,
			}

			if (user.Username == nil) != tt.wantNil {
				t.Errorf("Username nil check: got %v, want nil=%v", user.Username, tt.wantNil)
			}

			if !tt.wantNil && user.Username != nil {
				if *user.Username != *tt.username {
					t.Errorf("Username value: got %q, want %q", *user.Username, *tt.username)
				}
			}
		})
	}
}

func TestUser_IsLocked(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	tests := []struct {
		name        string
		lockedUntil *time.Time
		want        bool
	}{
		{
			name:        "not locked (nil)",
			lockedUntil: nil,
			want:        false,
		},
		{
			name:        "locked (future time)",
			lockedUntil: &future,
			want:        true,
		},
		{
			name:        "not locked (past time)",
			lockedUntil: &past,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{
				ID:          uuid.New(),
				Email:       "test@example.com",
				LockedUntil: tt.lockedUntil,
			}

			if got := user.IsLocked(); got != tt.want {
				t.Errorf("IsLocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_StructFields(t *testing.T) {
	// Test that all required fields exist
	userID := uuid.New()
	email := "test@example.com"
	username := "testuser"
	name := "Test User"
	now := time.Now()
	lockedUntil := now.Add(1 * time.Hour)

	user := User{
		ID:                  userID,
		Email:               email,
		Username:            &username,
		EmailVerified:       true,
		Name:                &name,
		FailedLoginAttempts: 3,
		LockedUntil:         &lockedUntil,
		CreatedAt:           now,
		UpdatedAt:           now,
		DeletedAt:           nil,
	}

	// Verify all fields are accessible
	if user.ID != userID {
		t.Errorf("ID: got %v, want %v", user.ID, userID)
	}
	if user.Email != email {
		t.Errorf("Email: got %v, want %v", user.Email, email)
	}
	if user.Username == nil || *user.Username != username {
		t.Errorf("Username: got %v, want %v", user.Username, username)
	}
	if !user.EmailVerified {
		t.Error("EmailVerified should be true")
	}
	if user.Name == nil || *user.Name != name {
		t.Errorf("Name: got %v, want %v", user.Name, name)
	}
	if user.FailedLoginAttempts != 3 {
		t.Errorf("FailedLoginAttempts: got %d, want 3", user.FailedLoginAttempts)
	}
	if user.LockedUntil == nil {
		t.Error("LockedUntil should not be nil")
	}
	if user.DeletedAt != nil {
		t.Error("DeletedAt should be nil")
	}
}

func TestUserPassword_Struct(t *testing.T) {
	userID := uuid.New()
	hash := "$argon2id$v=19$m=65536,t=1,p=4$..."
	now := time.Now()

	pwd := UserPassword{
		UserID:            userID,
		PasswordHash:      hash,
		PasswordUpdatedAt: now,
	}

	if pwd.UserID != userID {
		t.Errorf("UserID: got %v, want %v", pwd.UserID, userID)
	}
	if pwd.PasswordHash != hash {
		t.Errorf("PasswordHash: got %v, want %v", pwd.PasswordHash, hash)
	}
	if !pwd.PasswordUpdatedAt.Equal(now) {
		t.Errorf("PasswordUpdatedAt: got %v, want %v", pwd.PasswordUpdatedAt, now)
	}
}

func TestUserIdentity_Struct(t *testing.T) {
	id := uuid.New()
	userID := uuid.New()
	provider := ProviderGoogle
	providerSubject := "12345"
	email := "test@example.com"
	now := time.Now()

	identity := UserIdentity{
		ID:              id,
		UserID:          userID,
		Provider:        provider,
		ProviderSubject: providerSubject,
		Email:           &email,
		CreatedAt:       now,
	}

	if identity.ID != id {
		t.Errorf("ID: got %v, want %v", identity.ID, id)
	}
	if identity.UserID != userID {
		t.Errorf("UserID: got %v, want %v", identity.UserID, userID)
	}
	if identity.Provider != provider {
		t.Errorf("Provider: got %v, want %v", identity.Provider, provider)
	}
	if identity.ProviderSubject != providerSubject {
		t.Errorf("ProviderSubject: got %v, want %v", identity.ProviderSubject, providerSubject)
	}
	if identity.Email == nil || *identity.Email != email {
		t.Errorf("Email: got %v, want %v", identity.Email, email)
	}
	if !identity.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt: got %v, want %v", identity.CreatedAt, now)
	}
}

func TestProviderConstants(t *testing.T) {
	if ProviderGoogle != "google" {
		t.Errorf("ProviderGoogle: got %q, want %q", ProviderGoogle, "google")
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
