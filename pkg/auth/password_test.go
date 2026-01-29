package auth

import (
	"testing"

	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// Note: Hash/Verify tests are in crypto_test.go
// This file focuses on password service-specific logic

func TestPasswordService_ValidateUsernameFormat(t *testing.T) {
	// Test username validation logic that would be used in Register
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "valid username",
			username: "validuser",
			wantErr:  false,
		},
		{
			name:     "valid with numbers",
			username: "user123",
			wantErr:  false,
		},
		{
			name:     "valid with underscore",
			username: "user_name",
			wantErr:  false,
		},
		{
			name:     "valid with hyphen",
			username: "user-name",
			wantErr:  false,
		},
		{
			name:     "invalid - too short",
			username: "ab",
			wantErr:  true,
		},
		{
			name:     "invalid - starts with underscore",
			username: "_username",
			wantErr:  true,
		},
		{
			name:     "invalid - contains @",
			username: "user@name",
			wantErr:  true,
		},
		{
			name:     "invalid - empty",
			username: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername(%q) error = %v, wantErr %v", tt.username, err, tt.wantErr)
			}

			if err != nil && err != domain.ErrInvalidUsername {
				t.Errorf("Expected domain.ErrInvalidUsername, got %v", err)
			}
		})
	}
}

func TestPasswordService_Structure(t *testing.T) {
	// Test that password service can be instantiated
	policy := &PasswordPolicy{}
	service := NewPasswordService(nil, nil, nil, policy, false, false)

	if service == nil {
		t.Fatal("NewPasswordService should not return nil")
	}

	if service.db != nil {
		t.Error("Expected db to be nil")
	}
	if service.users != nil {
		t.Error("Expected users to be nil")
	}
	if service.creds != nil {
		t.Error("Expected creds to be nil")
	}
}

func TestPasswordService_Argon2Parameters(t *testing.T) {
	// Verify that Argon2 parameters are set correctly (OWASP recommended)
	if argon2Time != 1 {
		t.Errorf("argon2Time = %d, want 1", argon2Time)
	}
	if argon2Memory != 64*1024 {
		t.Errorf("argon2Memory = %d, want %d", argon2Memory, 64*1024)
	}
	if argon2Threads != 4 {
		t.Errorf("argon2Threads = %d, want 4", argon2Threads)
	}
	if argon2KeyLen != 32 {
		t.Errorf("argon2KeyLen = %d, want 32", argon2KeyLen)
	}
	if saltLen != 16 {
		t.Errorf("saltLen = %d, want 16", saltLen)
	}
}

func TestPasswordHashing_CaseSensitive(t *testing.T) {
	password := "TestPassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "exact match",
			password: "TestPassword123",
			want:     true,
		},
		{
			name:     "lowercase",
			password: "testpassword123",
			want:     false,
		},
		{
			name:     "uppercase",
			password: "TESTPASSWORD123",
			want:     false,
		},
		{
			name:     "mixed case different",
			password: "testPassword123",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyPassword(tt.password, hash)
			if got != tt.want {
				t.Errorf("VerifyPassword(%q) = %v, want %v", tt.password, got, tt.want)
			}
		})
	}
}

func TestPasswordStrength_EdgeCases(t *testing.T) {
	// Test that various password lengths and characters can be hashed
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "very short (1 char)",
			password: "a",
		},
		{
			name:     "empty string",
			password: "",
		},
		{
			name:     "medium length",
			password: "mediumPassword123",
		},
		{
			name:     "special characters",
			password: "p@ssw0rd!#$%^&*()",
		},
		{
			name:     "unicode",
			password: "pässwörd123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if err != nil {
				t.Errorf("HashPassword failed for %q: %v", tt.name, err)
				return
			}

			if !VerifyPassword(tt.password, hash) {
				t.Errorf("VerifyPassword failed for %q", tt.name)
			}
		})
	}
}
