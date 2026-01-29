package auth

import (
	"testing"

	"github.com/tendant/simple-idm-slim/internal/config"
)

func TestPasswordPolicy_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		policy   PasswordPolicy
		password string
		wantErr  bool
	}{
		{
			name:     "no requirements - any password valid",
			policy:   PasswordPolicy{},
			password: "a",
			wantErr:  false,
		},
		{
			name:     "min length - valid",
			policy:   PasswordPolicy{MinLength: 8},
			password: "12345678",
			wantErr:  false,
		},
		{
			name:     "min length - too short",
			policy:   PasswordPolicy{MinLength: 8},
			password: "1234567",
			wantErr:  true,
		},
		{
			name:     "require uppercase - valid",
			policy:   PasswordPolicy{RequireUppercase: true},
			password: "Password",
			wantErr:  false,
		},
		{
			name:     "require uppercase - missing",
			policy:   PasswordPolicy{RequireUppercase: true},
			password: "password",
			wantErr:  true,
		},
		{
			name:     "require lowercase - valid",
			policy:   PasswordPolicy{RequireLowercase: true},
			password: "Password",
			wantErr:  false,
		},
		{
			name:     "require lowercase - missing",
			policy:   PasswordPolicy{RequireLowercase: true},
			password: "PASSWORD",
			wantErr:  true,
		},
		{
			name:     "require number - valid",
			policy:   PasswordPolicy{RequireNumber: true},
			password: "Password123",
			wantErr:  false,
		},
		{
			name:     "require number - missing",
			policy:   PasswordPolicy{RequireNumber: true},
			password: "Password",
			wantErr:  true,
		},
		{
			name:     "require special - valid",
			policy:   PasswordPolicy{RequireSpecial: true},
			password: "Password!",
			wantErr:  false,
		},
		{
			name:     "require special - missing",
			policy:   PasswordPolicy{RequireSpecial: true},
			password: "Password123",
			wantErr:  true,
		},
		{
			name: "all requirements - valid",
			policy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumber:    true,
				RequireSpecial:   true,
			},
			password: "StrongPass123!",
			wantErr:  false,
		},
		{
			name: "all requirements - missing special",
			policy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumber:    true,
				RequireSpecial:   true,
			},
			password: "StrongPass123",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewPasswordPolicy(t *testing.T) {
	cfg := config.PasswordPolicyConfig{
		MinLength:        12,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumber:    true,
		RequireSpecial:   true,
	}

	policy := NewPasswordPolicy(cfg)

	if policy.MinLength != 12 {
		t.Errorf("MinLength = %d, want 12", policy.MinLength)
	}
	if !policy.RequireUppercase {
		t.Error("RequireUppercase should be true")
	}
	if !policy.RequireLowercase {
		t.Error("RequireLowercase should be true")
	}
	if !policy.RequireNumber {
		t.Error("RequireNumber should be true")
	}
	if !policy.RequireSpecial {
		t.Error("RequireSpecial should be true")
	}
}

func TestPasswordPolicy_GetRequirements(t *testing.T) {
	tests := []struct {
		name   string
		policy PasswordPolicy
		want   string
	}{
		{
			name:   "no requirements",
			policy: PasswordPolicy{},
			want:   "No password requirements",
		},
		{
			name:   "min length only",
			policy: PasswordPolicy{MinLength: 8},
			want:   "Password must contain at least 8 characters",
		},
		{
			name: "all requirements",
			policy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumber:    true,
				RequireSpecial:   true,
			},
			want: "Password must contain at least 12 characters, one uppercase letter, one lowercase letter, one number, one special character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.GetRequirements()
			if got != tt.want {
				t.Errorf("GetRequirements() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPasswordPolicy_HasRequirements(t *testing.T) {
	tests := []struct {
		name   string
		policy PasswordPolicy
		want   bool
	}{
		{
			name:   "no requirements",
			policy: PasswordPolicy{},
			want:   false,
		},
		{
			name:   "has min length",
			policy: PasswordPolicy{MinLength: 8},
			want:   true,
		},
		{
			name:   "has uppercase requirement",
			policy: PasswordPolicy{RequireUppercase: true},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.HasRequirements()
			if got != tt.want {
				t.Errorf("HasRequirements() = %v, want %v", got, tt.want)
			}
		})
	}
}
