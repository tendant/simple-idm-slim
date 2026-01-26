package auth

import (
	"testing"

	"github.com/tendant/simple-idm-slim/pkg/domain"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		// Valid usernames
		{
			name:     "valid alphanumeric",
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
			name:     "valid mixed",
			username: "user_123-abc",
			wantErr:  false,
		},
		{
			name:     "valid minimum length (3 chars)",
			username: "abc",
			wantErr:  false,
		},
		{
			name:     "valid maximum length (30 chars)",
			username: "abcdefghij1234567890abcdefghij",
			wantErr:  false,
		},
		{
			name:     "valid starts with letter",
			username: "a12",
			wantErr:  false,
		},
		{
			name:     "valid starts with number",
			username: "1ab",
			wantErr:  false,
		},

		// Invalid usernames
		{
			name:     "empty string",
			username: "",
			wantErr:  true,
		},
		{
			name:     "too short (2 chars)",
			username: "ab",
			wantErr:  true,
		},
		{
			name:     "too long (31 chars)",
			username: "abcdefghij1234567890abcdefghijk",
			wantErr:  true,
		},
		{
			name:     "starts with underscore",
			username: "_username",
			wantErr:  true,
		},
		{
			name:     "starts with hyphen",
			username: "-username",
			wantErr:  true,
		},
		{
			name:     "contains space",
			username: "user name",
			wantErr:  true,
		},
		{
			name:     "contains special char (@)",
			username: "user@name",
			wantErr:  true,
		},
		{
			name:     "contains special char (.)",
			username: "user.name",
			wantErr:  true,
		},
		{
			name:     "contains special char (!)",
			username: "user!name",
			wantErr:  true,
		},
		{
			name:     "only special chars",
			username: "___",
			wantErr:  true,
		},
		{
			name:     "unicode characters",
			username: "usér123",
			wantErr:  true,
		},
		{
			name:     "emoji",
			username: "user😀",
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
				t.Errorf("ValidateUsername(%q) error = %v, want %v", tt.username, err, domain.ErrInvalidUsername)
			}
		})
	}
}

func TestIsEmail(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       bool
	}{
		{
			name:       "valid email",
			identifier: "user@example.com",
			want:       true,
		},
		{
			name:       "email with subdomain",
			identifier: "user@mail.example.com",
			want:       true,
		},
		{
			name:       "username without @",
			identifier: "username",
			want:       false,
		},
		{
			name:       "username with underscore",
			identifier: "user_name",
			want:       false,
		},
		{
			name:       "username with hyphen",
			identifier: "user-name",
			want:       false,
		},
		{
			name:       "empty string",
			identifier: "",
			want:       false,
		},
		{
			name:       "@ at start",
			identifier: "@username",
			want:       true,
		},
		{
			name:       "@ at end",
			identifier: "username@",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEmail(tt.identifier); got != tt.want {
				t.Errorf("IsEmail(%q) = %v, want %v", tt.identifier, got, tt.want)
			}
		})
	}
}
