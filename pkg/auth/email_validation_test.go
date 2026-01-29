package auth

import (
	"testing"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name              string
		email             string
		strict            bool
		blockDisposable   bool
		wantErr           bool
	}{
		{
			name:    "valid email",
			email:   "test@example.com",
			strict:  false,
			wantErr: false,
		},
		{
			name:    "valid email with subdomain",
			email:   "test@mail.example.com",
			strict:  false,
			wantErr: false,
		},
		{
			name:    "valid email with plus",
			email:   "test+tag@example.com",
			strict:  false,
			wantErr: false,
		},
		{
			name:    "empty email",
			email:   "",
			strict:  false,
			wantErr: true,
		},
		{
			name:    "invalid - no @",
			email:   "invalid.com",
			strict:  false,
			wantErr: true,
		},
		{
			name:    "invalid - no domain",
			email:   "test@",
			strict:  false,
			wantErr: true,
		},
		{
			name:    "invalid - no local part",
			email:   "@example.com",
			strict:  false,
			wantErr: true,
		},
		{
			name:    "too long",
			email:   "a" + string(make([]byte, 300)) + "@example.com",
			strict:  false,
			wantErr: true,
		},
		{
			name:            "disposable email - blocked",
			email:           "test@tempmail.com",
			strict:          false,
			blockDisposable: true,
			wantErr:         true,
		},
		{
			name:            "disposable email - allowed",
			email:           "test@tempmail.com",
			strict:          false,
			blockDisposable: false,
			wantErr:         false,
		},
		{
			name:    "strict mode - valid",
			email:   "test@example.com",
			strict:  true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email, tt.strict, tt.blockDisposable)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "lowercase",
			email: "Test@Example.COM",
			want:  "test@example.com",
		},
		{
			name:  "trim spaces",
			email: "  test@example.com  ",
			want:  "test@example.com",
		},
		{
			name:  "both",
			email: "  Test@Example.COM  ",
			want:  "test@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeEmail(tt.email)
			if got != tt.want {
				t.Errorf("NormalizeEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}
