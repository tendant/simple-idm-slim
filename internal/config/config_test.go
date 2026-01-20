package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Set required JWT_SECRET
	os.Setenv("JWT_SECRET", "test-secret-key")
	defer os.Unsetenv("JWT_SECRET")

	// Clear any other env vars that might interfere
	envVars := []string{"SERVER_ADDR", "SERVER_PORT", "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSLMODE"}
	for _, v := range envVars {
		os.Unsetenv(v)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Check defaults
	if cfg.ServerAddr != "0.0.0.0" {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, "0.0.0.0")
	}
	if cfg.ServerPort != 8080 {
		t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, 8080)
	}
	if cfg.DBHost != "localhost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "localhost")
	}
	if cfg.DBPort != 25432 {
		t.Errorf("DBPort = %d, want %d", cfg.DBPort, 25432)
	}
	if cfg.DBSSLMode != "disable" {
		t.Errorf("DBSSLMode = %q, want %q", cfg.DBSSLMode, "disable")
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, 15*time.Minute)
	}
	if cfg.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, 7*24*time.Hour)
	}
}

func TestLoad_RequiredJWTSecret(t *testing.T) {
	os.Unsetenv("JWT_SECRET")

	_, err := Load()
	if err == nil {
		t.Error("Load should fail when JWT_SECRET is not set")
	}
}

func TestLoad_CustomValues(t *testing.T) {
	os.Setenv("JWT_SECRET", "custom-secret")
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("DB_HOST", "db.example.com")
	os.Setenv("ACCESS_TOKEN_TTL", "30m")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("ACCESS_TOKEN_TTL")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.ServerPort != 9090 {
		t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, 9090)
	}
	if cfg.DBHost != "db.example.com" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "db.example.com")
	}
	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, 30*time.Minute)
	}
}

func TestHasGoogleOAuth(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		expected     bool
	}{
		{
			name:         "both set",
			clientID:     "client-id",
			clientSecret: "client-secret",
			expected:     true,
		},
		{
			name:         "only client id",
			clientID:     "client-id",
			clientSecret: "",
			expected:     false,
		},
		{
			name:         "only client secret",
			clientID:     "",
			clientSecret: "client-secret",
			expected:     false,
		},
		{
			name:         "neither set",
			clientID:     "",
			clientSecret: "",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				GoogleClientID:     tt.clientID,
				GoogleClientSecret: tt.clientSecret,
			}
			if cfg.HasGoogleOAuth() != tt.expected {
				t.Errorf("HasGoogleOAuth() = %v, want %v", cfg.HasGoogleOAuth(), tt.expected)
			}
		})
	}
}

func TestGetEnvInt_InvalidValue(t *testing.T) {
	os.Setenv("TEST_INT", "not-a-number")
	defer os.Unsetenv("TEST_INT")

	result := getEnvInt("TEST_INT", 42)
	if result != 42 {
		t.Errorf("getEnvInt should return default for invalid value, got %d", result)
	}
}

func TestGetEnvDuration_InvalidValue(t *testing.T) {
	os.Setenv("TEST_DURATION", "invalid")
	defer os.Unsetenv("TEST_DURATION")

	result := getEnvDuration("TEST_DURATION", 5*time.Minute)
	if result != 5*time.Minute {
		t.Errorf("getEnvDuration should return default for invalid value, got %v", result)
	}
}
