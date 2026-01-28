package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds application configuration.
type Config struct {
	// Server
	ServerAddr string
	ServerPort int

	// Database
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	// JWT
	JWTSecret       string
	JWTIssuer       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// Google OAuth
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	// SMTP Email
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPFromName string

	// Application
	AppBaseURL string
	ServeUI    bool

	// Verification
	EmailVerificationTTL    time.Duration
	PasswordResetTTL        time.Duration
	RequireEmailVerification bool
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		// Server defaults
		ServerAddr: getEnv("SERVER_ADDR", "0.0.0.0"),
		ServerPort: getEnvInt("SERVER_PORT", 8080),

		// Database defaults (matches podman setup: make postgres-start)
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnvInt("DB_PORT", 25432),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", "postgres"),
		DBName:     getEnv("DB_NAME", "simple_idm"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),

		// JWT defaults
		JWTSecret:       getEnv("JWT_SECRET", ""),
		JWTIssuer:       getEnv("JWT_ISSUER", "simple-idm"),
		AccessTokenTTL:  getEnvDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL: getEnvDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour),

		// Google OAuth (optional)
		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURI:  getEnv("GOOGLE_REDIRECT_URI", ""),

		// SMTP Email (optional)
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     getEnvInt("SMTP_PORT", 587),
		SMTPUser:     getEnv("SMTP_USER", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", ""),
		SMTPFromName: getEnv("SMTP_FROM_NAME", "Simple IDM"),

		// Application
		AppBaseURL: getEnv("APP_BASE_URL", "http://localhost:8080"),
		ServeUI:    getEnvBool("SERVE_UI", true),

		// Verification
		EmailVerificationTTL:    getEnvDuration("EMAIL_VERIFICATION_TTL", 24*time.Hour),
		PasswordResetTTL:        getEnvDuration("PASSWORD_RESET_TTL", 1*time.Hour),
		RequireEmailVerification: getEnvBool("REQUIRE_EMAIL_VERIFICATION", true),
	}

	// Validate required fields
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}

// HasGoogleOAuth returns true if Google OAuth is configured.
func (c *Config) HasGoogleOAuth() bool {
	return c.GoogleClientID != "" && c.GoogleClientSecret != ""
}

// HasSMTP returns true if SMTP is configured.
func (c *Config) HasSMTP() bool {
	return c.SMTPHost != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
