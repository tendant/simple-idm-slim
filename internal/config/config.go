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
