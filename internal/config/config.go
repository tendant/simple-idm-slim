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
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration

	// Rate Limiting
	RateLimit RateLimitConfig

	// Security
	PasswordPolicy PasswordPolicyConfig
	SecurityHeaders SecurityHeadersConfig
	SessionSecurity SessionSecurityConfig
	Validation ValidationConfig

	// MFA
	MFAEnabled       bool
	MFAEncryptionKey string
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled bool

	// Auth endpoints (login, register)
	AuthRequestsPerMinute int
	AuthWindowMinutes     int

	// Password reset endpoints
	ResetRequestsPerWindow int
	ResetWindowMinutes     int

	// Email verification endpoints
	VerifyRequestsPerWindow int
	VerifyWindowMinutes     int

	// Refresh token endpoint
	RefreshRequestsPerMinute int
	RefreshWindowMinutes     int

	// Profile endpoints (me)
	ProfileRequestsPerMinute int
	ProfileWindowMinutes     int
}

// PasswordPolicyConfig holds password complexity requirements.
type PasswordPolicyConfig struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

// SecurityHeadersConfig holds security headers configuration.
type SecurityHeadersConfig struct {
	Enabled             bool
	CSP                 string
	HSTSMaxAge          int
	FrameOptions        string
	ContentTypeOptions  string
	XSSProtection       string
	ReferrerPolicy      string
	PermissionsPolicy   string
}

// SessionSecurityConfig holds session security configuration.
type SessionSecurityConfig struct {
	CookieSecure          bool
	CookieSameSite        string // Strict, Lax, None
	FingerprintEnabled    bool
	DetectReuse           bool
}

// ValidationConfig holds input validation configuration.
type ValidationConfig struct {
	MaxRequestBodySize    int64
	StrictEmailValidation bool
	BlockDisposableEmail  bool
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
		EmailVerificationTTL: getEnvDuration("EMAIL_VERIFICATION_TTL", 24*time.Hour),
		PasswordResetTTL:     getEnvDuration("PASSWORD_RESET_TTL", 1*time.Hour),

		// Rate Limiting (defaults match current hardcoded limits)
		RateLimit: RateLimitConfig{
			Enabled:                  getEnvBool("RATE_LIMIT_ENABLED", true),
			AuthRequestsPerMinute:    getEnvInt("RATE_LIMIT_AUTH_REQUESTS", 10),
			AuthWindowMinutes:        getEnvInt("RATE_LIMIT_AUTH_WINDOW", 1),
			ResetRequestsPerWindow:   getEnvInt("RATE_LIMIT_RESET_REQUESTS", 3),
			ResetWindowMinutes:       getEnvInt("RATE_LIMIT_RESET_WINDOW", 5),
			VerifyRequestsPerWindow:  getEnvInt("RATE_LIMIT_VERIFY_REQUESTS", 5),
			VerifyWindowMinutes:      getEnvInt("RATE_LIMIT_VERIFY_WINDOW", 5),
			RefreshRequestsPerMinute: getEnvInt("RATE_LIMIT_REFRESH_REQUESTS", 20),
			RefreshWindowMinutes:     getEnvInt("RATE_LIMIT_REFRESH_WINDOW", 1),
			ProfileRequestsPerMinute: getEnvInt("RATE_LIMIT_PROFILE_REQUESTS", 30),
			ProfileWindowMinutes:     getEnvInt("RATE_LIMIT_PROFILE_WINDOW", 1),
		},

		// Password Policy (no enforcement by default for backward compatibility)
		PasswordPolicy: PasswordPolicyConfig{
			MinLength:        getEnvInt("PASSWORD_MIN_LENGTH", 0),
			RequireUppercase: getEnvBool("PASSWORD_REQUIRE_UPPERCASE", false),
			RequireLowercase: getEnvBool("PASSWORD_REQUIRE_LOWERCASE", false),
			RequireNumber:    getEnvBool("PASSWORD_REQUIRE_NUMBER", false),
			RequireSpecial:   getEnvBool("PASSWORD_REQUIRE_SPECIAL", false),
		},

		// Security Headers (enabled with OWASP defaults)
		SecurityHeaders: SecurityHeadersConfig{
			Enabled:            getEnvBool("SECURITY_HEADERS_ENABLED", true),
			CSP:                getEnv("SECURITY_HEADERS_CSP", "default-src 'self'"),
			HSTSMaxAge:         getEnvInt("SECURITY_HEADERS_HSTS_MAX_AGE", 31536000),
			FrameOptions:       getEnv("SECURITY_HEADERS_FRAME_OPTIONS", "DENY"),
			ContentTypeOptions: getEnv("SECURITY_HEADERS_CONTENT_TYPE_OPTIONS", "nosniff"),
			XSSProtection:      getEnv("SECURITY_HEADERS_XSS_PROTECTION", "1; mode=block"),
			ReferrerPolicy:     getEnv("SECURITY_HEADERS_REFERRER_POLICY", "strict-origin-when-cross-origin"),
			PermissionsPolicy:  getEnv("SECURITY_HEADERS_PERMISSIONS_POLICY", "geolocation=(), microphone=(), camera=()"),
		},

		// Session Security (secure defaults but cookie secure is false for dev)
		SessionSecurity: SessionSecurityConfig{
			CookieSecure:       getEnvBool("COOKIE_SECURE", false),
			CookieSameSite:     getEnv("COOKIE_SAMESITE", "Lax"),
			FingerprintEnabled: getEnvBool("SESSION_FINGERPRINT_ENABLED", true),
			DetectReuse:        getEnvBool("SESSION_DETECT_REUSE", true),
		},

		// Validation (sensible defaults)
		Validation: ValidationConfig{
			MaxRequestBodySize:    getEnvInt64("MAX_REQUEST_BODY_SIZE", 1048576), // 1MB
			StrictEmailValidation: getEnvBool("STRICT_EMAIL_VALIDATION", true),
			BlockDisposableEmail:  getEnvBool("BLOCK_DISPOSABLE_EMAIL", false),
		},

		// MFA
		MFAEnabled:       getEnvBool("MFA_ENABLED", true),
		MFAEncryptionKey: getEnv("MFA_ENCRYPTION_KEY", ""),
	}

	// Validate required fields
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	// Validate MFA encryption key if MFA is enabled
	if cfg.MFAEnabled && cfg.MFAEncryptionKey == "" {
		return nil, fmt.Errorf("MFA_ENCRYPTION_KEY is required when MFA is enabled")
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

// HasMFA returns true if MFA is enabled and properly configured.
func (c *Config) HasMFA() bool {
	return c.MFAEnabled && c.MFAEncryptionKey != ""
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

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}
