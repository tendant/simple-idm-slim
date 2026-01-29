# simple-idm-slim

A minimal, embeddable identity management library for Go applications.

## Features

- Email + password authentication with Argon2id hashing
- Optional username support (login with email or username)
- Google OAuth authentication
- JWT access tokens + opaque refresh tokens
- Session management with token revocation
- User profile management
- **Multi-Factor Authentication (MFA/2FA)**: TOTP-based two-factor authentication with recovery codes
- **Security**: Comprehensive rate limiting, password policies, security headers, session fingerprinting
- Built on chi router with standard library compatibility
- **Extensible**: Core packages in `pkg/` allow custom implementations

## Installation

```bash
go get github.com/tendant/simple-idm-slim
```

## Quick Start

### 1. Run migrations

Copy migrations to your project and run with your preferred tool:

```bash
# Using goose
goose -dir migrations postgres "$DB_URL" up

# Or using golang-migrate
migrate -path migrations -database "$DB_URL" up

# Or manually
psql -d yourdb -f migrations/001_initial_schema.sql
```

### 2. Use in your app

```go
package main

import (
    "database/sql"
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    _ "github.com/lib/pq"
    "github.com/tendant/simple-idm-slim/idm"
)

func main() {
    db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

    // Create IDM instance (validates schema exists)
    auth, err := idm.New(idm.Config{
        DB:        db,
        JWTSecret: "your-secret-key-at-least-32-characters",
    })
    if err != nil {
        log.Fatal(err) // Fails if migrations haven't been run
    }

    r := chi.NewRouter()
    r.Mount("/auth", auth.Router())
    log.Fatal(http.ListenAndServe(":8080", r))
}
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Register user |
| POST | `/login` | Login |
| POST | `/refresh` | Refresh token |
| POST | `/logout` | Logout |
| POST | `/logout/all` | Logout all sessions (protected) |
| GET | `/me` | Get profile (protected) |
| PATCH | `/me` | Update profile (protected) |
| GET | `/google/start` | Start Google OAuth (if configured) |
| GET | `/google/callback` | Google OAuth callback (if configured) |
| GET | `/me/mfa/status` | Get MFA status (protected) |
| POST | `/me/mfa/setup` | Setup MFA (protected) |
| POST | `/me/mfa/enable` | Enable MFA (protected) |
| POST | `/me/mfa/disable` | Disable MFA (protected) |
| POST | `/auth/mfa/verify` | Verify MFA challenge |

## Mounting Options

### Chi Router (Recommended)

```go
r := chi.NewRouter()
r.Mount("/auth", auth.Router())

// Or mount auth and /me separately
r.Mount("/api/auth", auth.AuthRouter())
r.Mount("/api/user", auth.MeRouter())
```

### Standard Library

```go
mux := http.NewServeMux()
auth.Routes(mux, "/api/v1/auth")
```

## Protect Your Routes

```go
r := chi.NewRouter()
r.Mount("/auth", auth.Router())

r.Group(func(r chi.Router) {
    r.Use(auth.AuthMiddleware())

    r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
        user, _ := auth.GetUser(r)
        fmt.Fprintf(w, "Hello %s!", user.Email)
    })
})
```

## Google OAuth

```go
auth, _ := idm.New(idm.Config{
    DB:        db,
    JWTSecret: "your-secret-key-at-least-32-characters",
    Google: &idm.GoogleConfig{
        ClientID:     "your-google-client-id",
        ClientSecret: "your-google-client-secret",
        RedirectURI:  "http://localhost:8080/auth/google/callback",
    },
})
```

## Configuration

```go
idm.New(idm.Config{
    DB:              db,                    // *sql.DB (required)
    JWTSecret:       "...",                 // min 32 chars (required)
    JWTIssuer:       "my-app",              // default: "simple-idm"
    AccessTokenTTL:  30 * time.Minute,      // default: 15 minutes
    RefreshTokenTTL: 24 * time.Hour,        // default: 7 days
    Logger:          slog.Default(),        // default: JSON logger
    Google:          &idm.GoogleConfig{},   // optional
})
```

## Security Features

simple-idm-slim includes comprehensive security features to protect your application:

### Multi-Factor Authentication (MFA/2FA)

TOTP-based two-factor authentication adds an extra layer of security:

```bash
# Enable MFA (enabled by default)
MFA_ENABLED=true

# Generate encryption key for storing TOTP secrets
# Run: openssl rand -hex 32
MFA_ENCRYPTION_KEY=<64-char-hex-string>
```

**Features:**
- **TOTP Standard**: RFC 6238 compliant (works with Google Authenticator, Authy, 1Password, etc.)
- **QR Code Setup**: Easy enrollment via QR code or manual entry
- **Recovery Codes**: 8 one-time backup codes (hashed with Argon2id)
- **Challenge Token**: 5-minute expiry for security
- **Backward Compatible**: Existing users continue to work without MFA

**Setup Flow:**

1. **User enables MFA:**
   ```bash
   POST /v1/me/mfa/setup
   {
     "password": "user_password"
   }

   # Returns QR code, secret, and recovery codes
   ```

2. **User scans QR code** with authenticator app (Google Authenticator, Authy, etc.)

3. **User verifies and enables:**
   ```bash
   POST /v1/me/mfa/enable
   {
     "code": "123456"  # 6-digit TOTP code
   }
   ```

**Login Flow with MFA:**

1. **Initial login:**
   ```bash
   POST /v1/auth/password/login
   {
     "identifier": "user@example.com",
     "password": "password123"
   }

   # If MFA enabled, returns:
   {
     "mfa_required": true,
     "challenge_token": "...",
     "message": "MFA verification required"
   }
   ```

2. **Complete MFA verification:**
   ```bash
   POST /v1/auth/mfa/verify
   {
     "challenge_token": "...",
     "code": "123456"  # TOTP code or recovery code
   }

   # Returns full session tokens
   ```

**Disable MFA:**

```bash
POST /v1/me/mfa/disable
{
  "password": "user_password",
  "code": "123456"  # TOTP or recovery code
}

# All sessions are revoked for security
```

**Check MFA Status:**

```bash
GET /v1/me/mfa/status

# Returns:
{
  "enabled": true,
  "recovery_codes_remaining": 7
}
```

**Security Considerations:**

- TOTP secrets encrypted at rest with AES-256-GCM
- Recovery codes hashed with Argon2id (same as passwords)
- Challenge tokens expire after 5 minutes
- One-time use recovery codes
- Rate limiting on verification endpoint (10 req/min)
- ±30 seconds clock drift tolerance
- `MFAVerified` claim in JWT for fine-grained access control

### Rate Limiting

Configurable rate limiting protects against brute force attacks and API abuse:

- **Auth endpoints** (login, register): 10 requests/minute (default)
- **Password reset**: 3 requests/5 minutes (default)
- **Email verification**: 5 requests/5 minutes (default)
- **Token refresh**: 20 requests/minute (default)
- **Profile endpoints**: 30 requests/minute (default)

All limits are configurable via environment variables. See `.env.example` for details.

Rate limit violations are logged with IP, path, method, and user agent for security monitoring.

### Password Policy

Enforce password complexity requirements:

```go
auth, _ := idm.New(idm.Config{
    DB:        db,
    JWTSecret: "...",
    PasswordPolicy: &idm.PasswordPolicyConfig{
        MinLength:        12,
        RequireUppercase: true,
        RequireLowercase: true,
        RequireNumber:    true,
        RequireSpecial:   true,
    },
})
```

Or via environment variables:
```bash
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBER=true
PASSWORD_REQUIRE_SPECIAL=true
```

### Security Headers

OWASP-recommended security headers are automatically applied:

- **Content-Security-Policy**: Prevents XSS attacks
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **X-XSS-Protection**: Legacy XSS protection
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Controls browser features

All headers are configurable via environment variables.

### Session Security

Enhanced session security features:

#### Session Fingerprinting

Detects token theft by tracking device fingerprints (IP + User-Agent):

```go
auth, _ := idm.New(idm.Config{
    DB:        db,
    JWTSecret: "...",
    SessionSecurity: &idm.SessionSecurityConfig{
        FingerprintEnabled: true,
        DetectReuse:        true,
    },
})
```

When fingerprint mismatches are detected, the session is automatically revoked.

#### Secure Cookies

Configure cookie security settings:

```bash
COOKIE_SECURE=true      # Set to true in production (requires HTTPS)
COOKIE_SAMESITE=Strict  # Strict, Lax, or None
```

### Input Validation

Comprehensive input validation and sanitization:

- **Email validation**: RFC 5322 compliant with optional disposable domain blocking
- **Input sanitization**: HTML escaping and control character removal
- **Request size limits**: Prevents memory exhaustion (default: 1MB)

```bash
STRICT_EMAIL_VALIDATION=true
BLOCK_DISPOSABLE_EMAIL=true
MAX_REQUEST_BODY_SIZE=1048576
```

### Production Recommendations

For production deployments:

1. **Enable all security features**:
   ```bash
   RATE_LIMIT_ENABLED=true
   SECURITY_HEADERS_ENABLED=true
   SESSION_FINGERPRINT_ENABLED=true
   SESSION_DETECT_REUSE=true
   ```

2. **Enforce strong passwords**:
   ```bash
   PASSWORD_MIN_LENGTH=12
   PASSWORD_REQUIRE_UPPERCASE=true
   PASSWORD_REQUIRE_LOWERCASE=true
   PASSWORD_REQUIRE_NUMBER=true
   PASSWORD_REQUIRE_SPECIAL=true
   ```

3. **Use secure cookies (requires HTTPS)**:
   ```bash
   COOKIE_SECURE=true
   COOKIE_SAMESITE=Strict
   ```

4. **Enable strict validation**:
   ```bash
   STRICT_EMAIL_VALIDATION=true
   BLOCK_DISPOSABLE_EMAIL=true
   ```

5. **Enable MFA** (recommended):
   ```bash
   MFA_ENABLED=true
   MFA_ENCRYPTION_KEY=<generate with: openssl rand -hex 32>
   ```

See `.env.example` for complete configuration options.

## API Reference

| Function | Description |
|----------|-------------|
| `idm.New(Config)` | Create IDM instance (validates schema) |
| `auth.Router()` | Chi router with all routes |
| `auth.AuthRouter()` | Chi router without /me |
| `auth.MeRouter()` | Chi router for /me only |
| `auth.Handler()` | http.Handler (for StripPrefix) |
| `auth.Routes(mux, prefix)` | Register on ServeMux |
| `auth.AuthMiddleware()` | JWT validation middleware |
| `auth.GetUser(r)` | Get current user from DB |
| `idm.GetUserID(r)` | Get user ID string |
| `idm.GetUserIDFromContext(ctx)` | Get user UUID |

## Database Migrations

Migrations are in `migrations/` folder. Use your preferred tool:

```bash
# Install goose (if using goose)
make install-goose

# Run migrations
make migrate-up

# Rollback
make migrate-down

# Status
make migrate-status
```

Set `DB_URL` environment variable or it defaults to `postgres://localhost/simple_idm?sslmode=disable`.

## Extensibility

Core packages are in `pkg/` and can be extended or replaced:

### Custom User Fields

```go
import "github.com/tendant/simple-idm-slim/pkg/domain"

type MyUser struct {
    domain.User
    CompanyID   string
    Role        string
    Permissions []string
}
```

### Custom Storage Backend

```go
import (
    "github.com/tendant/simple-idm-slim/pkg/repository"
    "github.com/tendant/simple-idm-slim/pkg/domain"
)

// Implement repository methods for MongoDB, DynamoDB, etc.
type MongoUsersRepo struct {
    client *mongo.Client
}

func (r *MongoUsersRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
    // Custom implementation
}
```

### Enforce MFA for Sensitive Operations

Use the `RequireMFA` middleware for endpoints requiring MFA verification:

```go
import "github.com/tendant/simple-idm-slim/internal/http/middleware"

r.With(middleware.Auth(sessionService)).
  With(middleware.RequireMFA()).
  Delete("/v1/me", meHandler.DeleteMe)
```

This checks the `MFAVerified` claim in the JWT and returns 403 if MFA was not verified.

## Package Structure

```
pkg/
├── domain/          - Domain models (User, Session, etc.)
├── repository/      - Data access layer
└── auth/            - Authentication services

internal/
├── http/            - HTTP handlers (Chi-specific)
├── httputil/        - HTTP utilities
├── notification/    - Email service
└── config/          - Configuration
```

## Standalone Server

For testing or standalone deployment:

```bash
cp .env.example .env
make migrate-up
go run ./cmd/simple-idm
```

## License

MIT
