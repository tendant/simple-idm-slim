# simple-idm-slim

A minimal, embeddable identity management library for Go applications.

## Features

- Email + password authentication with Argon2id hashing
- Google OAuth authentication
- JWT access tokens + opaque refresh tokens
- Session management with token revocation
- User profile management
- Built on chi router with standard library compatibility

## Installation

```bash
go get github.com/tendant/simple-idm-slim
```

## Quick Start

### 1. Run the migration

```bash
# Install goose
make install-goose

# Run migrations
DB_URL=postgres://localhost/yourdb?sslmode=disable make migrate-up
```

### 2. Use in your app

**With chi router (recommended):**

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
    db, _ := sql.Open("postgres", "postgres://localhost/yourdb?sslmode=disable")

    auth, _ := idm.New(idm.Config{
        DB:        db,
        JWTSecret: "your-secret-key-at-least-32-characters",
    })

    r := chi.NewRouter()
    r.Mount("/auth", auth.Router())

    log.Fatal(http.ListenAndServe(":8080", r))
}
```

**With standard library:**

```go
package main

import (
    "database/sql"
    "log"
    "net/http"

    _ "github.com/lib/pq"
    "github.com/tendant/simple-idm-slim/idm"
)

func main() {
    db, _ := sql.Open("postgres", "postgres://localhost/yourdb?sslmode=disable")

    auth, _ := idm.New(idm.Config{
        DB:        db,
        JWTSecret: "your-secret-key-at-least-32-characters",
    })

    mux := http.NewServeMux()
    auth.Routes(mux, "/api/v1/auth")

    log.Fatal(http.ListenAndServe(":8080", mux))
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

## Mounting Options

### Option 1: Chi Router (Recommended)

Mount using chi's Mount method:

```go
r := chi.NewRouter()

// All routes under /auth
r.Mount("/auth", auth.Router())

// Or mount auth and /me separately
r.Mount("/api/auth", auth.AuthRouter())   // Auth routes without /me
r.Mount("/api/user", auth.MeRouter())     // Just /me endpoints
```

### Option 2: Standard Library with Routes()

Register routes directly on your mux with any prefix:

```go
mux := http.NewServeMux()
auth.Routes(mux, "/api/v1/auth")  // All routes under /api/v1/auth/*
```

### Option 3: Standard Library with Handler()

Get a handler and mount it with StripPrefix:

```go
mux := http.NewServeMux()
mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
```

### Option 4: Mount /me Separately (avoid conflicts)

If your app already has a `/me` route:

```go
// With chi
r := chi.NewRouter()
r.Mount("/auth", auth.AuthRouter())        // Auth routes without /me
r.Mount("/user/profile", auth.MeRouter())  // /me at custom path

// With standard library
mux := http.NewServeMux()
mux.Handle("/user/profile", auth.MeHandler())
```

## Protect Your Own Routes

**With chi router:**

```go
r := chi.NewRouter()
r.Mount("/auth", auth.Router())

// Protected routes using chi's Group
r.Group(func(r chi.Router) {
    r.Use(auth.AuthMiddleware())

    r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
        user, _ := auth.GetUser(r)
        fmt.Fprintf(w, "Hello %s!", user.Email)
    })
})
```

**With standard library:**

```go
mux := http.NewServeMux()
auth.Routes(mux, "/auth")

mux.Handle("/api/", auth.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    userID, ok := idm.GetUserID(r)
    user, err := auth.GetUser(r)
    fmt.Fprintf(w, "Hello %s!", user.Email)
})))
```

## Add Google OAuth

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

## API Methods

| Method | Description |
|--------|-------------|
| `idm.New(Config)` | Create IDM instance |
| `auth.Router()` | Get chi.Router with all routes |
| `auth.AuthRouter()` | Get chi.Router without /me routes |
| `auth.MeRouter()` | Get chi.Router for /me only |
| `auth.Handler()` | Get http.Handler (for StripPrefix) |
| `auth.Routes(mux, prefix)` | Register routes on ServeMux |
| `auth.MeHandler()` | Get /me handler separately |
| `auth.AuthMiddleware()` | Middleware to protect routes |
| `auth.GetUser(r)` | Get current user from DB |
| `auth.HealthHandler()` | Health check handler |
| `idm.GetUserID(r)` | Get user ID from request |

## Standalone Server

Run as a standalone server:

```bash
cp .env.example .env
go run ./cmd/simple-idm
```

## Database Migrations

Migrations use [goose](https://github.com/pressly/goose):

```bash
# Install goose CLI
make install-goose

# Run all pending migrations
make migrate-up

# Rollback one migration
make migrate-down

# Show migration status
make migrate-status

# Create a new migration
make migrate-create

# Reset database (rollback all, then apply all)
make migrate-reset
```

Set `DB_URL` environment variable or it defaults to `postgres://localhost/simple_idm?sslmode=disable`.

## License

MIT
