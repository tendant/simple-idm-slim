// Package idm provides a minimal identity management library with
// password and Google OAuth authentication.
//
// Setup:
//
//  1. Run migrations from migrations/ folder using your preferred tool
//  2. Create IDM instance and mount routes
//
// Basic usage:
//
//	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")
//
//	auth, err := idm.New(idm.Config{
//	    DB:        db,
//	    JWTSecret: "your-secret-key-at-least-32-chars",
//	})
//	if err != nil {
//	    log.Fatal(err) // Will fail if migrations haven't been run
//	}
//
//	r := chi.NewRouter()
//	r.Mount("/auth", auth.Router())
//	http.ListenAndServe(":8080", r)
//
// With Google OAuth:
//
//	auth, err := idm.New(idm.Config{
//	    DB:        db,
//	    JWTSecret: "your-secret-key-at-least-32-chars",
//	    Google: &idm.GoogleConfig{
//	        ClientID:     "your-client-id",
//	        ClientSecret: "your-client-secret",
//	        RedirectURI:  "http://localhost:8080/auth/google/callback",
//	    },
//	})
package idm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/internal/http/features/google"
	"github.com/tendant/simple-idm-slim/internal/http/features/me"
	"github.com/tendant/simple-idm-slim/internal/http/features/password"
	"github.com/tendant/simple-idm-slim/internal/http/features/session"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

// Config holds the configuration for the IDM library.
type Config struct {
	// DB is the database connection (required).
	DB *sql.DB

	// JWTSecret is the secret key for signing JWT tokens (required, min 32 chars).
	JWTSecret string

	// JWTIssuer is the issuer claim in JWT tokens (default: "simple-idm").
	JWTIssuer string

	// AccessTokenTTL is the lifetime of access tokens (default: 15 minutes).
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of refresh tokens (default: 7 days).
	RefreshTokenTTL time.Duration

	// Google enables Google OAuth authentication (optional).
	Google *GoogleConfig

	// Logger is the structured logger (default: slog.Default()).
	Logger *slog.Logger
}

// GoogleConfig holds Google OAuth configuration.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// IDM is the main identity management instance.
type IDM struct {
	config          Config
	db              *sql.DB
	usersRepo       *repository.UsersRepository
	credsRepo       *repository.CredentialsRepository
	identitiesRepo  *repository.IdentitiesRepository
	sessionsRepo    *repository.SessionsRepository
	tenantsRepo     *repository.TenantsRepository
	membershipsRepo *repository.MembershipsRepository
	passwordService *auth.PasswordService
	sessionService  *auth.SessionService
	googleService   *auth.GoogleService
}

// New creates a new IDM instance with the given configuration.
// Returns an error if required database tables don't exist.
// Run migrations first - see migrations/ folder for SQL files.
func New(cfg Config) (*IDM, error) {
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	applyDefaults(&cfg)

	// Validate schema exists
	if err := validateSchema(cfg.DB); err != nil {
		return nil, err
	}

	// Initialize repositories
	usersRepo := repository.NewUsersRepository(cfg.DB)
	credsRepo := repository.NewCredentialsRepository(cfg.DB)
	identitiesRepo := repository.NewIdentitiesRepository(cfg.DB)
	sessionsRepo := repository.NewSessionsRepository(cfg.DB)
	tenantsRepo := repository.NewTenantsRepository(cfg.DB)
	membershipsRepo := repository.NewMembershipsRepository(cfg.DB)

	// Initialize services
	passwordService := auth.NewPasswordService(cfg.DB, usersRepo, credsRepo)
	sessionService := auth.NewSessionService(auth.SessionConfig{
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		JWTSecret:       []byte(cfg.JWTSecret),
		Issuer:          cfg.JWTIssuer,
	}, sessionsRepo, usersRepo, membershipsRepo)

	var googleService *auth.GoogleService
	if cfg.Google != nil {
		googleService = auth.NewGoogleService(
			auth.GoogleConfig{
				ClientID:     cfg.Google.ClientID,
				ClientSecret: cfg.Google.ClientSecret,
				RedirectURI:  cfg.Google.RedirectURI,
			},
			cfg.DB,
			usersRepo,
			identitiesRepo,
		)
	}

	return &IDM{
		config:          cfg,
		db:              cfg.DB,
		usersRepo:       usersRepo,
		credsRepo:       credsRepo,
		identitiesRepo:  identitiesRepo,
		sessionsRepo:    sessionsRepo,
		tenantsRepo:     tenantsRepo,
		membershipsRepo: membershipsRepo,
		passwordService: passwordService,
		sessionService:  sessionService,
		googleService:   googleService,
	}, nil
}

// Router returns a chi router with all auth routes.
// Mount this on your main router:
//
//	r := chi.NewRouter()
//	r.Mount("/auth", auth.Router())
//
// Routes:
//
//	POST /register          - Register with email/password
//	POST /login             - Login with email/password
//	POST /refresh           - Refresh access token
//	POST /logout            - Logout (revoke session)
//	POST /logout/all        - Logout all sessions (protected)
//	GET  /me                - Get current user (protected)
//	PATCH /me               - Update current user (protected)
//	GET  /google/start      - Start Google OAuth (if configured)
//	GET  /google/callback   - Google OAuth callback (if configured)
func (i *IDM) Router() chi.Router {
	r := chi.NewRouter()

	// Middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Logger)

	// Password auth routes
	passwordHandler := password.NewHandler(
		i.config.Logger,
		i.passwordService,
		i.sessionService,
		nil,   // verification service
		nil,   // email service
		i.tenantsRepo,
		i.membershipsRepo,
		"",    // app base URL
		false, // requireEmailVerification (disabled without email service)
	)
	r.Post("/register", passwordHandler.Register)
	r.Post("/login", passwordHandler.Login)

	// Session routes
	sessionHandler := session.NewHandler(i.sessionService)
	r.Post("/refresh", sessionHandler.Refresh)
	r.Post("/logout", sessionHandler.Logout)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(i.sessionService))

		r.Post("/logout/all", sessionHandler.LogoutAll)

		// User profile routes
		meHandler := me.NewHandler(slog.Default(), i.usersRepo, i.passwordService, i.sessionService, nil, nil, "")
		r.Get("/me", meHandler.GetMe)
		r.Patch("/me", meHandler.UpdateMe)
	})

	// Google OAuth routes (if configured)
	if i.googleService != nil {
		googleHandler := google.NewHandler(
			i.googleService,
			i.sessionService,
			i.tenantsRepo,
			i.membershipsRepo,
			i.usersRepo,
			i.config.Logger,
		)
		r.Get("/google/start", googleHandler.Start)
		r.Get("/google/callback", googleHandler.Callback)
	}

	return r
}

// MeRouter returns a protected chi router for user profile endpoints.
// Mount this wherever you want the /me endpoint:
//
//	r.Mount("/user", auth.MeRouter())      // GET/PATCH /user
//	r.Mount("/profile", auth.MeRouter())   // GET/PATCH /profile
func (i *IDM) MeRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Auth(i.sessionService))

	meHandler := me.NewHandler(slog.Default(), i.usersRepo, i.passwordService, i.sessionService, nil, nil, "")
	r.Get("/", meHandler.GetMe)
	r.Patch("/", meHandler.UpdateMe)
	r.Delete("/", meHandler.DeleteMe)

	return r
}

// AuthRouter returns a chi router with only auth routes (no /me).
// Use this if you want to mount /me separately:
//
//	r.Mount("/auth", auth.AuthRouter())
//	r.Mount("/user", auth.MeRouter())
func (i *IDM) AuthRouter() chi.Router {
	r := chi.NewRouter()

	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Logger)

	// Password auth routes
	passwordHandler := password.NewHandler(
		i.config.Logger,
		i.passwordService,
		i.sessionService,
		nil,   // verification service
		nil,   // email service
		i.tenantsRepo,
		i.membershipsRepo,
		"",    // app base URL
		false, // requireEmailVerification (disabled without email service)
	)
	r.Post("/register", passwordHandler.Register)
	r.Post("/login", passwordHandler.Login)

	// Session routes
	sessionHandler := session.NewHandler(i.sessionService)
	r.Post("/refresh", sessionHandler.Refresh)
	r.Post("/logout", sessionHandler.Logout)

	// Protected logout all
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(i.sessionService))
		r.Post("/logout/all", sessionHandler.LogoutAll)
	})

	// Google OAuth routes (if configured)
	if i.googleService != nil {
		googleHandler := google.NewHandler(
			i.googleService,
			i.sessionService,
			i.tenantsRepo,
			i.membershipsRepo,
			i.usersRepo,
			i.config.Logger,
		)
		r.Get("/google/start", googleHandler.Start)
		r.Get("/google/callback", googleHandler.Callback)
	}

	return r
}

// SessionService returns the session service for advanced usage.
func (i *IDM) SessionService() *auth.SessionService {
	return i.sessionService
}

// AuthMiddleware returns middleware that validates JWT tokens.
// Use this to protect your own routes:
//
//	r.Group(func(r chi.Router) {
//	    r.Use(auth.AuthMiddleware())
//	    r.Get("/protected", handler)
//	})
func (i *IDM) AuthMiddleware() func(http.Handler) http.Handler {
	return middleware.Auth(i.sessionService)
}

// GetUserID extracts the user ID from a request.
// Use after AuthMiddleware:
//
//	userID, ok := idm.GetUserID(r)
func GetUserID(r *http.Request) (string, bool) {
	id, ok := middleware.GetUserID(r.Context())
	if !ok {
		return "", false
	}
	return id.String(), true
}

// GetUserIDFromContext extracts the user ID from a context.
// Use after AuthMiddleware:
//
//	userID, ok := idm.GetUserIDFromContext(ctx)
func GetUserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	return middleware.GetUserID(ctx)
}

// User represents basic user info returned by GetUser.
type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          *string
}

// GetUser retrieves the current user from the database.
// Use after AuthMiddleware:
//
//	user, err := auth.GetUser(r)
func (i *IDM) GetUser(r *http.Request) (*User, error) {
	id, ok := middleware.GetUserID(r.Context())
	if !ok {
		return nil, errors.New("user not authenticated")
	}

	u, err := i.usersRepo.GetByID(r.Context(), id)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:            u.ID.String(),
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
	}, nil
}

// HealthHandler returns a simple health check handler.
func (i *IDM) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// Handler returns an http.Handler for mounting with http.StripPrefix.
// This is useful when using standard library ServeMux:
//
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
func (i *IDM) Handler() http.Handler {
	return i.Router()
}

// Routes registers all auth routes on an http.ServeMux with the given prefix.
// This provides a simpler way to mount routes without StripPrefix:
//
//	mux := http.NewServeMux()
//	auth.Routes(mux, "/api/v1/auth")
func (i *IDM) Routes(mux *http.ServeMux, prefix string) {
	mux.Handle(prefix+"/", http.StripPrefix(prefix, i.Router()))
}

// MeHandler returns an http.Handler for just the /me endpoints.
// Use this when you want to mount /me separately:
//
//	mux.Handle("/user/profile", auth.MeHandler())
func (i *IDM) MeHandler() http.Handler {
	return i.MeRouter()
}

func validateConfig(cfg *Config) error {
	if cfg.DB == nil {
		return errors.New("idm: DB is required")
	}
	if cfg.JWTSecret == "" {
		return errors.New("idm: JWTSecret is required")
	}
	if len(cfg.JWTSecret) < 32 {
		return errors.New("idm: JWTSecret must be at least 32 characters")
	}
	if cfg.Google != nil {
		if cfg.Google.ClientID == "" || cfg.Google.ClientSecret == "" {
			return errors.New("idm: Google ClientID and ClientSecret are required when Google is configured")
		}
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.JWTIssuer == "" {
		cfg.JWTIssuer = "simple-idm"
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
}

// validateSchema checks that required database tables exist.
func validateSchema(db *sql.DB) error {
	requiredTables := []string{"users", "user_password", "user_identities", "sessions"}

	query := `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = $1
	`

	for _, table := range requiredTables {
		var name string
		err := db.QueryRow(query, table).Scan(&name)
		if err == sql.ErrNoRows {
			return fmt.Errorf("idm: missing table '%s' - run migrations first (see migrations/ folder)", table)
		}
		if err != nil {
			return fmt.Errorf("idm: failed to check schema: %w", err)
		}
	}

	return nil
}
