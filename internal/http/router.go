package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/internal/http/features/email"
	"github.com/tendant/simple-idm-slim/internal/http/features/google"
	"github.com/tendant/simple-idm-slim/internal/http/features/me"
	"github.com/tendant/simple-idm-slim/internal/http/features/pages"
	"github.com/tendant/simple-idm-slim/internal/http/features/password"
	"github.com/tendant/simple-idm-slim/internal/http/features/session"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/notification"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

// RouterConfig holds configuration for the router.
type RouterConfig struct {
	Logger                   *slog.Logger
	PasswordService          *auth.PasswordService
	GoogleService            *auth.GoogleService
	SessionService           *auth.SessionService
	VerificationService      *auth.VerificationService
	EmailService             *notification.EmailService
	UsersRepo                *repository.UsersRepository
	TenantsRepo              *repository.TenantsRepository
	MembershipsRepo          *repository.MembershipsRepository
	AppBaseURL               string
	ServeUI                  bool
	TemplatesDir             string
	RequireEmailVerification bool
}

// NewRouter creates a new HTTP router with all routes registered.
func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	// Apply global middleware
	r.Use(middleware.Recover(cfg.Logger))
	r.Use(middleware.Logging(cfg.Logger))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		httputil.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Create rate limiters for different endpoint types
	authRateLimiter := httprate.Limit(
		10,                // 10 requests
		time.Minute,       // per minute
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			httputil.Error(w, http.StatusTooManyRequests, "rate limit exceeded. please try again later")
		}),
	)

	resetRateLimiter := httprate.Limit(
		3,                 // 3 requests
		5*time.Minute,     // per 5 minutes
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			httputil.Error(w, http.StatusTooManyRequests, "rate limit exceeded. please try again later")
		}),
	)

	verifyRateLimiter := httprate.Limit(
		5,                 // 5 requests
		5*time.Minute,     // per 5 minutes
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			httputil.Error(w, http.StatusTooManyRequests, "rate limit exceeded. please try again later")
		}),
	)

	// Register password authentication routes
	passwordHandler := password.NewHandler(
		cfg.Logger,
		cfg.PasswordService,
		cfg.SessionService,
		cfg.VerificationService,
		cfg.EmailService,
		cfg.TenantsRepo,
		cfg.MembershipsRepo,
		cfg.AppBaseURL,
		cfg.RequireEmailVerification,
	)
	r.Group(func(r chi.Router) {
		r.Use(authRateLimiter)
		r.Post("/v1/auth/password/register", passwordHandler.Register)
		r.Post("/v1/auth/password/login", passwordHandler.Login)
	})
	r.Group(func(r chi.Router) {
		r.Use(resetRateLimiter)
		r.Post("/v1/auth/password/reset-request", passwordHandler.RequestPasswordReset)
		r.Post("/v1/auth/password/reset", passwordHandler.ResetPassword)
	})

	// Register Google OAuth routes (if configured)
	if cfg.GoogleService != nil {
		googleHandler := google.NewHandler(
			cfg.GoogleService,
			cfg.SessionService,
			cfg.TenantsRepo,
			cfg.MembershipsRepo,
			cfg.UsersRepo,
			cfg.Logger,
		)
		r.Get("/v1/auth/google", googleHandler.Start)
		r.Get("/v1/auth/google/callback", googleHandler.Callback)
	}

	// Register session routes
	sessionHandler := session.NewHandler(cfg.SessionService)
	r.Post("/v1/auth/refresh", sessionHandler.Refresh)
	r.Post("/v1/auth/logout", sessionHandler.Logout)
	r.With(middleware.Auth(cfg.SessionService)).Post("/v1/auth/logout/all", sessionHandler.LogoutAll)

	// Register user profile routes
	meHandler := me.NewHandler(
		cfg.Logger,
		cfg.UsersRepo,
		cfg.PasswordService,
		cfg.SessionService,
		cfg.VerificationService,
		cfg.EmailService,
		cfg.AppBaseURL,
	)
	r.With(middleware.Auth(cfg.SessionService)).Get("/v1/me", meHandler.GetMe)
	r.With(middleware.Auth(cfg.SessionService)).Patch("/v1/me", meHandler.UpdateMe)
	r.With(middleware.Auth(cfg.SessionService)).Delete("/v1/me", meHandler.DeleteMe)

	// Email verification routes (if email service is configured)
	if cfg.EmailService != nil {
		emailHandler := email.NewHandler(
			cfg.Logger,
			cfg.VerificationService,
			cfg.EmailService,
			cfg.SessionService,
			cfg.PasswordService,
			cfg.AppBaseURL,
		)
		r.Post("/v1/auth/verify-email", emailHandler.VerifyEmail)
		r.With(middleware.Auth(cfg.SessionService)).Post("/v1/auth/resend-verification", emailHandler.ResendVerificationEmail)
		r.With(verifyRateLimiter).Post("/v1/auth/request-verification", emailHandler.RequestVerificationEmail)
	}

	// Authentication pages (if UI is enabled)
	if cfg.ServeUI {
		pagesHandler, err := pages.NewHandler(cfg.TemplatesDir)
		if err != nil {
			cfg.Logger.Error("failed to load page templates", "error", err)
		} else {
			r.Get("/auth/register", pagesHandler.Register)
			r.Get("/auth/login", pagesHandler.Login)
			r.Get("/auth/verify-email", pagesHandler.VerifyEmail)
			r.Get("/auth/reset-password", pagesHandler.ResetPassword)
			r.Get("/auth/reset-password/confirm", pagesHandler.ResetPasswordConfirm)
			r.Get("/auth/request-verification", pagesHandler.RequestVerification)
		}
	}

	return r
}
