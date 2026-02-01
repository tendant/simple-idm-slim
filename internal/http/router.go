package http

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/internal/config"
	"github.com/tendant/simple-idm-slim/internal/http/features/email"
	"github.com/tendant/simple-idm-slim/internal/http/features/google"
	"github.com/tendant/simple-idm-slim/internal/http/features/me"
	"github.com/tendant/simple-idm-slim/internal/http/features/mfa"
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
	Logger                    *slog.Logger
	PasswordService           *auth.PasswordService
	GoogleService             *auth.GoogleService
	SessionService            *auth.SessionService
	VerificationService       *auth.VerificationService
	EmailService              *notification.EmailService
	MFAService                *auth.MFAService
	UsersRepo                 *repository.UsersRepository
	AppBaseURL                string
	ServeUI                   bool
	TemplatesDir              string
	RateLimitConfig           config.RateLimitConfig
	SecurityHeaders           config.SecurityHeadersConfig
	Validation                config.ValidationConfig
	SessionSecurity           config.SessionSecurityConfig
	EmailVerificationRequired bool
	OAuthStateSignKey         []byte // Key for signing OAuth state cookies (enables multi-replica support)
	CookieSecure              bool   // Whether to use Secure flag on cookies (should be true for HTTPS)
}

// NewRouter creates a new HTTP router with all routes registered.
func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	// Apply global middleware
	r.Use(middleware.Recover(cfg.Logger))
	r.Use(middleware.Logging(cfg.Logger))
	r.Use(middleware.SecurityHeaders(cfg.SecurityHeaders))
	r.Use(middleware.RequestSizeLimit(cfg.Validation.MaxRequestBodySize))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		httputil.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Create rate limiters for different endpoint types
	rateLimiters := middleware.CreateRateLimiters(cfg.RateLimitConfig, cfg.Logger)

	// Register password authentication routes
	passwordHandler := password.NewHandler(
		cfg.Logger,
		cfg.PasswordService,
		cfg.SessionService,
		cfg.VerificationService,
		cfg.EmailService,
		cfg.MFAService,
		cfg.AppBaseURL,
		cfg.EmailVerificationRequired,
	)
	r.Group(func(r chi.Router) {
		r.Use(rateLimiters["auth"])
		r.Post("/v1/auth/password/register", passwordHandler.Register)
		r.Post("/v1/auth/password/login", passwordHandler.Login)
	})
	r.Group(func(r chi.Router) {
		r.Use(rateLimiters["reset"])
		r.Post("/v1/auth/password/reset-request", passwordHandler.RequestPasswordReset)
		r.Post("/v1/auth/password/reset", passwordHandler.ResetPassword)
	})

	// Register Google OAuth routes (if configured)
	if cfg.GoogleService != nil {
		var googleHandler *google.Handler
		if len(cfg.OAuthStateSignKey) > 0 {
			// Use cookie-based state storage (recommended for multi-replica deployments)
			googleHandler = google.NewHandlerWithCookieState(cfg.GoogleService, cfg.SessionService, cfg.OAuthStateSignKey, cfg.CookieSecure)
			cfg.Logger.Info("Google OAuth: using cookie-based state storage (multi-replica safe)")
		} else {
			// Fall back to in-memory state storage (single replica only)
			googleHandler = google.NewHandler(cfg.GoogleService, cfg.SessionService)
			cfg.Logger.Warn("Google OAuth: using in-memory state storage (not safe for multi-replica)")
		}
		r.Get("/v1/auth/google", googleHandler.Start)
		r.Get("/v1/auth/google/callback", googleHandler.Callback)
	}

	// Register session routes
	sessionHandler := session.NewHandler(cfg.SessionService)
	r.Group(func(r chi.Router) {
		r.Use(rateLimiters["refresh"])
		r.Post("/v1/auth/refresh", sessionHandler.Refresh)
	})
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
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(cfg.SessionService))
		r.Use(rateLimiters["profile"])
		r.Get("/v1/me", meHandler.GetMe)
		r.Patch("/v1/me", meHandler.UpdateMe)
		r.Delete("/v1/me", meHandler.DeleteMe)
	})

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
		r.With(rateLimiters["verify"]).Post("/v1/auth/verify-email", emailHandler.VerifyEmail)
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(cfg.SessionService))
			r.Use(rateLimiters["verify"])
			r.Post("/v1/auth/resend-verification", emailHandler.ResendVerificationEmail)
		})
		r.With(rateLimiters["verify"]).Post("/v1/auth/request-verification", emailHandler.RequestVerificationEmail)
	}

	// MFA routes (if MFA service is configured)
	if cfg.MFAService != nil {
		mfaHandler := mfa.NewHandler(
			cfg.Logger,
			cfg.MFAService,
			cfg.PasswordService,
			cfg.SessionService,
		)

		// Authenticated MFA management
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(cfg.SessionService))
			r.Use(rateLimiters["profile"])
			r.Get("/v1/me/mfa/status", mfaHandler.Status)
			r.Post("/v1/me/mfa/setup", mfaHandler.Setup)
			r.Post("/v1/me/mfa/enable", mfaHandler.Enable)
			r.Post("/v1/me/mfa/disable", mfaHandler.Disable)
		})

		// Unauthenticated MFA verification
		r.Group(func(r chi.Router) {
			r.Use(rateLimiters["auth"])
			r.Post("/v1/auth/mfa/verify", mfaHandler.Verify)
		})
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
