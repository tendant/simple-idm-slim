package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/httprate"
	"github.com/tendant/simple-idm-slim/internal/config"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// RateLimitConfig holds rate limiting configuration for a specific endpoint type.
type RateLimitConfig struct {
	Requests int
	Window   time.Duration
	Logger   *slog.Logger
}

// RateLimit creates an IP-based rate limiter middleware with logging.
func RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	return httprate.Limit(
		cfg.Requests,
		cfg.Window,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Logger != nil {
				cfg.Logger.Warn("rate limit exceeded",
					"ip", r.RemoteAddr,
					"path", r.URL.Path,
					"method", r.Method,
					"user_agent", r.UserAgent(),
				)
			}
			httputil.Error(w, http.StatusTooManyRequests, "rate limit exceeded. please try again later")
		}),
	)
}

// NoRateLimit returns a no-op middleware when rate limiting is disabled.
func NoRateLimit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}

// CreateRateLimiters creates rate limiting middleware functions based on configuration.
func CreateRateLimiters(cfg config.RateLimitConfig, logger *slog.Logger) map[string]func(http.Handler) http.Handler {
	if !cfg.Enabled {
		noOp := NoRateLimit()
		return map[string]func(http.Handler) http.Handler{
			"auth":    noOp,
			"reset":   noOp,
			"verify":  noOp,
			"refresh": noOp,
			"profile": noOp,
		}
	}

	return map[string]func(http.Handler) http.Handler{
		"auth": RateLimit(RateLimitConfig{
			Requests: cfg.AuthRequestsPerMinute,
			Window:   time.Duration(cfg.AuthWindowMinutes) * time.Minute,
			Logger:   logger,
		}),
		"reset": RateLimit(RateLimitConfig{
			Requests: cfg.ResetRequestsPerWindow,
			Window:   time.Duration(cfg.ResetWindowMinutes) * time.Minute,
			Logger:   logger,
		}),
		"verify": RateLimit(RateLimitConfig{
			Requests: cfg.VerifyRequestsPerWindow,
			Window:   time.Duration(cfg.VerifyWindowMinutes) * time.Minute,
			Logger:   logger,
		}),
		"refresh": RateLimit(RateLimitConfig{
			Requests: cfg.RefreshRequestsPerMinute,
			Window:   time.Duration(cfg.RefreshWindowMinutes) * time.Minute,
			Logger:   logger,
		}),
		"profile": RateLimit(RateLimitConfig{
			Requests: cfg.ProfileRequestsPerMinute,
			Window:   time.Duration(cfg.ProfileWindowMinutes) * time.Minute,
			Logger:   logger,
		}),
	}
}
