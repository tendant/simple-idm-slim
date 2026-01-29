package middleware

import (
	"fmt"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/config"
)

// SecurityHeaders creates middleware that applies OWASP-recommended security headers.
func SecurityHeaders(cfg config.SecurityHeadersConfig) func(http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Content Security Policy - prevents XSS attacks
			if cfg.CSP != "" {
				w.Header().Set("Content-Security-Policy", cfg.CSP)
			}

			// Strict-Transport-Security - enforces HTTPS
			if cfg.HSTSMaxAge > 0 {
				w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", cfg.HSTSMaxAge))
			}

			// X-Frame-Options - prevents clickjacking
			if cfg.FrameOptions != "" {
				w.Header().Set("X-Frame-Options", cfg.FrameOptions)
			}

			// X-Content-Type-Options - prevents MIME sniffing
			if cfg.ContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", cfg.ContentTypeOptions)
			}

			// X-XSS-Protection - legacy XSS protection
			if cfg.XSSProtection != "" {
				w.Header().Set("X-XSS-Protection", cfg.XSSProtection)
			}

			// Referrer-Policy - controls referrer information
			if cfg.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", cfg.ReferrerPolicy)
			}

			// Permissions-Policy - controls browser features
			if cfg.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", cfg.PermissionsPolicy)
			}

			next.ServeHTTP(w, r)
		})
	}
}
