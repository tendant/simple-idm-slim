package middleware

import (
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// RequireMFA enforces MFA verification for sensitive endpoints.
// This middleware should be applied AFTER the Auth middleware.
// It checks the MFAVerified claim in the JWT and returns 403 if MFA was not verified.
//
// Example usage:
//
//	r.With(middleware.Auth(sessionService)).
//	  With(middleware.RequireMFA()).
//	  Delete("/v1/me", meHandler.DeleteMe)
func RequireMFA() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get claims from context (set by Auth middleware)
			claims, ok := GetClaims(r.Context())
			if !ok {
				httputil.Error(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			// Check if MFA was verified
			if !claims.MFAVerified {
				httputil.Error(w, http.StatusForbidden, "MFA verification required for this operation")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
