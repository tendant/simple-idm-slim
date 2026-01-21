package middleware

import (
	"net/http"
)

// RequireVerified creates middleware that requires email verification.
// Must be used after Auth middleware.
func RequireVerified() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r.Context())
			if !ok {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			if !claims.EmailVerified {
				http.Error(w, `{"error":"email verification required"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
