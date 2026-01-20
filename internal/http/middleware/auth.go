package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

type contextKey string

const (
	// UserIDKey is the context key for the authenticated user ID.
	UserIDKey contextKey = "user_id"
	// ClaimsKey is the context key for the token claims.
	ClaimsKey contextKey = "claims"
)

// Auth creates middleware that validates JWT access tokens.
// Checks Authorization header first, then falls back to cookie for web clients.
func Auth(sessionService *auth.SessionService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// Try Authorization header first (mobile clients and API calls)
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					tokenString = parts[1]
				}
			}

			// Fall back to cookie (web clients)
			if tokenString == "" {
				if token, ok := httputil.GetAccessTokenFromCookie(r); ok {
					tokenString = token
				}
			}

			if tokenString == "" {
				http.Error(w, `{"error":"missing authorization"}`, http.StatusUnauthorized)
				return
			}

			// Validate token
			claims, err := sessionService.ValidateAccessToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Parse user ID
			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				http.Error(w, `{"error":"invalid token subject"}`, http.StatusUnauthorized)
				return
			}

			// Add user ID and claims to context
			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, ClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID extracts the user ID from the request context.
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(UserIDKey).(uuid.UUID)
	return userID, ok
}

// GetClaims extracts the token claims from the request context.
func GetClaims(ctx context.Context) (*auth.AccessTokenClaims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*auth.AccessTokenClaims)
	return claims, ok
}
