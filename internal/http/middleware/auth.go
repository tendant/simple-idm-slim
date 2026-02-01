package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/auth"
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
	return AuthWithLogger(sessionService, slog.Default())
}

// AuthWithLogger creates middleware that validates JWT access tokens with custom logger.
// Checks Authorization header first, then falls back to cookie for web clients.
func AuthWithLogger(sessionService *auth.SessionService, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string
			var tokenSource string

			clientIP := r.RemoteAddr
			path := r.URL.Path
			method := r.Method

			// Try Authorization header first (mobile clients and API calls)
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					tokenString = parts[1]
					tokenSource = "header"
				}
			}

			// Fall back to cookie (web clients)
			if tokenString == "" {
				if token, ok := httputil.GetAccessTokenFromCookie(r); ok {
					tokenString = token
					tokenSource = "cookie"
				}
			}

			if tokenString == "" {
				logger.Debug("auth middleware: no token found",
					"path", path,
					"method", method,
					"client_ip", clientIP,
				)
				http.Error(w, `{"error":"missing authorization"}`, http.StatusUnauthorized)
				return
			}

			// Log token validation attempt (mask the token)
			maskedToken := ""
			if len(tokenString) > 20 {
				maskedToken = tokenString[:10] + "..." + tokenString[len(tokenString)-10:]
			}
			logger.Debug("auth middleware: validating token",
				"path", path,
				"method", method,
				"client_ip", clientIP,
				"token_source", tokenSource,
				"token_prefix", maskedToken,
			)

			// Validate token
			claims, err := sessionService.ValidateAccessToken(tokenString)
			if err != nil {
				logger.Warn("auth middleware: token validation failed",
					"path", path,
					"method", method,
					"client_ip", clientIP,
					"token_source", tokenSource,
					"error", err,
				)
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Parse user ID
			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				logger.Warn("auth middleware: invalid user ID in token",
					"path", path,
					"method", method,
					"client_ip", clientIP,
					"subject", claims.Subject,
					"error", err,
				)
				http.Error(w, `{"error":"invalid token subject"}`, http.StatusUnauthorized)
				return
			}

			logger.Debug("auth middleware: token validated successfully",
				"path", path,
				"method", method,
				"client_ip", clientIP,
				"user_id", userID,
				"token_source", tokenSource,
			)

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
