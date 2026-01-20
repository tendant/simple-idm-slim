package session

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// Alias for cleaner code
type tokenPair = domain.TokenPair

// Handler handles session endpoints.
type Handler struct {
	sessionService *auth.SessionService
	cookieConfig   httputil.CookieConfig
}

// NewHandler creates a new session handler.
func NewHandler(sessionService *auth.SessionService) *Handler {
	return &Handler{
		sessionService: sessionService,
		cookieConfig:   httputil.DefaultCookieConfig(),
	}
}

// RefreshRequest represents a token refresh request (for mobile clients).
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse represents a token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// LogoutRequest represents a logout request (for mobile clients).
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh refreshes an access token.
// POST /v1/auth/refresh
//
// For web clients: Reads refresh token from cookie, sets new cookies.
// For mobile clients: Reads/returns tokens in request/response body.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var refreshToken string

	if httputil.IsMobileClient(r) {
		// Mobile: read from request body
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.Error(w, http.StatusBadRequest, "invalid request body")
			return
		}
		refreshToken = req.RefreshToken
	} else {
		// Web: read from cookie
		var ok bool
		refreshToken, ok = httputil.GetRefreshTokenFromCookie(r)
		if !ok {
			httputil.Error(w, http.StatusUnauthorized, "refresh token not found")
			return
		}
	}

	if refreshToken == "" {
		httputil.Error(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	tokens, err := h.sessionService.RefreshSession(r.Context(), refreshToken, opts)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) ||
			errors.Is(err, domain.ErrSessionExpired) ||
			errors.Is(err, domain.ErrSessionRevoked) {
			// Clear cookies on invalid token for web clients
			if !httputil.IsMobileClient(r) {
				httputil.ClearAuthCookies(w, h.cookieConfig)
			}
			httputil.Error(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "failed to refresh token")
		return
	}

	h.writeTokenResponse(w, r, tokens)
}

// Logout revokes a session.
// POST /v1/auth/logout
//
// For web clients: Reads refresh token from cookie, clears cookies.
// For mobile clients: Reads token from request body.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var refreshToken string

	if httputil.IsMobileClient(r) {
		// Mobile: read from request body
		var req LogoutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.Error(w, http.StatusBadRequest, "invalid request body")
			return
		}
		refreshToken = req.RefreshToken
	} else {
		// Web: read from cookie
		refreshToken, _ = httputil.GetRefreshTokenFromCookie(r)
	}

	if refreshToken != "" {
		// Revoke session (ignore errors to prevent enumeration attacks)
		_ = h.sessionService.RevokeSession(r.Context(), refreshToken)
	}

	// Clear cookies for web clients
	if !httputil.IsMobileClient(r) {
		httputil.ClearAuthCookies(w, h.cookieConfig)
	}

	w.WriteHeader(http.StatusNoContent)
}

// LogoutAll revokes all sessions for the current user.
// POST /v1/auth/logout/all
// Requires authentication
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.sessionService.RevokeAllSessions(r.Context(), userID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to logout all sessions")
		return
	}

	// Clear cookies for web clients
	if !httputil.IsMobileClient(r) {
		httputil.ClearAuthCookies(w, h.cookieConfig)
	}

	w.WriteHeader(http.StatusNoContent)
}

// writeTokenResponse writes tokens as cookies (web) or JSON (mobile).
func (h *Handler) writeTokenResponse(w http.ResponseWriter, r *http.Request, tokens *tokenPair) {
	if httputil.IsMobileClient(r) {
		httputil.JSON(w, http.StatusOK, TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			TokenType:    tokens.TokenType,
			ExpiresIn:    tokens.ExpiresIn,
		})
		return
	}

	// Web: set HttpOnly cookies
	httputil.SetAuthCookies(
		w,
		tokens.AccessToken,
		tokens.RefreshToken,
		h.sessionService.AccessTokenTTL(),
		h.sessionService.RefreshTokenTTL(),
		h.cookieConfig,
	)

	httputil.JSON(w, http.StatusOK, TokenResponse{
		TokenType: tokens.TokenType,
		ExpiresIn: tokens.ExpiresIn,
	})
}
