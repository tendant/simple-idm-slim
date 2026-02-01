package google

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// Handler handles Google OAuth endpoints.
type Handler struct {
	googleService  *auth.GoogleService
	sessionService *auth.SessionService
	stateStore     *StateStore
	stateSignKey   []byte // Key for signing state cookies
	cookieSecure   bool   // Whether to use Secure flag on cookies
}

// NewHandler creates a new Google handler.
func NewHandler(googleService *auth.GoogleService, sessionService *auth.SessionService) *Handler {
	return &Handler{
		googleService:  googleService,
		sessionService: sessionService,
		stateStore:     NewStateStore(),
		stateSignKey:   nil, // Will fall back to in-memory store
		cookieSecure:   true,
	}
}

// NewHandlerWithCookieState creates a handler that stores OAuth state in signed cookies.
// This is recommended for multi-replica deployments.
func NewHandlerWithCookieState(googleService *auth.GoogleService, sessionService *auth.SessionService, stateSignKey []byte, cookieSecure bool) *Handler {
	return &Handler{
		googleService:  googleService,
		sessionService: sessionService,
		stateStore:     NewStateStore(), // Keep as fallback
		stateSignKey:   stateSignKey,
		cookieSecure:   cookieSecure,
	}
}

// signState creates an HMAC signature for state data.
func (h *Handler) signState(data string) string {
	mac := hmac.New(sha256.New, h.stateSignKey)
	mac.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyStateSignature verifies the HMAC signature of state data.
func (h *Handler) verifyStateSignature(data, signature string) bool {
	expected := h.signState(data)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// StateStore stores OAuth state for CSRF protection.
// In production, use Redis or similar for distributed systems.
type StateStore struct {
	mu     sync.RWMutex
	states map[string]*auth.OAuthState
}

// NewStateStore creates a new state store.
func NewStateStore() *StateStore {
	s := &StateStore{
		states: make(map[string]*auth.OAuthState),
	}
	// Start cleanup goroutine
	go s.cleanup()
	return s
}

func (s *StateStore) Set(state *auth.OAuthState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	slog.Debug("StateStore.Set: stored OAuth state",
		"state_prefix", state.State[:10]+"...",
		"expires_at", state.ExpiresAt,
		"total_states", len(s.states),
	)
}

func (s *StateStore) Get(state string) (*auth.OAuthState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.states[state]
	statePrefix := state
	if len(state) > 10 {
		statePrefix = state[:10] + "..."
	}
	slog.Debug("StateStore.Get: looking up OAuth state",
		"state_prefix", statePrefix,
		"found", ok,
		"total_states", len(s.states),
	)
	return st, ok
}

func (s *StateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
	statePrefix := state
	if len(state) > 10 {
		statePrefix = state[:10] + "..."
	}
	slog.Debug("StateStore.Delete: removed OAuth state",
		"state_prefix", statePrefix,
	)
}

func (s *StateStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, state := range s.states {
			if now.After(state.ExpiresAt) {
				delete(s.states, key)
			}
		}
		s.mu.Unlock()
	}
}

// generateRandomString generates a cryptographically secure random string.
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Start initiates the Google OAuth flow.
// GET /v1/auth/google/start?redirect_uri=<app_return_uri>
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/"
	}

	// Generate state and nonce
	state := generateRandomString(32)
	nonce := generateRandomString(32)

	slog.Info("Google OAuth: starting auth flow",
		"client_ip", clientIP,
		"redirect_uri", redirectURI,
		"state_prefix", state[:10]+"...",
		"use_cookie_state", h.stateSignKey != nil,
	)

	// Store state - use cookie if signing key is configured, otherwise use in-memory
	oauthState := &auth.OAuthState{
		State:       state,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	if h.stateSignKey != nil {
		// Cookie-based state storage (recommended for multi-replica)
		// Format: nonce|redirect_uri|expiry|signature
		expiryStr := oauthState.ExpiresAt.Format(time.RFC3339)
		stateData := nonce + "|" + redirectURI + "|" + expiryStr
		signature := h.signState(stateData)
		cookieValue := base64.URLEncoding.EncodeToString([]byte(stateData + "|" + signature))

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state_" + state[:16],
			Value:    cookieValue,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			Secure:   h.cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
		slog.Debug("Google OAuth: stored state in cookie",
			"state_prefix", state[:10]+"...",
		)
	} else {
		// Fall back to in-memory store
		h.stateStore.Set(oauthState)
	}

	// Generate auth URL and redirect
	authURL := h.googleService.GenerateAuthURL(state, nonce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// CallbackResponse represents a successful callback response.
type CallbackResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
}

// Callback handles the Google OAuth callback.
// GET /v1/auth/google/callback?code=...&state=...
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	statePrefix := state
	if len(state) > 10 {
		statePrefix = state[:10] + "..."
	}

	slog.Info("Google OAuth: callback received",
		"client_ip", clientIP,
		"state_prefix", statePrefix,
		"has_code", code != "",
		"error", errorParam,
	)

	// Check for OAuth error
	if errorParam != "" {
		slog.Warn("Google OAuth: error from Google",
			"client_ip", clientIP,
			"error", errorParam,
		)
		httputil.Error(w, http.StatusBadRequest, errorParam)
		return
	}

	// Validate state - try cookie first, then fall back to in-memory
	var oauthState *auth.OAuthState
	var ok bool

	if h.stateSignKey != nil && len(state) >= 16 {
		// Try cookie-based state retrieval
		cookieName := "oauth_state_" + state[:16]
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			// Decode and verify cookie
			decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
			if err == nil {
				parts := strings.SplitN(string(decoded), "|", 4)
				if len(parts) == 4 {
					nonce, redirectURI, expiryStr, signature := parts[0], parts[1], parts[2], parts[3]
					stateData := nonce + "|" + redirectURI + "|" + expiryStr

					if h.verifyStateSignature(stateData, signature) {
						expiry, err := time.Parse(time.RFC3339, expiryStr)
						if err == nil {
							oauthState = &auth.OAuthState{
								State:       state,
								Nonce:       nonce,
								RedirectURI: redirectURI,
								ExpiresAt:   expiry,
							}
							ok = true
							slog.Debug("Google OAuth: state retrieved from cookie",
								"state_prefix", statePrefix,
							)
						}
					} else {
						slog.Warn("Google OAuth: cookie signature verification failed",
							"client_ip", clientIP,
							"state_prefix", statePrefix,
						)
					}
				}
			}
		}

		// Clear the cookie regardless
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   h.cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Fall back to in-memory store if cookie not found
	if !ok {
		oauthState, ok = h.stateStore.Get(state)
		if ok {
			h.stateStore.Delete(state)
			slog.Debug("Google OAuth: state retrieved from in-memory store",
				"state_prefix", statePrefix,
			)
		}
	}

	if !ok {
		slog.Warn("Google OAuth: state not found (possible pod restart or multi-replica issue)",
			"client_ip", clientIP,
			"state_prefix", statePrefix,
		)
		httputil.Error(w, http.StatusBadRequest, "invalid or expired state")
		return
	}

	if time.Now().After(oauthState.ExpiresAt) {
		slog.Warn("Google OAuth: state expired",
			"client_ip", clientIP,
			"state_prefix", statePrefix,
			"expired_at", oauthState.ExpiresAt,
		)
		httputil.Error(w, http.StatusBadRequest, "state expired")
		return
	}

	slog.Debug("Google OAuth: state validated, exchanging code",
		"client_ip", clientIP,
	)

	// Exchange code for tokens
	tokenResp, err := h.googleService.ExchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("Google OAuth: failed to exchange code",
			"client_ip", clientIP,
			"error", err,
		)
		httputil.Error(w, http.StatusInternalServerError, "failed to exchange code")
		return
	}

	// Validate ID token
	claims, err := h.googleService.ValidateIDToken(r.Context(), tokenResp.IDToken, oauthState.Nonce)
	if err != nil {
		slog.Error("Google OAuth: invalid ID token",
			"client_ip", clientIP,
			"error", err,
		)
		httputil.Error(w, http.StatusUnauthorized, "invalid ID token")
		return
	}

	slog.Debug("Google OAuth: ID token validated",
		"client_ip", clientIP,
		"email", claims.Email,
	)

	// Authenticate (find or create user)
	userID, err := h.googleService.Authenticate(r.Context(), claims)
	if err != nil {
		slog.Error("Google OAuth: authentication failed",
			"client_ip", clientIP,
			"email", claims.Email,
			"error", err,
		)
		httputil.Error(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	// Issue session
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), userID, opts)
	if err != nil {
		slog.Error("Google OAuth: failed to issue session",
			"client_ip", clientIP,
			"user_id", userID,
			"error", err,
		)
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	slog.Info("Google OAuth: login successful",
		"client_ip", clientIP,
		"user_id", userID,
		"email", claims.Email,
	)

	// Return tokens as JSON (or redirect with tokens in fragment/query for SPA)
	// For SPA, you might want to redirect to oauthState.RedirectURI with tokens
	httputil.JSON(w, http.StatusOK, CallbackResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
		RedirectURI:  oauthState.RedirectURI,
	})
}

// CallbackHTML handles the callback and returns an HTML page that posts tokens to the parent window.
// This is useful for popup-based OAuth flows.
func (h *Handler) CallbackHTML(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check for OAuth error
	if errorParam != "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"` + errorParam + `"},"*");window.close();</script></body></html>`))
		return
	}

	// Validate state
	oauthState, ok := h.stateStore.Get(state)
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"invalid_state"},"*");window.close();</script></body></html>`))
		return
	}
	h.stateStore.Delete(state)

	// Exchange code for tokens
	tokenResp, err := h.googleService.ExchangeCode(r.Context(), code)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"token_exchange_failed"},"*");window.close();</script></body></html>`))
		return
	}

	// Validate ID token
	claims, err := h.googleService.ValidateIDToken(r.Context(), tokenResp.IDToken, oauthState.Nonce)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"invalid_token"},"*");window.close();</script></body></html>`))
		return
	}

	// Authenticate
	userID, err := h.googleService.Authenticate(r.Context(), claims)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"auth_failed"},"*");window.close();</script></body></html>`))
		return
	}

	// Issue session
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), userID, opts)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"session_failed"},"*");window.close();</script></body></html>`))
		return
	}

	// Return HTML that posts tokens to parent window
	tokenJSON, _ := json.Marshal(map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"expires_in":    tokens.ExpiresIn,
	})

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<html><body><script>window.opener.postMessage(` + string(tokenJSON) + `,"*");window.close();</script></body></html>`))
}
