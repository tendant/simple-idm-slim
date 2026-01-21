package password

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/notification"
)

// Alias for cleaner code
type tokenPair = domain.TokenPair

// Handler handles password authentication endpoints.
type Handler struct {
	logger              *slog.Logger
	passwordService     *auth.PasswordService
	sessionService      *auth.SessionService
	verificationService *auth.VerificationService
	emailService        *notification.EmailService
	cookieConfig        httputil.CookieConfig
	appBaseURL          string
}

// NewHandler creates a new password handler.
func NewHandler(
	logger *slog.Logger,
	passwordService *auth.PasswordService,
	sessionService *auth.SessionService,
	verificationService *auth.VerificationService,
	emailService *notification.EmailService,
	appBaseURL string,
) *Handler {
	return &Handler{
		logger:              logger,
		passwordService:     passwordService,
		sessionService:      sessionService,
		verificationService: verificationService,
		emailService:        emailService,
		cookieConfig:        httputil.DefaultCookieConfig(),
		appBaseURL:          appBaseURL,
	}
}

// RegisterRequest represents a registration request.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse represents a token response (for mobile clients).
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Register handles user registration.
// POST /v1/auth/password/register
//
// For web clients: Sets HttpOnly cookies, returns minimal response.
// For mobile clients (X-Client-Type: mobile): Returns tokens in response body.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "email and password are required")
		return
	}

	if len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	user, err := h.passwordService.Register(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			httputil.Error(w, http.StatusConflict, "user already exists")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "registration failed")
		return
	}

	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), user.ID, opts)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	// Send verification email if email service is configured
	if h.emailService != nil && h.verificationService != nil {
		tokenOpts := auth.CreateVerificationTokenOpts{
			IP:        r.RemoteAddr,
			UserAgent: r.UserAgent(),
		}
		token, err := h.verificationService.CreateEmailVerificationToken(r.Context(), user.ID, tokenOpts)
		if err != nil {
			h.logger.Error("failed to create verification token", "error", err, "user_id", user.ID)
		} else {
			verifyURL := fmt.Sprintf("%s/auth/verify-email?token=%s", h.appBaseURL, token)
			if err := h.emailService.SendVerificationEmail(user.Email, verifyURL); err != nil {
				h.logger.Error("failed to send verification email", "error", err, "user_id", user.ID)
			} else {
				h.logger.Info("verification email sent", "user_id", user.ID)
			}
		}
	}

	h.writeTokenResponse(w, r, tokens, http.StatusCreated)
}

// Login handles user login.
// POST /v1/auth/password/login
//
// For web clients: Sets HttpOnly cookies, returns minimal response.
// For mobile clients (X-Client-Type: mobile): Returns tokens in response body.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "email and password are required")
		return
	}

	userID, err := h.passwordService.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			httputil.Error(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), userID, opts)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	h.writeTokenResponse(w, r, tokens, http.StatusOK)
}

// writeTokenResponse writes tokens as cookies (web) or JSON (mobile).
func (h *Handler) writeTokenResponse(w http.ResponseWriter, r *http.Request, tokens *tokenPair, status int) {
	if httputil.IsMobileClient(r) {
		// Mobile: return tokens in response body
		httputil.JSON(w, status, TokenResponse{
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

	httputil.JSON(w, status, TokenResponse{
		TokenType: tokens.TokenType,
		ExpiresIn: tokens.ExpiresIn,
	})
}

// PasswordResetRequestRequest represents a password reset request.
type PasswordResetRequestRequest struct {
	Email string `json:"email"`
}

// PasswordResetRequest represents a password reset.
type PasswordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// MessageResponse represents a simple message response.
type MessageResponse struct {
	Message string `json:"message"`
}

// RequestPasswordReset handles password reset requests.
// POST /v1/auth/password/reset-request
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		httputil.Error(w, http.StatusBadRequest, "email is required")
		return
	}

	if h.emailService == nil {
		httputil.Error(w, http.StatusServiceUnavailable, "email service not configured")
		return
	}

	// Look up user by email (don't reveal if user exists)
	user, err := h.passwordService.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Don't reveal whether user exists - always return success
		if !errors.Is(err, domain.ErrUserNotFound) {
			h.logger.Error("failed to get user by email", "error", err)
		}
		httputil.JSON(w, http.StatusOK, MessageResponse{
			Message: "If an account exists with that email, a password reset link has been sent",
		})
		return
	}

	// Create password reset token
	opts := auth.CreateVerificationTokenOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	token, err := h.verificationService.CreatePasswordResetToken(r.Context(), user.ID, opts)
	if err != nil {
		h.logger.Error("failed to create password reset token", "error", err, "user_id", user.ID)
		httputil.Error(w, http.StatusInternalServerError, "failed to create reset token")
		return
	}

	// Send password reset email
	resetURL := fmt.Sprintf("%s/auth/reset-password/confirm?token=%s", h.appBaseURL, token)
	if err := h.emailService.SendPasswordResetEmail(user.Email, resetURL); err != nil {
		h.logger.Error("failed to send password reset email", "error", err, "user_id", user.ID)
		httputil.Error(w, http.StatusInternalServerError, "failed to send reset email")
		return
	}

	h.logger.Info("password reset email sent", "user_id", user.ID)

	httputil.JSON(w, http.StatusOK, MessageResponse{
		Message: "If an account exists with that email, a password reset link has been sent",
	})
}

// ResetPassword handles password resets.
// POST /v1/auth/password/reset
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Token == "" {
		httputil.Error(w, http.StatusBadRequest, "token is required")
		return
	}

	if req.NewPassword == "" {
		httputil.Error(w, http.StatusBadRequest, "new password is required")
		return
	}

	if len(req.NewPassword) < 8 {
		httputil.Error(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Validate token
	userID, err := h.verificationService.ValidatePasswordResetToken(r.Context(), req.Token)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrVerificationTokenInvalid):
			httputil.Error(w, http.StatusBadRequest, "invalid reset token")
		case errors.Is(err, domain.ErrVerificationTokenExpired):
			httputil.Error(w, http.StatusBadRequest, "reset token expired")
		case errors.Is(err, domain.ErrVerificationTokenConsumed):
			httputil.Error(w, http.StatusBadRequest, "reset token already used")
		default:
			h.logger.Error("failed to validate password reset token", "error", err)
			httputil.Error(w, http.StatusInternalServerError, "validation failed")
		}
		return
	}

	// Change password
	if err := h.passwordService.ChangePassword(r.Context(), userID, req.NewPassword); err != nil {
		h.logger.Error("failed to change password", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to change password")
		return
	}

	// Consume token
	if err := h.verificationService.ConsumePasswordResetToken(r.Context(), req.Token); err != nil {
		h.logger.Error("failed to consume password reset token", "error", err, "user_id", userID)
		// Don't fail the request since password was already changed
	}

	// Revoke all existing sessions for security
	if err := h.sessionService.RevokeAllSessions(r.Context(), userID); err != nil {
		h.logger.Error("failed to revoke sessions", "error", err, "user_id", userID)
		// Don't fail the request
	}

	h.logger.Info("password reset successful", "user_id", userID)

	httputil.JSON(w, http.StatusOK, MessageResponse{
		Message: "Password reset successful",
	})
}
