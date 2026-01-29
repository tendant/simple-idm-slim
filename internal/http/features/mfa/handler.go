package mfa

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// Handler handles MFA-related HTTP requests
type Handler struct {
	logger          *slog.Logger
	mfaService      *auth.MFAService
	passwordService *auth.PasswordService
	sessionService  *auth.SessionService
}

// NewHandler creates a new MFA handler
func NewHandler(
	logger *slog.Logger,
	mfaService *auth.MFAService,
	passwordService *auth.PasswordService,
	sessionService *auth.SessionService,
) *Handler {
	return &Handler{
		logger:          logger,
		mfaService:      mfaService,
		passwordService: passwordService,
		sessionService:  sessionService,
	}
}

// SetupRequest represents the request body for MFA setup
type SetupRequest struct {
	Password string `json:"password"`
}

// SetupResponse represents the response body for MFA setup
type SetupResponse struct {
	QRCode        string   `json:"qr_code"`
	Secret        string   `json:"secret"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// Setup handles POST /v1/me/mfa/setup
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "password is required")
		return
	}

	// Verify password
	if _, err := h.passwordService.Authenticate(ctx, "", req.Password); err != nil {
		// For security, we need to verify it's the correct user's password
		// Get user and authenticate properly
		user, err := h.passwordService.GetUserByID(ctx, userID)
		if err != nil {
			httputil.Error(w, http.StatusInternalServerError, "failed to get user")
			return
		}

		// Authenticate with user's identifier
		authenticatedUserID, err := h.passwordService.Authenticate(ctx, user.Email, req.Password)
		if err != nil || authenticatedUserID != userID {
			httputil.Error(w, http.StatusUnauthorized, "invalid password")
			return
		}
	}

	// Setup TOTP
	setup, err := h.mfaService.SetupTOTP(ctx, userID)
	if err != nil {
		if err == domain.ErrMFAAlreadyEnabled {
			httputil.Error(w, http.StatusConflict, "MFA is already enabled")
			return
		}
		h.logger.Error("failed to setup TOTP", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to setup MFA")
		return
	}

	httputil.JSON(w, http.StatusOK, SetupResponse{
		QRCode:        setup.QRCodeDataURI,
		Secret:        setup.Secret,
		RecoveryCodes: setup.RecoveryCodes,
	})
}

// EnableRequest represents the request body for enabling MFA
type EnableRequest struct {
	Code string `json:"code"`
}

// Enable handles POST /v1/me/mfa/enable
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req EnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		httputil.Error(w, http.StatusBadRequest, "code is required")
		return
	}

	// Verify TOTP code and enable MFA
	if err := h.mfaService.VerifyTOTPAndEnable(ctx, userID, req.Code); err != nil {
		if err == domain.ErrInvalidMFACode {
			httputil.Error(w, http.StatusBadRequest, "invalid MFA code")
			return
		}
		if err == domain.ErrMFANotEnabled {
			httputil.Error(w, http.StatusBadRequest, "MFA setup not initiated. Please call /setup first")
			return
		}
		h.logger.Error("failed to enable MFA", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to enable MFA")
		return
	}

	httputil.JSON(w, http.StatusOK, map[string]string{
		"message": "MFA enabled successfully",
	})
}

// DisableRequest represents the request body for disabling MFA
type DisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// Disable handles POST /v1/me/mfa/disable
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req DisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" || req.Code == "" {
		httputil.Error(w, http.StatusBadRequest, "password and code are required")
		return
	}

	// Verify password
	user, err := h.passwordService.GetUserByID(ctx, userID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	authenticatedUserID, err := h.passwordService.Authenticate(ctx, user.Email, req.Password)
	if err != nil || authenticatedUserID != userID {
		httputil.Error(w, http.StatusUnauthorized, "invalid password")
		return
	}

	// Verify TOTP code or recovery code
	validTOTP, err := h.mfaService.VerifyTOTP(ctx, userID, req.Code)
	if err != nil && err != domain.ErrMFANotEnabled {
		h.logger.Error("failed to verify TOTP", "error", err)
	}

	validRecovery := false
	if !validTOTP {
		validRecovery, err = h.mfaService.VerifyRecoveryCode(ctx, userID, req.Code)
		if err != nil && err != domain.ErrInvalidRecoveryCode {
			h.logger.Error("failed to verify recovery code", "error", err)
		}
	}

	if !validTOTP && !validRecovery {
		httputil.Error(w, http.StatusUnauthorized, "invalid MFA code")
		return
	}

	// Disable MFA
	if err := h.mfaService.DisableMFA(ctx, userID); err != nil {
		h.logger.Error("failed to disable MFA", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to disable MFA")
		return
	}

	// Revoke all sessions for security
	if err := h.sessionService.RevokeAllSessions(ctx, userID); err != nil {
		h.logger.Error("failed to revoke sessions", "error", err)
	}

	httputil.JSON(w, http.StatusOK, map[string]string{
		"message": "MFA disabled. All sessions revoked.",
	})
}

// StatusResponse represents the response body for MFA status
type StatusResponse struct {
	Enabled                 bool `json:"enabled"`
	RecoveryCodesRemaining  int  `json:"recovery_codes_remaining"`
}

// Status handles GET /v1/me/mfa/status
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	enabled, remaining, err := h.mfaService.GetMFAStatus(ctx, userID)
	if err != nil {
		h.logger.Error("failed to get MFA status", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to get MFA status")
		return
	}

	httputil.JSON(w, http.StatusOK, StatusResponse{
		Enabled:                enabled,
		RecoveryCodesRemaining: remaining,
	})
}

// VerifyRequest represents the request body for MFA verification
type VerifyRequest struct {
	ChallengeToken string `json:"challenge_token"`
	Code           string `json:"code"`
}

// Verify handles POST /v1/auth/mfa/verify
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ChallengeToken == "" || req.Code == "" {
		httputil.Error(w, http.StatusBadRequest, "challenge_token and code are required")
		return
	}

	// Validate challenge token
	userID, err := h.mfaService.ValidateMFAChallenge(ctx, req.ChallengeToken)
	if err != nil {
		if err == domain.ErrMFAChallengeExpired {
			httputil.Error(w, http.StatusUnauthorized, "MFA challenge expired")
			return
		}
		h.logger.Error("failed to validate MFA challenge", "error", err)
		httputil.Error(w, http.StatusUnauthorized, "invalid challenge token")
		return
	}

	// Verify TOTP code or recovery code
	validTOTP, err := h.mfaService.VerifyTOTP(ctx, userID, req.Code)
	if err != nil && err != domain.ErrMFANotEnabled {
		h.logger.Error("failed to verify TOTP", "error", err)
	}

	validRecovery := false
	if !validTOTP {
		validRecovery, err = h.mfaService.VerifyRecoveryCode(ctx, userID, req.Code)
		if err != nil && err != domain.ErrInvalidRecoveryCode {
			h.logger.Error("failed to verify recovery code", "error", err)
		}
	}

	if !validTOTP && !validRecovery {
		httputil.Error(w, http.StatusUnauthorized, "invalid MFA code")
		return
	}

	// Consume challenge token
	if err := h.mfaService.ConsumeMFAChallenge(ctx, req.ChallengeToken); err != nil {
		h.logger.Error("failed to consume MFA challenge", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to complete MFA verification")
		return
	}

	// Issue session with MFA verified
	opts := auth.IssueSessionOpts{
		IP:          r.RemoteAddr,
		UserAgent:   r.UserAgent(),
		Request:     r,
		MFAVerified: true,
	}

	tokens, err := h.sessionService.IssueSession(ctx, userID, opts)
	if err != nil {
		h.logger.Error("failed to issue session", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	httputil.JSON(w, http.StatusOK, tokens)
}
