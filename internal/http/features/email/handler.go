package email

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/notification"
)

type Handler struct {
	logger              *slog.Logger
	verificationService *auth.VerificationService
	emailService        *notification.EmailService
	sessionService      *auth.SessionService
	appBaseURL          string
}

func NewHandler(
	logger *slog.Logger,
	verificationService *auth.VerificationService,
	emailService *notification.EmailService,
	sessionService *auth.SessionService,
	appBaseURL string,
) *Handler {
	return &Handler{
		logger:              logger,
		verificationService: verificationService,
		emailService:        emailService,
		sessionService:      sessionService,
		appBaseURL:          appBaseURL,
	}
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

// VerifyEmail handles email verification.
// POST /v1/auth/verify-email
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Support both query parameter and JSON body
	token := r.URL.Query().Get("token")
	if token == "" {
		var req VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.Error(w, http.StatusBadRequest, "invalid request")
			return
		}
		token = req.Token
	}

	if token == "" {
		httputil.Error(w, http.StatusBadRequest, "token is required")
		return
	}

	userID, err := h.verificationService.VerifyEmailToken(r.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrVerificationTokenInvalid):
			httputil.Error(w, http.StatusBadRequest, "invalid verification token")
		case errors.Is(err, domain.ErrVerificationTokenExpired):
			httputil.Error(w, http.StatusBadRequest, "verification token expired")
		case errors.Is(err, domain.ErrVerificationTokenConsumed):
			httputil.Error(w, http.StatusBadRequest, "verification token already used")
		default:
			h.logger.Error("failed to verify email", "error", err)
			httputil.Error(w, http.StatusInternalServerError, "verification failed")
		}
		return
	}

	h.logger.Info("email verified", "user_id", userID)

	httputil.JSON(w, http.StatusOK, MessageResponse{
		Message: "Email verified successfully",
	})
}

// ResendVerificationEmail resends the verification email.
// POST /v1/auth/resend-verification
// Requires authentication.
func (h *Handler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	claims, ok := middleware.GetClaims(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if claims.EmailVerified {
		httputil.Error(w, http.StatusBadRequest, "email already verified")
		return
	}

	if h.emailService == nil {
		httputil.Error(w, http.StatusServiceUnavailable, "email service not configured")
		return
	}

	opts := auth.CreateVerificationTokenOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	token, err := h.verificationService.CreateEmailVerificationToken(r.Context(), userID, opts)
	if err != nil {
		h.logger.Error("failed to create verification token", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to create verification token")
		return
	}

	verifyURL := fmt.Sprintf("%s/auth/verify-email?token=%s", h.appBaseURL, token)
	if err := h.emailService.SendVerificationEmail(claims.Email, verifyURL); err != nil {
		h.logger.Error("failed to send verification email", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to send verification email")
		return
	}

	h.logger.Info("verification email resent", "user_id", userID)

	httputil.JSON(w, http.StatusOK, MessageResponse{
		Message: "Verification email sent",
	})
}
