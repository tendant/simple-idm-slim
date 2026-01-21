package me

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/notification"
	"github.com/tendant/simple-idm-slim/internal/repository"
)

// Handler handles user profile endpoints.
type Handler struct {
	logger              *slog.Logger
	users               *repository.UsersRepository
	verificationService *auth.VerificationService
	emailService        *notification.EmailService
	appBaseURL          string
}

// NewHandler creates a new me handler.
func NewHandler(
	logger *slog.Logger,
	users *repository.UsersRepository,
	verificationService *auth.VerificationService,
	emailService *notification.EmailService,
	appBaseURL string,
) *Handler {
	return &Handler{
		logger:              logger,
		users:               users,
		verificationService: verificationService,
		emailService:        emailService,
		appBaseURL:          appBaseURL,
	}
}

// UserResponse represents the user profile response.
type UserResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          *string `json:"name,omitempty"`
}

// UpdateRequest represents a profile update request.
type UpdateRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

// GetMe returns the current user's profile.
// GET /v1/me
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, "user not found")
		return
	}

	httputil.JSON(w, http.StatusOK, UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
	})
}

// UpdateMe updates the current user's profile.
// PATCH /v1/me
// When email is changed, it must be verified before taking effect.
func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, "user not found")
		return
	}

	// Track if we need to send verification email
	emailChanged := false
	oldEmail := user.Email

	// Update fields if provided
	if req.Name != nil {
		user.Name = req.Name
	}

	if req.Email != nil && *req.Email != "" && *req.Email != user.Email {
		// Check if email is already taken
		existingUser, err := h.users.GetByEmail(r.Context(), *req.Email)
		if err == nil && existingUser.ID != user.ID {
			httputil.Error(w, http.StatusConflict, "email already in use")
			return
		}

		// Update email and mark as unverified
		user.Email = *req.Email
		user.EmailVerified = false
		emailChanged = true
	}

	if err := h.users.Update(r.Context(), user); err != nil {
		if err == domain.ErrUserNotFound {
			httputil.Error(w, http.StatusNotFound, "user not found")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "failed to update profile")
		return
	}

	// Send verification email if email was changed
	if emailChanged && h.emailService != nil && h.verificationService != nil {
		opts := auth.CreateVerificationTokenOpts{
			IP:        r.RemoteAddr,
			UserAgent: r.UserAgent(),
		}
		token, err := h.verificationService.CreateEmailVerificationToken(r.Context(), userID, opts)
		if err != nil {
			h.logger.Error("failed to create verification token", "error", err, "user_id", userID)
		} else {
			verifyURL := fmt.Sprintf("%s/auth/verify-email?token=%s", h.appBaseURL, token)
			if err := h.emailService.SendVerificationEmail(user.Email, verifyURL); err != nil {
				h.logger.Error("failed to send verification email", "error", err, "user_id", userID)
			} else {
				h.logger.Info("email changed, verification sent", "user_id", userID, "old_email", oldEmail, "new_email", user.Email)
			}
		}
	}

	response := UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
	}

	// Add message if email was changed
	if emailChanged {
		httputil.JSON(w, http.StatusOK, map[string]interface{}{
			"user":    response,
			"message": "Email updated. Please check your new email address for a verification link.",
		})
		return
	}

	httputil.JSON(w, http.StatusOK, response)
}
