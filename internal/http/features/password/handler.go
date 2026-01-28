package password

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/notification"
)

// Alias for cleaner code
type tokenPair = domain.TokenPair

// Handler handles password authentication endpoints.
type Handler struct {
	logger                   *slog.Logger
	passwordService          *auth.PasswordService
	sessionService           *auth.SessionService
	verificationService      *auth.VerificationService
	emailService             *notification.EmailService
	tenantsRepo              *repository.TenantsRepository
	membershipsRepo          *repository.MembershipsRepository
	db                       *sql.DB
	cookieConfig             httputil.CookieConfig
	appBaseURL               string
	requireEmailVerification bool
}

// NewHandler creates a new password handler.
func NewHandler(
	logger *slog.Logger,
	passwordService *auth.PasswordService,
	sessionService *auth.SessionService,
	verificationService *auth.VerificationService,
	emailService *notification.EmailService,
	tenantsRepo *repository.TenantsRepository,
	membershipsRepo *repository.MembershipsRepository,
	appBaseURL string,
	requireEmailVerification bool,
) *Handler {
	return &Handler{
		logger:                   logger,
		passwordService:          passwordService,
		sessionService:           sessionService,
		verificationService:      verificationService,
		emailService:             emailService,
		tenantsRepo:              tenantsRepo,
		membershipsRepo:          membershipsRepo,
		cookieConfig:             httputil.DefaultCookieConfig(),
		appBaseURL:               appBaseURL,
		requireEmailVerification: requireEmailVerification,
	}
}

// RegisterRequest represents a registration request.
type RegisterRequest struct {
	Email    string  `json:"email"`
	Username *string `json:"username,omitempty"`
	Password string  `json:"password"`
	Name     string  `json:"name"`
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Identifier string     `json:"identifier,omitempty"` // New: email or username
	Email      string     `json:"email,omitempty"`      // Legacy: backward compatibility
	Password   string     `json:"password"`
	TenantID   *uuid.UUID `json:"tenant_id,omitempty"` // Optional: tenant selection
}

// TokenResponse represents a token response (for mobile clients).
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// TenantSelectionResponse represents a tenant selection required response.
type TenantSelectionResponse struct {
	Error   string         `json:"error"`
	Message string         `json:"message"`
	Tenants []TenantOption `json:"tenants"`
}

// TenantOption represents a tenant option for selection.
type TenantOption struct {
	TenantID     string `json:"tenant_id"`
	TenantName   string `json:"tenant_name"`
	TenantSlug   string `json:"tenant_slug"`
	MembershipID string `json:"membership_id"`
}

// Register handles user registration.
// POST /v1/auth/password/register
//
// For web clients: Sets HttpOnly cookies, returns minimal response.
// For mobile clients (X-Client-Type: mobile): Returns tokens in response body.
//
// Registration now creates:
// 1. User account
// 2. Personal tenant (auto-generated slug from email)
// 3. Active membership
// 4. Session with tenant context
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

	// Normalize username: empty string -> nil
	var username *string
	if req.Username != nil && *req.Username != "" {
		username = req.Username
	}

	// Register user (creates user + password credential)
	user, err := h.passwordService.Register(r.Context(), req.Email, req.Password, req.Name, username)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			httputil.Error(w, http.StatusConflict, "user already exists")
			return
		}
		if errors.Is(err, domain.ErrUsernameAlreadyExists) {
			httputil.Error(w, http.StatusConflict, "username already taken")
			return
		}
		if errors.Is(err, domain.ErrInvalidUsername) {
			httputil.Error(w, http.StatusBadRequest, "invalid username format: must be 3-30 characters, alphanumeric/underscore/hyphen, start with alphanumeric")
			return
		}
		h.logger.Error("registration failed", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "registration failed")
		return
	}

	// Create personal tenant
	tenantID := uuid.New()
	membershipID := uuid.New()
	tenantSlug := generateTenantSlug(req.Email)
	tenantName := req.Name + "'s Workspace"
	if req.Name == "" {
		tenantName = "Personal Workspace"
	}

	now := time.Now()
	tenant := &domain.Tenant{
		ID:        tenantID,
		Name:      tenantName,
		Slug:      tenantSlug,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.tenantsRepo.Create(r.Context(), tenant); err != nil {
		h.logger.Error("failed to create tenant", "error", err, "user_id", user.ID)
		httputil.Error(w, http.StatusInternalServerError, "registration failed")
		return
	}

	// Create active membership
	membership := &domain.Membership{
		ID:        membershipID,
		TenantID:  tenantID,
		UserID:    user.ID,
		Status:    domain.MembershipStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.membershipsRepo.Create(r.Context(), membership); err != nil {
		h.logger.Error("failed to create membership", "error", err, "user_id", user.ID, "tenant_id", tenantID)
		httputil.Error(w, http.StatusInternalServerError, "registration failed")
		return
	}

	// Issue session with tenant context
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), user.ID, tenantID, membershipID, opts)
	if err != nil {
		h.logger.Error("failed to issue session", "error", err, "user_id", user.ID)
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

	h.logger.Info("user registered", "user_id", user.ID, "tenant_id", tenantID)
	h.writeTokenResponse(w, r, tokens, http.StatusCreated)
}

// Login handles user login.
// POST /v1/auth/password/login
//
// Login flow:
// 1. Authenticate user (email/username + password)
// 2. Fetch active memberships for user
// 3. If no memberships -> error (user not in any tenant)
// 4. If tenant_id provided:
//    - Verify user has active membership in that tenant
//    - Use that tenant for session
// 5. If tenant_id NOT provided:
//    - If exactly 1 membership -> auto-select that tenant
//    - If multiple memberships -> return tenant selection required error
// 6. Issue session with tenant_id + membership_id
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Support both 'identifier' (new) and 'email' (legacy) fields
	identifier := req.Identifier
	if identifier == "" {
		identifier = req.Email
	}

	if identifier == "" || req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "email/username and password are required")
		return
	}

	// Authenticate user
	userID, err := h.passwordService.Authenticate(r.Context(), identifier, req.Password)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			httputil.Error(w, http.StatusUnauthorized, "invalid email/username or password")
			return
		}
		if errors.Is(err, domain.ErrAccountLocked) {
			httputil.Error(w, http.StatusForbidden, "account temporarily locked due to too many failed login attempts. Please try again in 15 minutes.")
			return
		}
		h.logger.Error("authentication failed", "error", err)
		httputil.Error(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	// Check if email is verified
	user, err := h.passwordService.GetUserByID(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get user", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// Check email verification if enforced
	if h.requireEmailVerification && !user.EmailVerified {
		httputil.Error(w, http.StatusForbidden, "email verification required. Please check your email for verification link")
		return
	}

	// Fetch active memberships
	memberships, err := h.membershipsRepo.GetActiveMembershipsWithTenants(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to get memberships", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to get memberships")
		return
	}

	if len(memberships) == 0 {
		httputil.Error(w, http.StatusForbidden, "no tenant access")
		return
	}

	var selectedMembership *repository.MembershipWithTenant

	// Handle tenant selection
	if req.TenantID != nil {
		// Validate tenant_id
		for _, m := range memberships {
			if m.Membership.TenantID == *req.TenantID && m.Membership.IsActive() {
				selectedMembership = m
				break
			}
		}
		if selectedMembership == nil {
			httputil.Error(w, http.StatusForbidden, "invalid tenant access")
			return
		}
	} else {
		// Auto-select if only one
		if len(memberships) == 1 {
			selectedMembership = memberships[0]
		} else {
			// Multiple tenants - return tenant selection required
			var tenantOptions []TenantOption
			for _, m := range memberships {
				tenantOptions = append(tenantOptions, TenantOption{
					TenantID:     m.Tenant.ID.String(),
					TenantName:   m.Tenant.Name,
					TenantSlug:   m.Tenant.Slug,
					MembershipID: m.Membership.ID.String(),
				})
			}

			httputil.JSON(w, http.StatusConflict, TenantSelectionResponse{
				Error:   "tenant_selection_required",
				Message: "User has access to multiple tenants",
				Tenants: tenantOptions,
			})
			return
		}
	}

	// Issue session with tenant context
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), userID,
		selectedMembership.Membership.TenantID,
		selectedMembership.Membership.ID,
		opts)
	if err != nil {
		h.logger.Error("failed to issue session", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	h.logger.Info("user logged in", "user_id", userID, "tenant_id", selectedMembership.Membership.TenantID)
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
