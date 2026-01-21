package pages

import (
	"net/http"
)

// RegisterRoutes registers authentication page routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/register", h.Register)
	mux.HandleFunc("GET /auth/login", h.Login)
	mux.HandleFunc("GET /auth/verify-email", h.VerifyEmail)
	mux.HandleFunc("GET /auth/reset-password", h.ResetPassword)
	mux.HandleFunc("GET /auth/reset-password/confirm", h.ResetPasswordConfirm)
}
