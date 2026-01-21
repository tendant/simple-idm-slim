package email

import (
	"net/http"
)

// RegisterRoutes registers email verification routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware func(http.Handler) http.Handler) {
	mux.HandleFunc("POST /v1/auth/verify-email", h.VerifyEmail)
	mux.Handle("POST /v1/auth/resend-verification", authMiddleware(http.HandlerFunc(h.ResendVerificationEmail)))
}
