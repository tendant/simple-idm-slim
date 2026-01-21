package password

import (
	"net/http"
)

// RegisterRoutes registers password authentication routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/password/register", h.Register)
	mux.HandleFunc("POST /v1/auth/password/login", h.Login)
	mux.HandleFunc("POST /v1/auth/password/reset-request", h.RequestPasswordReset)
	mux.HandleFunc("POST /v1/auth/password/reset", h.ResetPassword)
}
