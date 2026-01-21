package pages

import (
	"html/template"
	"net/http"
	"path/filepath"
)

// Handler handles authentication page rendering.
type Handler struct {
	templates *template.Template
}

// NewHandler creates a new pages handler.
func NewHandler(templatesDir string) (*Handler, error) {
	// Parse all templates
	tmpl, err := template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, err
	}

	return &Handler{
		templates: tmpl,
	}, nil
}

// PageData holds data for template rendering.
type PageData struct {
	Title string
}

// Register renders the registration page.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	h.render(w, "register.html", PageData{Title: "Register"})
}

// Login renders the login page.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	h.render(w, "login.html", PageData{Title: "Sign In"})
}

// VerifyEmail renders the email verification page.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	h.render(w, "verify-email.html", PageData{Title: "Verify Email"})
}

// ResetPassword renders the password reset request page.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	h.render(w, "reset-password.html", PageData{Title: "Reset Password"})
}

// ResetPasswordConfirm renders the password reset confirmation page.
func (h *Handler) ResetPasswordConfirm(w http.ResponseWriter, r *http.Request) {
	h.render(w, "reset-password-confirm.html", PageData{Title: "Set New Password"})
}

func (h *Handler) render(w http.ResponseWriter, tmpl string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, tmpl, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
