package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tendant/simple-idm-slim/internal/config"
)

func TestSecurityHeaders(t *testing.T) {
	cfg := config.SecurityHeadersConfig{
		Enabled:            true,
		CSP:                "default-src 'self'",
		HSTSMaxAge:         31536000,
		FrameOptions:       "DENY",
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",
		ReferrerPolicy:     "strict-origin-when-cross-origin",
		PermissionsPolicy:  "geolocation=()",
	}

	handler := SecurityHeaders(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Check headers
	if got := w.Header().Get("Content-Security-Policy"); got != cfg.CSP {
		t.Errorf("CSP header = %v, want %v", got, cfg.CSP)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS header = %v, want max-age=31536000; includeSubDomains", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != cfg.FrameOptions {
		t.Errorf("Frame Options header = %v, want %v", got, cfg.FrameOptions)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != cfg.ContentTypeOptions {
		t.Errorf("Content Type Options header = %v, want %v", got, cfg.ContentTypeOptions)
	}
	if got := w.Header().Get("X-XSS-Protection"); got != cfg.XSSProtection {
		t.Errorf("XSS Protection header = %v, want %v", got, cfg.XSSProtection)
	}
	if got := w.Header().Get("Referrer-Policy"); got != cfg.ReferrerPolicy {
		t.Errorf("Referrer Policy header = %v, want %v", got, cfg.ReferrerPolicy)
	}
	if got := w.Header().Get("Permissions-Policy"); got != cfg.PermissionsPolicy {
		t.Errorf("Permissions Policy header = %v, want %v", got, cfg.PermissionsPolicy)
	}
}

func TestSecurityHeaders_Disabled(t *testing.T) {
	cfg := config.SecurityHeadersConfig{
		Enabled: false,
		CSP:     "default-src 'self'",
	}

	handler := SecurityHeaders(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// No headers should be set
	if got := w.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP header should not be set when disabled, got %v", got)
	}
}

func TestSecurityHeaders_EmptyValues(t *testing.T) {
	cfg := config.SecurityHeadersConfig{
		Enabled:       true,
		CSP:           "",
		HSTSMaxAge:    0,
		FrameOptions:  "",
	}

	handler := SecurityHeaders(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Empty values should not set headers
	if got := w.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP header should not be set when empty, got %v", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS header should not be set when max age is 0, got %v", got)
	}
}
