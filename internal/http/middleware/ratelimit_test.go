package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tendant/simple-idm-slim/internal/config"
)

func TestRateLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := RateLimitConfig{
		Requests: 2,
		Window:   time.Second,
		Logger:   logger,
	}

	handler := RateLimit(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// First request should succeed
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request: got status %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request should succeed
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Second request: got status %d, want %d", w2.Code, http.StatusOK)
	}

	// Third request should be rate limited
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "192.168.1.1:12345"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("Third request: got status %d, want %d", w3.Code, http.StatusTooManyRequests)
	}
}

func TestNoRateLimit(t *testing.T) {
	handler := NoRateLimit()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// All requests should succeed
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: got status %d, want %d", i, w.Code, http.StatusOK)
		}
	}
}

func TestCreateRateLimiters_Disabled(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled: false,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	limiters := CreateRateLimiters(cfg, logger)

	// All limiters should be no-op
	handler := limiters["auth"](http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: got status %d, want %d", i, w.Code, http.StatusOK)
		}
	}
}

func TestCreateRateLimiters_Enabled(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:              true,
		AuthRequestsPerMinute: 5,
		AuthWindowMinutes:    1,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	limiters := CreateRateLimiters(cfg, logger)

	if limiters["auth"] == nil {
		t.Error("auth limiter should not be nil")
	}
	if limiters["reset"] == nil {
		t.Error("reset limiter should not be nil")
	}
	if limiters["verify"] == nil {
		t.Error("verify limiter should not be nil")
	}
	if limiters["refresh"] == nil {
		t.Error("refresh limiter should not be nil")
	}
	if limiters["profile"] == nil {
		t.Error("profile limiter should not be nil")
	}
}
