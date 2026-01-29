package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateFingerprint(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	fp := GenerateFingerprint(req)

	if fp.IPAddress == "" {
		t.Error("IPAddress should not be empty")
	}
	if fp.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %s, want Mozilla/5.0", fp.UserAgent)
	}
	if fp.Hash == "" {
		t.Error("Hash should not be empty")
	}
}

func TestSessionFingerprint_Validate(t *testing.T) {
	// Create initial request
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	req1.Header.Set("User-Agent", "Mozilla/5.0")

	fp := GenerateFingerprint(req1)

	tests := []struct {
		name       string
		setupReq   func() *http.Request
		wantValid  bool
	}{
		{
			name: "same fingerprint",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
				return req
			},
			wantValid: true,
		},
		{
			name: "different IP",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.2:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
				return req
			},
			wantValid: false,
		},
		{
			name: "different User-Agent",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				req.Header.Set("User-Agent", "Chrome/1.0")
				return req
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			valid := fp.Validate(req)
			if valid != tt.wantValid {
				t.Errorf("Validate() = %v, want %v", valid, tt.wantValid)
			}
		})
	}
}

func TestSessionFingerprint_DetectReuse(t *testing.T) {
	// Create initial request
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	req1.Header.Set("User-Agent", "Mozilla/5.0")

	fp := GenerateFingerprint(req1)

	tests := []struct {
		name       string
		setupReq   func() *http.Request
		wantReused bool
	}{
		{
			name: "no reuse - same fingerprint",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
				return req
			},
			wantReused: false,
		},
		{
			name: "reuse detected - different IP",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "10.0.0.1:12345"
				req.Header.Set("User-Agent", "Mozilla/5.0")
				return req
			},
			wantReused: true,
		},
		{
			name: "reuse detected - different UA",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				req.Header.Set("User-Agent", "Chrome/1.0")
				return req
			},
			wantReused: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			reused, _ := fp.DetectReuse(req)
			if reused != tt.wantReused {
				t.Errorf("DetectReuse() reused = %v, want %v", reused, tt.wantReused)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		setupReq func() *http.Request
		wantIP   string
	}{
		{
			name: "X-Forwarded-For header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			wantIP: "203.0.113.1",
		},
		{
			name: "X-Real-IP header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Real-IP", "203.0.113.1")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			wantIP: "203.0.113.1",
		},
		{
			name: "RemoteAddr only",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			wantIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			got := getClientIP(req)
			if got != tt.wantIP {
				t.Errorf("getClientIP() = %v, want %v", got, tt.wantIP)
			}
		})
	}
}
