package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// SessionFingerprint represents a session's device fingerprint.
type SessionFingerprint struct {
	IPAddress string
	UserAgent string
	Hash      string
}

// GenerateFingerprint creates a fingerprint from request metadata.
func GenerateFingerprint(r *http.Request) *SessionFingerprint {
	ip := getClientIP(r)
	ua := r.UserAgent()

	// Create hash of IP + User-Agent
	hash := hashFingerprint(ip, ua)

	return &SessionFingerprint{
		IPAddress: ip,
		UserAgent: ua,
		Hash:      hash,
	}
}

// Validate checks if the current request matches the stored fingerprint.
func (f *SessionFingerprint) Validate(r *http.Request) bool {
	current := GenerateFingerprint(r)
	return f.Hash == current.Hash
}

// DetectReuse checks for suspicious IP or User-Agent changes.
func (f *SessionFingerprint) DetectReuse(r *http.Request) (bool, string) {
	current := GenerateFingerprint(r)

	if f.IPAddress != current.IPAddress {
		return true, fmt.Sprintf("IP address changed from %s to %s", f.IPAddress, current.IPAddress)
	}

	if f.UserAgent != current.UserAgent {
		return true, fmt.Sprintf("User-Agent changed from %s to %s", f.UserAgent, current.UserAgent)
	}

	return false, ""
}

// hashFingerprint creates a SHA-256 hash of the fingerprint components.
func hashFingerprint(ip, userAgent string) string {
	data := fmt.Sprintf("%s|%s", ip, userAgent)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// getClientIP extracts the client IP address from the request.
// Checks X-Forwarded-For and X-Real-IP headers before falling back to RemoteAddr.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP (client IP)
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	// RemoteAddr format is "IP:port", so we need to strip the port
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}

	return addr
}
