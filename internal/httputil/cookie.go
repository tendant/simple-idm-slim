package httputil

import (
	"net/http"
	"time"
)

// CookieConfig holds cookie configuration.
type CookieConfig struct {
	Domain   string
	Path     string
	Secure   bool // Set to true in production (HTTPS)
	SameSite http.SameSite
}

// DefaultCookieConfig returns default cookie configuration.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Path:     "/",
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
	}
}

// SetAuthCookies sets HttpOnly cookies for access and refresh tokens.
func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, accessTTL, refreshTTL time.Duration, cfg CookieConfig) {
	// Access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   int(accessTTL.Seconds()),
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})

	// Refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   int(refreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})
}

// ClearAuthCookies clears auth cookies.
func ClearAuthCookies(w http.ResponseWriter, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})
}

// GetRefreshTokenFromCookie extracts refresh token from cookie.
func GetRefreshTokenFromCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

// GetAccessTokenFromCookie extracts access token from cookie.
func GetAccessTokenFromCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

// IsMobileClient checks if request is from a mobile client.
// Mobile clients should set header: X-Client-Type: mobile
func IsMobileClient(r *http.Request) bool {
	return r.Header.Get("X-Client-Type") == "mobile"
}
