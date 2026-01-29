package middleware

import (
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// RequestSizeLimit creates middleware that limits the maximum request body size.
func RequestSizeLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Limit request body size to prevent memory exhaustion
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

			next.ServeHTTP(w, r)
		})
	}
}

// handleMaxBytesError checks if the error is from MaxBytesReader and returns appropriate response.
func handleMaxBytesError(w http.ResponseWriter, err error) bool {
	if err != nil && err.Error() == "http: request body too large" {
		httputil.Error(w, http.StatusRequestEntityTooLarge, "request body too large")
		return true
	}
	return false
}
