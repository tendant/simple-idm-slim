package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestSizeLimit(t *testing.T) {
	maxSize := int64(100) // 100 bytes

	handler := RequestSizeLimit(maxSize)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))

	tests := []struct {
		name       string
		bodySize   int
		wantStatus int
	}{
		{
			name:       "small body - accepted",
			bodySize:   50,
			wantStatus: http.StatusOK,
		},
		{
			name:       "exact limit - accepted",
			bodySize:   100,
			wantStatus: http.StatusOK,
		},
		{
			name:       "too large - rejected",
			bodySize:   150,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), tt.bodySize)
			req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
