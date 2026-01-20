package session

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshRequest_Validation_Mobile(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "empty body",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "refresh_token is required",
		},
		{
			name:           "empty refresh_token",
			body:           `{"refresh_token": ""}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "refresh_token is required",
		},
		{
			name:           "invalid json",
			body:           `{invalid}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid request body",
		},
	}

	handler := &Handler{
		sessionService: nil,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Client-Type", "mobile") // Mobile client sends tokens in body
			rec := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Validation should have failed before reaching service")
				}
			}()

			handler.Refresh(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d", rec.Code, tt.expectedStatus)
			}

			var response map[string]string
			json.NewDecoder(rec.Body).Decode(&response)
			if response["error"] != tt.expectedError {
				t.Errorf("Error = %q, want %q", response["error"], tt.expectedError)
			}
		})
	}
}

func TestRefreshRequest_WebClient_NoCookie(t *testing.T) {
	handler := &Handler{
		sessionService: nil,
	}

	// Web client without cookie should get 401
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	rec := httptest.NewRecorder()

	handler.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var response map[string]string
	json.NewDecoder(rec.Body).Decode(&response)
	if response["error"] != "refresh token not found" {
		t.Errorf("Error = %q, want %q", response["error"], "refresh token not found")
	}
}

func TestLogoutRequest_Validation_Mobile(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "empty body",
			body:           `{}`,
			expectedStatus: http.StatusNoContent, // Logout succeeds even with empty token
			expectedError:  "",
		},
		{
			name:           "empty refresh_token",
			body:           `{"refresh_token": ""}`,
			expectedStatus: http.StatusNoContent,
			expectedError:  "",
		},
		{
			name:           "invalid json",
			body:           `{invalid}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid request body",
		},
	}

	handler := &Handler{
		sessionService: nil,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Client-Type", "mobile") // Mobile client sends tokens in body
			rec := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Validation should have failed before reaching service")
				}
			}()

			handler.Logout(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d", rec.Code, tt.expectedStatus)
			}

			if tt.expectedError != "" {
				var response map[string]string
				json.NewDecoder(rec.Body).Decode(&response)
				if response["error"] != tt.expectedError {
					t.Errorf("Error = %q, want %q", response["error"], tt.expectedError)
				}
			}
		})
	}
}

func TestLogoutRequest_WebClient_NoCookie(t *testing.T) {
	handler := &Handler{
		sessionService: nil,
	}

	// Web client without cookie should still succeed (clears cookies)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	rec := httptest.NewRecorder()

	handler.Logout(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestTokenResponse_JSON(t *testing.T) {
	response := TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal TokenResponse: %v", err)
	}

	var decoded TokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TokenResponse: %v", err)
	}

	if decoded != response {
		t.Errorf("TokenResponse mismatch: got %+v, want %+v", decoded, response)
	}
}
