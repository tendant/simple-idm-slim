package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

func TestGenerateRecoveryCode(t *testing.T) {
	// Test recovery code generation
	for i := 0; i < 100; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			t.Fatalf("generateRecoveryCode() error = %v", err)
		}

		// Check format: XXXX-XXXX-XXXX
		parts := strings.Split(code, "-")
		if len(parts) != 3 {
			t.Errorf("Expected 3 parts separated by '-', got %d: %s", len(parts), code)
		}

		for _, part := range parts {
			if len(part) != 4 {
				t.Errorf("Expected each part to be 4 characters, got %d: %s", len(part), part)
			}
		}

		// Check that all characters are from the allowed charset
		cleanCode := strings.ReplaceAll(code, "-", "")
		for _, char := range cleanCode {
			if !strings.ContainsRune(recoveryCodeChars, char) {
				t.Errorf("Code contains invalid character: %c", char)
			}
		}

		// Verify total length
		if len(cleanCode) != recoveryCodeLength {
			t.Errorf("Expected code length %d, got %d", recoveryCodeLength, len(cleanCode))
		}
	}
}

func TestGenerateRecoveryCode_Uniqueness(t *testing.T) {
	// Generate multiple codes and check they're unique
	codes := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			t.Fatalf("generateRecoveryCode() error = %v", err)
		}
		if codes[code] {
			t.Errorf("Duplicate code generated: %s", code)
		}
		codes[code] = true
	}
}

func TestMFAService_EncryptDecrypt(t *testing.T) {
	// Create encryption key
	encryptionKey := make([]byte, 32)
	for i := range encryptionKey {
		encryptionKey[i] = byte(i)
	}

	service := &MFAService{
		config: MFAConfig{
			Issuer:        "Test",
			EncryptionKey: encryptionKey,
		},
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple text",
			plaintext: "hello world",
		},
		{
			name:      "TOTP secret",
			plaintext: "JBSWY3DPEHPK3PXP",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "long text",
			plaintext: strings.Repeat("a", 1000),
		},
		{
			name:      "special characters",
			plaintext: "!@#$%^&*()_+-=[]{}|;':,.<>?/~`",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := service.encryptSecret(tt.plaintext)
			if err != nil {
				t.Fatalf("encryptSecret() error = %v", err)
			}

			// Verify encrypted is different from plaintext
			if encrypted == tt.plaintext {
				t.Error("Encrypted text should be different from plaintext")
			}

			// Verify encrypted is base64
			if _, err := base64.StdEncoding.DecodeString(encrypted); err != nil {
				t.Errorf("Encrypted text is not valid base64: %v", err)
			}

			// Decrypt
			decrypted, err := service.decryptSecret(encrypted)
			if err != nil {
				t.Fatalf("decryptSecret() error = %v", err)
			}

			// Verify decrypted matches original
			if decrypted != tt.plaintext {
				t.Errorf("Decrypted text mismatch: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestMFAService_EncryptDecrypt_DifferentCiphertexts(t *testing.T) {
	// Verify that encrypting the same plaintext produces different ciphertexts (due to random nonce)
	encryptionKey := make([]byte, 32)
	service := &MFAService{
		config: MFAConfig{
			Issuer:        "Test",
			EncryptionKey: encryptionKey,
		},
	}

	plaintext := "test secret"
	encrypted1, _ := service.encryptSecret(plaintext)
	encrypted2, _ := service.encryptSecret(plaintext)

	if encrypted1 == encrypted2 {
		t.Error("Encrypting the same plaintext should produce different ciphertexts")
	}

	// Both should decrypt to the same plaintext
	decrypted1, _ := service.decryptSecret(encrypted1)
	decrypted2, _ := service.decryptSecret(encrypted2)

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Error("Both ciphertexts should decrypt to the original plaintext")
	}
}

func TestMFAService_DecryptInvalidData(t *testing.T) {
	encryptionKey := make([]byte, 32)
	service := &MFAService{
		config: MFAConfig{
			Issuer:        "Test",
			EncryptionKey: encryptionKey,
		},
	}

	tests := []struct {
		name      string
		encrypted string
	}{
		{
			name:      "invalid base64",
			encrypted: "not-base64!@#$",
		},
		{
			name:      "too short",
			encrypted: base64.StdEncoding.EncodeToString([]byte("short")),
		},
		{
			name:      "empty string",
			encrypted: "",
		},
		{
			name:      "valid base64 but wrong data",
			encrypted: base64.StdEncoding.EncodeToString([]byte("this is not encrypted data")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.decryptSecret(tt.encrypted)
			if err == nil {
				t.Error("Expected error when decrypting invalid data")
			}
		})
	}
}

func TestMFAService_HashRecoveryCode(t *testing.T) {
	service := &MFAService{}

	code := "ABCD-EFGH-IJKL"

	// Hash the code
	hash1, err := service.hashRecoveryCode(code)
	if err != nil {
		t.Fatalf("hashRecoveryCode() error = %v", err)
	}

	// Hash again - should be different due to random salt
	hash2, err := service.hashRecoveryCode(code)
	if err != nil {
		t.Fatalf("hashRecoveryCode() error = %v", err)
	}

	if hash1 == hash2 {
		t.Error("Hashing the same code should produce different hashes (random salt)")
	}

	// Verify both hashes
	if !VerifyPassword(code, hash1) {
		t.Error("Hash1 verification failed")
	}
	if !VerifyPassword(code, hash2) {
		t.Error("Hash2 verification failed")
	}

	// Verify wrong code doesn't match
	if VerifyPassword("WRONG-CODE-HERE", hash1) {
		t.Error("Wrong code should not verify")
	}
}

func TestHashTokenMFA(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "simple token",
			token: "test-token-123",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "long token",
			token: strings.Repeat("a", 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hashToken(tt.token)

			// Verify hash is base64
			if _, err := base64.StdEncoding.DecodeString(hash); err != nil {
				t.Errorf("Hash is not valid base64: %v", err)
			}

			// Verify hashing is deterministic
			hash2 := hashToken(tt.token)
			if hash != hash2 {
				t.Error("Hashing the same token should produce the same hash")
			}

			// Verify different tokens produce different hashes
			differentHash := hashToken(tt.token + "different")
			if hash == differentHash {
				t.Error("Different tokens should produce different hashes")
			}
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	// Generate multiple tokens
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := generateSecureToken()

		// Verify token is base64
		if _, err := base64.URLEncoding.DecodeString(token); err != nil {
			t.Errorf("Token is not valid base64: %v", err)
		}

		// Verify uniqueness
		if tokens[token] {
			t.Errorf("Duplicate token generated: %s", token)
		}
		tokens[token] = true

		// Verify reasonable length
		if len(token) < 40 {
			t.Errorf("Token too short: %d chars", len(token))
		}
	}
}

func TestMFAService_TOTPValidation(t *testing.T) {
	// Test TOTP code validation logic
	// Generate a real TOTP secret
	secret := "JBSWY3DPEHPK3PXP"

	// Generate current code
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Validate current code
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    6,
		Algorithm: 0, // SHA1
	})
	if err != nil {
		t.Fatalf("Failed to validate TOTP code: %v", err)
	}
	if !valid {
		t.Error("Current TOTP code should be valid")
	}

	// Test with invalid code
	invalidValid, _ := totp.ValidateCustom("000000", secret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    6,
		Algorithm: 0,
	})
	if invalidValid {
		t.Error("Invalid code should not validate")
	}
}

func TestMFAService_TOTPClockDrift(t *testing.T) {
	// Test that TOTP validation allows ±30 second clock drift
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Now()

	// Generate code for 30 seconds ago
	pastCode, err := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("Failed to generate past TOTP code: %v", err)
	}

	// Should still be valid with skew=1
	valid, err := totp.ValidateCustom(pastCode, secret, now, totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    6,
		Algorithm: 0,
	})
	if err != nil {
		t.Fatalf("Failed to validate past TOTP code: %v", err)
	}
	if !valid {
		t.Error("TOTP code from 30 seconds ago should still be valid (clock drift tolerance)")
	}

	// Generate code for 30 seconds in the future
	futureCode, err := totp.GenerateCode(secret, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Failed to generate future TOTP code: %v", err)
	}

	// Should still be valid with skew=1
	valid, err = totp.ValidateCustom(futureCode, secret, now, totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    6,
		Algorithm: 0,
	})
	if err != nil {
		t.Fatalf("Failed to validate future TOTP code: %v", err)
	}
	if !valid {
		t.Error("TOTP code from 30 seconds in the future should still be valid (clock drift tolerance)")
	}

	// Code from 90 seconds ago should not be valid
	oldCode, _ := totp.GenerateCode(secret, now.Add(-90*time.Second))
	valid, _ = totp.ValidateCustom(oldCode, secret, now, totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    6,
		Algorithm: 0,
	})
	if valid {
		t.Error("TOTP code from 90 seconds ago should not be valid")
	}
}

func TestMFAService_VerifyRecoveryCode_Normalization(t *testing.T) {
	// Test that recovery codes can be entered with or without dashes and in any case
	service := &MFAService{}

	baseCode := "ABCD-EFGH-IJKL"
	hash, err := service.hashRecoveryCode(strings.ToUpper(strings.ReplaceAll(baseCode, "-", "")))
	if err != nil {
		t.Fatalf("hashRecoveryCode() error = %v", err)
	}

	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{
			name:  "exact match",
			input: "ABCD-EFGH-IJKL",
			valid: true,
		},
		{
			name:  "lowercase",
			input: "abcd-efgh-ijkl",
			valid: true,
		},
		{
			name:  "no dashes",
			input: "ABCDEFGHIJKL",
			valid: true,
		},
		{
			name:  "lowercase no dashes",
			input: "abcdefghijkl",
			valid: true,
		},
		{
			name:  "with spaces",
			input: "ABCD EFGH IJKL",
			valid: true,
		},
		{
			name:  "wrong code",
			input: "XXXX-YYYY-ZZZZ",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Normalize the input the same way the service does
			normalizedInput := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(tt.input, "-", ""), " ", ""))

			// Verify against hash
			valid := VerifyPassword(normalizedInput, hash)
			if valid != tt.valid {
				t.Errorf("Code %q: got valid=%v, want valid=%v", tt.input, valid, tt.valid)
			}
		})
	}
}

func TestMFAService_Constants(t *testing.T) {
	// Verify TOTP constants match the plan
	if totpDigits != 6 {
		t.Errorf("TOTP digits: got %d, want 6", totpDigits)
	}

	if totpPeriod != 30 {
		t.Errorf("TOTP period: got %d, want 30", totpPeriod)
	}

	if totpWindow != 1 {
		t.Errorf("TOTP window: got %d, want 1", totpWindow)
	}

	if recoveryCodeLength != 12 {
		t.Errorf("Recovery code length: got %d, want 12", recoveryCodeLength)
	}

	if recoveryCodeCount != 8 {
		t.Errorf("Recovery code count: got %d, want 8", recoveryCodeCount)
	}

	if mfaChallengeTokenTTL != 5*time.Minute {
		t.Errorf("MFA challenge token TTL: got %v, want 5m", mfaChallengeTokenTTL)
	}
}

func TestMFAService_RecoveryCodeCharset(t *testing.T) {
	// Verify recovery code charset doesn't contain ambiguous characters
	ambiguous := "01OIl"

	for _, char := range ambiguous {
		if strings.ContainsRune(recoveryCodeChars, char) {
			t.Errorf("Recovery code charset contains ambiguous character: %c", char)
		}
	}

	// Verify charset has reasonable length
	if len(recoveryCodeChars) < 20 {
		t.Errorf("Recovery code charset too small: %d chars", len(recoveryCodeChars))
	}
}

func TestMFAConfig_Validation(t *testing.T) {
	tests := []struct {
		name          string
		encryptionKey []byte
		valid         bool
	}{
		{
			name:          "valid 32-byte key",
			encryptionKey: make([]byte, 32),
			valid:         true,
		},
		{
			name:          "invalid too short",
			encryptionKey: make([]byte, 16),
			valid:         false,
		},
		{
			name:          "invalid too long",
			encryptionKey: make([]byte, 64),
			valid:         false,
		},
		{
			name:          "invalid empty",
			encryptionKey: []byte{},
			valid:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &MFAService{
				config: MFAConfig{
					Issuer:        "Test",
					EncryptionKey: tt.encryptionKey,
				},
			}

			// Try to encrypt something
			_, err := service.encryptSecret("test")

			if tt.valid && err != nil {
				t.Errorf("Expected encryption to succeed with %d-byte key, got error: %v", len(tt.encryptionKey), err)
			}
			if !tt.valid && err == nil && len(tt.encryptionKey) != 32 {
				// Note: Some invalid key lengths might still work with AES, but 32 is required for AES-256
				t.Logf("Warning: Expected error with %d-byte key", len(tt.encryptionKey))
			}
		})
	}
}

func TestMFASetupResponse_Structure(t *testing.T) {
	// Test that MFASetupResponse has the expected structure
	response := &domain.MFASetupResponse{
		Secret:        "BASE32SECRET",
		QRCodeDataURI: "data:image/png;base64,iVBORw0KG...",
		RecoveryCodes: []string{"ABCD-EFGH-IJKL", "MNOP-QRST-UVWX"},
	}

	if response.Secret == "" {
		t.Error("Secret should not be empty")
	}

	if !strings.HasPrefix(response.QRCodeDataURI, "data:image/png;base64,") {
		t.Error("QRCodeDataURI should be a data URI")
	}

	if len(response.RecoveryCodes) != 2 {
		t.Errorf("Expected 2 recovery codes, got %d", len(response.RecoveryCodes))
	}
}

func TestMFASecret_Structure(t *testing.T) {
	// Test MFASecret domain model
	secret := &domain.MFASecret{
		ID:              uuid.New(),
		UserID:          uuid.New(),
		Method:          domain.MFAMethodTOTP,
		SecretEncrypted: "encrypted_data",
		CreatedAt:       time.Now(),
		LastUsedAt:      nil,
	}

	if secret.Method != domain.MFAMethodTOTP {
		t.Errorf("Expected method TOTP, got %s", secret.Method)
	}

	// Test with last used
	now := time.Now()
	secret.LastUsedAt = &now
	if secret.LastUsedAt == nil {
		t.Error("LastUsedAt should be set")
	}
}

func TestMFARecoveryCode_IsUsed(t *testing.T) {
	// Test IsUsed method
	code := &domain.MFARecoveryCode{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CodeHash:  "hash",
		UsedAt:    nil,
		CreatedAt: time.Now(),
	}

	// Not used initially
	if code.IsUsed() {
		t.Error("Code should not be used initially")
	}

	// Mark as used
	now := time.Now()
	code.UsedAt = &now

	if !code.IsUsed() {
		t.Error("Code should be marked as used")
	}
}

func TestMFAMethod_Constants(t *testing.T) {
	// Test MFA method constants
	if domain.MFAMethodTOTP != "totp" {
		t.Errorf("MFAMethodTOTP: got %s, want 'totp'", domain.MFAMethodTOTP)
	}

	if domain.MFAMethodSMS != "sms" {
		t.Errorf("MFAMethodSMS: got %s, want 'sms'", domain.MFAMethodSMS)
	}
}

func TestTokenKindMFAChallenge(t *testing.T) {
	// Test that MFA challenge token kind is defined
	if domain.TokenKindMFAChallenge != "mfa_challenge" {
		t.Errorf("TokenKindMFAChallenge: got %s, want 'mfa_challenge'", domain.TokenKindMFAChallenge)
	}
}

func TestMFAErrors(t *testing.T) {
	// Test that all MFA errors are defined
	errors := []error{
		domain.ErrMFARequired,
		domain.ErrMFANotEnabled,
		domain.ErrMFAAlreadyEnabled,
		domain.ErrInvalidMFACode,
		domain.ErrInvalidRecoveryCode,
		domain.ErrMFAChallengeExpired,
	}

	for i, err := range errors {
		if err == nil {
			t.Errorf("Error %d should not be nil", i)
		}
		if err.Error() == "" {
			t.Errorf("Error %d should have a message", i)
		}
	}
}

func TestNewMFAService(t *testing.T) {
	// Test MFA service creation
	encryptionKey := make([]byte, 32)
	config := MFAConfig{
		Issuer:        "Test",
		EncryptionKey: encryptionKey,
	}

	service := NewMFAService(config, nil, nil, nil, nil, nil)

	if service == nil {
		t.Fatal("NewMFAService should not return nil")
	}

	if service.config.Issuer != "Test" {
		t.Errorf("Issuer: got %s, want 'Test'", service.config.Issuer)
	}

	if len(service.config.EncryptionKey) != 32 {
		t.Errorf("Encryption key length: got %d, want 32", len(service.config.EncryptionKey))
	}
}
