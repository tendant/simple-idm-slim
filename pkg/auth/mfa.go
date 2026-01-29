package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

const (
	// TOTP parameters
	totpDigits = 6
	totpPeriod = 30
	totpWindow = 1 // Allow ±30 seconds clock drift

	// Recovery code parameters
	recoveryCodeLength = 12
	recoveryCodeCount  = 8
	recoveryCodeChars  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // No ambiguous chars

	// MFA challenge parameters
	mfaChallengeTokenTTL = 5 * time.Minute
)

// MFAConfig contains configuration for the MFA service
type MFAConfig struct {
	Issuer        string // e.g., "Simple IDM"
	EncryptionKey []byte // 32 bytes for AES-256
}

// MFAService handles multi-factor authentication operations
type MFAService struct {
	config        MFAConfig
	db            *sql.DB
	secrets       *repository.MFASecretsRepository
	recoveryCodes *repository.MFARecoveryCodesRepository
	users         *repository.UsersRepository
	tokens        *repository.VerificationTokensRepository
}

// NewMFAService creates a new MFA service
func NewMFAService(
	config MFAConfig,
	db *sql.DB,
	secrets *repository.MFASecretsRepository,
	recoveryCodes *repository.MFARecoveryCodesRepository,
	users *repository.UsersRepository,
	tokens *repository.VerificationTokensRepository,
) *MFAService {
	return &MFAService{
		config:        config,
		db:            db,
		secrets:       secrets,
		recoveryCodes: recoveryCodes,
		users:         users,
		tokens:        tokens,
	}
}

// SetupTOTP generates a new TOTP secret and recovery codes for a user
func (s *MFAService) SetupTOTP(ctx context.Context, userID uuid.UUID) (*domain.MFASetupResponse, error) {
	// Check if MFA is already enabled
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.MFAEnabled {
		return nil, domain.ErrMFAAlreadyEnabled
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.Issuer,
		AccountName: user.Email,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate QR code
	var qrBuf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code image: %w", err)
	}
	if err := png.Encode(&qrBuf, img); err != nil {
		return nil, fmt.Errorf("failed to encode QR code: %w", err)
	}
	qrDataURI := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(qrBuf.Bytes()))

	// Generate recovery codes
	plainRecoveryCodes := make([]string, recoveryCodeCount)
	hashedRecoveryCodes := make([]*domain.MFARecoveryCode, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate recovery code: %w", err)
		}
		plainRecoveryCodes[i] = code

		// Hash the recovery code
		hash, err := s.hashRecoveryCode(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash recovery code: %w", err)
		}

		hashedRecoveryCodes[i] = &domain.MFARecoveryCode{
			ID:        uuid.New(),
			UserID:    userID,
			CodeHash:  hash,
			CreatedAt: time.Now(),
		}
	}

	// Encrypt TOTP secret
	encryptedSecret, err := s.encryptSecret(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Store in database within a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete any existing MFA setup (in case of re-setup)
	if err := s.secrets.DeleteAllByUserID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to delete existing MFA secrets: %w", err)
	}
	if err := s.recoveryCodes.DeleteAllByUserID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to delete existing recovery codes: %w", err)
	}

	// Create MFA secret
	secret := &domain.MFASecret{
		ID:              uuid.New(),
		UserID:          userID,
		Method:          domain.MFAMethodTOTP,
		SecretEncrypted: encryptedSecret,
		CreatedAt:       time.Now(),
	}
	if err := s.secrets.Create(ctx, secret); err != nil {
		return nil, fmt.Errorf("failed to create MFA secret: %w", err)
	}

	// Create recovery codes
	if err := s.recoveryCodes.CreateBatch(ctx, hashedRecoveryCodes); err != nil {
		return nil, fmt.Errorf("failed to create recovery codes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &domain.MFASetupResponse{
		Secret:        key.Secret(),
		QRCodeDataURI: qrDataURI,
		RecoveryCodes: plainRecoveryCodes,
	}, nil
}

// VerifyTOTPAndEnable verifies a TOTP code and enables MFA for the user
func (s *MFAService) VerifyTOTPAndEnable(ctx context.Context, userID uuid.UUID, code string) error {
	// Get MFA secret
	secret, err := s.secrets.GetByUserIDAndMethod(ctx, userID, domain.MFAMethodTOTP)
	if err != nil {
		return err
	}

	// Decrypt secret
	decryptedSecret, err := s.decryptSecret(secret.SecretEncrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Verify TOTP code
	valid, err := totp.ValidateCustom(code, decryptedSecret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("failed to validate TOTP code: %w", err)
	}
	if !valid {
		return domain.ErrInvalidMFACode
	}

	// Enable MFA for user
	if err := s.users.UpdateMFAEnabled(ctx, userID, true); err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Update last used timestamp
	if err := s.secrets.UpdateLastUsed(ctx, secret.ID); err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	return nil
}

// VerifyTOTP verifies a TOTP code for an MFA-enabled user
func (s *MFAService) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	// Get MFA secret
	secret, err := s.secrets.GetByUserIDAndMethod(ctx, userID, domain.MFAMethodTOTP)
	if err != nil {
		return false, err
	}

	// Decrypt secret
	decryptedSecret, err := s.decryptSecret(secret.SecretEncrypted)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Verify TOTP code
	valid, err := totp.ValidateCustom(code, decryptedSecret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindow,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false, fmt.Errorf("failed to validate TOTP code: %w", err)
	}

	if valid {
		// Update last used timestamp
		if err := s.secrets.UpdateLastUsed(ctx, secret.ID); err != nil {
			return false, fmt.Errorf("failed to update last used: %w", err)
		}
	}

	return valid, nil
}

// VerifyRecoveryCode verifies and consumes a recovery code
func (s *MFAService) VerifyRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	// Normalize the code (remove dashes and spaces, uppercase)
	normalizedCode := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(code, "-", ""), " ", ""))

	// Hash the code
	hash, err := s.hashRecoveryCode(normalizedCode)
	if err != nil {
		return false, fmt.Errorf("failed to hash recovery code: %w", err)
	}

	// Find the recovery code
	recoveryCode, err := s.recoveryCodes.GetByCodeHash(ctx, hash)
	if err != nil {
		return false, err
	}

	// Verify it belongs to the user
	if recoveryCode.UserID != userID {
		return false, domain.ErrInvalidRecoveryCode
	}

	// Check if already used
	if recoveryCode.IsUsed() {
		return false, domain.ErrInvalidRecoveryCode
	}

	// Mark as used
	if err := s.recoveryCodes.MarkUsed(ctx, recoveryCode.ID); err != nil {
		return false, fmt.Errorf("failed to mark recovery code as used: %w", err)
	}

	return true, nil
}

// DisableMFA disables MFA for a user and removes all MFA data
func (s *MFAService) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	// Start transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete all MFA secrets
	if err := s.secrets.DeleteAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete MFA secrets: %w", err)
	}

	// Delete all recovery codes
	if err := s.recoveryCodes.DeleteAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}

	// Disable MFA flag
	if err := s.users.UpdateMFAEnabled(ctx, userID, false); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// CreateMFAChallenge creates a challenge token for MFA verification
func (s *MFAService) CreateMFAChallenge(ctx context.Context, userID uuid.UUID, ip, userAgent string) (string, error) {
	// Create metadata
	metadata := map[string]interface{}{
		"user_id":           userID.String(),
		"password_verified": true,
		"ip":                ip,
		"user_agent":        userAgent,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Generate token
	rawToken := generateSecureToken()
	tokenHash := hashToken(rawToken)

	// Create verification token
	token := &domain.VerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		Kind:      domain.TokenKindMFAChallenge,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(mfaChallengeTokenTTL),
		Metadata:  metadataJSON,
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return "", fmt.Errorf("failed to create MFA challenge token: %w", err)
	}

	return rawToken, nil
}

// ValidateMFAChallenge validates a challenge token and returns the user ID
func (s *MFAService) ValidateMFAChallenge(ctx context.Context, challengeToken string) (uuid.UUID, error) {
	tokenHash := hashToken(challengeToken)

	token, err := s.tokens.GetByTokenHash(ctx, tokenHash, domain.TokenKindMFAChallenge)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationTokenNotFound) {
			return uuid.Nil, domain.ErrMFAChallengeExpired
		}
		return uuid.Nil, err
	}

	if !token.IsValid() {
		return uuid.Nil, domain.ErrMFAChallengeExpired
	}

	return token.UserID, nil
}

// ConsumeMFAChallenge marks a challenge token as consumed
func (s *MFAService) ConsumeMFAChallenge(ctx context.Context, challengeToken string) error {
	tokenHash := hashToken(challengeToken)

	token, err := s.tokens.GetByTokenHash(ctx, tokenHash, domain.TokenKindMFAChallenge)
	if err != nil {
		return err
	}

	return s.tokens.MarkConsumed(ctx, token.ID)
}

// GetMFAStatus returns the MFA status for a user
func (s *MFAService) GetMFAStatus(ctx context.Context, userID uuid.UUID) (enabled bool, recoveryCodesRemaining int, err error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return false, 0, err
	}

	if !user.MFAEnabled {
		return false, 0, nil
	}

	count, err := s.recoveryCodes.CountUnused(ctx, userID)
	if err != nil {
		return false, 0, err
	}

	return true, count, nil
}

// encryptSecret encrypts a plaintext secret using AES-256-GCM
func (s *MFAService) encryptSecret(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.config.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSecret decrypts an encrypted secret using AES-256-GCM
func (s *MFAService) decryptSecret(encrypted string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(s.config.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// hashRecoveryCode hashes a recovery code using Argon2id (same as passwords)
func (s *MFAService) hashRecoveryCode(code string) (string, error) {
	return HashPassword(code)
}

// generateRecoveryCode generates a random recovery code in format XXXX-XXXX-XXXX
func generateRecoveryCode() (string, error) {
	chars := make([]byte, recoveryCodeLength)
	if _, err := rand.Read(chars); err != nil {
		return "", err
	}

	for i := range chars {
		chars[i] = recoveryCodeChars[int(chars[i])%len(recoveryCodeChars)]
	}

	// Format as XXXX-XXXX-XXXX
	return fmt.Sprintf("%s-%s-%s",
		string(chars[0:4]),
		string(chars[4:8]),
		string(chars[8:12]),
	), nil
}

// hashToken hashes a token using SHA-256
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
