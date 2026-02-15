package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleJWKSURL     = "https://www.googleapis.com/oauth2/v3/certs"
	googleIssuer      = "https://accounts.google.com"
	googleIssuerAlt   = "accounts.google.com"
)

// GoogleConfig holds Google OAuth configuration.
type GoogleConfig struct {
	ClientID       string
	ClientSecret   string
	RedirectURI    string
	MobileClientIDs []string
}

// GoogleClaims represents the claims from a Google ID token.
type GoogleClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// GoogleService handles Google OAuth authentication.
type GoogleService struct {
	config     GoogleConfig
	db         *sql.DB
	users      *repository.UsersRepository
	identities *repository.IdentitiesRepository
	httpClient *http.Client
}

// NewGoogleService creates a new Google service.
func NewGoogleService(
	config GoogleConfig,
	db *sql.DB,
	users *repository.UsersRepository,
	identities *repository.IdentitiesRepository,
) *GoogleService {
	return &GoogleService{
		config:     config,
		db:         db,
		users:      users,
		identities: identities,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// OAuthState holds state for OAuth flow.
type OAuthState struct {
	State       string
	Nonce       string
	RedirectURI string
	ExpiresAt   time.Time
}

// GenerateAuthURL generates the Google OAuth authorization URL.
func (s *GoogleService) GenerateAuthURL(state, nonce string) string {
	params := url.Values{
		"client_id":     {s.config.ClientID},
		"redirect_uri":  {s.config.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"nonce":         {nonce},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	return googleAuthURL + "?" + params.Encode()
}

// GoogleTokenResponse represents the response from Google token endpoint.
type GoogleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// ExchangeCode exchanges an authorization code for tokens.
func (s *GoogleService) ExchangeCode(ctx context.Context, code string) (*GoogleTokenResponse, error) {
	data := url.Values{
		"code":          {code},
		"client_id":     {s.config.ClientID},
		"client_secret": {s.config.ClientSecret},
		"redirect_uri":  {s.config.RedirectURI},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp GoogleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// ValidateIDToken validates a Google ID token and extracts claims.
// Note: For production, you should verify the signature using Google's JWKS.
// This implementation does basic validation; add signature verification for production.
func (s *GoogleService) ValidateIDToken(ctx context.Context, idToken, expectedNonce string) (*GoogleClaims, error) {
	// Parse without verification first to get claims
	// In production, use jwt.Parse with proper key func to verify signature
	token, _, err := jwt.NewParser().ParseUnverified(idToken, &GoogleClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	claims, ok := token.Claims.(*GoogleClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	// Validate issuer
	if claims.Issuer != googleIssuer && claims.Issuer != googleIssuerAlt {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Issuer)
	}

	// Validate audience (accept web client ID or any mobile client ID)
	validAudience := false
	if len(claims.Audience) > 0 {
		aud := claims.Audience[0]
		if aud == s.config.ClientID {
			validAudience = true
		} else {
			for _, mobileID := range s.config.MobileClientIDs {
				if mobileID != "" && aud == mobileID {
					validAudience = true
					break
				}
			}
		}
	}
	if !validAudience {
		return nil, errors.New("invalid audience")
	}

	// Validate expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// Authenticate handles the Google OAuth callback and returns a user ID.
// It either finds an existing user or creates a new one.
func (s *GoogleService) Authenticate(ctx context.Context, claims *GoogleClaims) (uuid.UUID, error) {
	// 1. Check if identity already exists
	identity, err := s.identities.GetByProviderSubject(ctx, domain.ProviderGoogle, claims.Subject)
	if err == nil {
		// Identity exists, return linked user
		return identity.UserID, nil
	}
	if !errors.Is(err, domain.ErrIdentityNotFound) {
		return uuid.Nil, err
	}

	// 2. Check if user exists by email (for auto-linking)
	user, err := s.users.GetByEmail(ctx, claims.Email)
	if err == nil && claims.EmailVerified {
		// User exists and Google email is verified - link identity
		identity := &domain.UserIdentity{
			ID:              uuid.New(),
			UserID:          user.ID,
			Provider:        domain.ProviderGoogle,
			ProviderSubject: claims.Subject,
			Email:           &claims.Email,
			CreatedAt:       time.Now(),
		}
		if err := s.identities.Create(ctx, identity); err != nil {
			return uuid.Nil, err
		}
		return user.ID, nil
	}
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return uuid.Nil, err
	}

	// 3. Create new user and link identity
	now := time.Now()
	newUser := &domain.User{
		ID:            uuid.New(),
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          &claims.Name,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	newIdentity := &domain.UserIdentity{
		ID:              uuid.New(),
		UserID:          newUser.ID,
		Provider:        domain.ProviderGoogle,
		ProviderSubject: claims.Subject,
		Email:           &claims.Email,
		CreatedAt:       now,
	}

	err = repository.Tx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.users.CreateTx(ctx, tx, newUser); err != nil {
			return err
		}
		return s.identities.CreateTx(ctx, tx, newIdentity)
	})
	if err != nil {
		return uuid.Nil, err
	}

	return newUser.ID, nil
}
