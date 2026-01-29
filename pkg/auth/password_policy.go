package auth

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/tendant/simple-idm-slim/internal/config"
)

// PasswordPolicy defines password complexity requirements.
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

// NewPasswordPolicy creates a PasswordPolicy from config.
func NewPasswordPolicy(cfg config.PasswordPolicyConfig) *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        cfg.MinLength,
		RequireUppercase: cfg.RequireUppercase,
		RequireLowercase: cfg.RequireLowercase,
		RequireNumber:    cfg.RequireNumber,
		RequireSpecial:   cfg.RequireSpecial,
	}
}

// ValidatePassword checks if a password meets the policy requirements.
func (p *PasswordPolicy) ValidatePassword(password string) error {
	// Check minimum length
	if p.MinLength > 0 && len(password) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinLength)
	}

	// Check uppercase requirement
	if p.RequireUppercase && !containsUppercase(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	// Check lowercase requirement
	if p.RequireLowercase && !containsLowercase(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	// Check number requirement
	if p.RequireNumber && !containsNumber(password) {
		return fmt.Errorf("password must contain at least one number")
	}

	// Check special character requirement
	if p.RequireSpecial && !containsSpecial(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// GetRequirements returns a human-readable description of the policy.
func (p *PasswordPolicy) GetRequirements() string {
	if !p.HasRequirements() {
		return "No password requirements"
	}

	var requirements []string

	if p.MinLength > 0 {
		requirements = append(requirements, fmt.Sprintf("at least %d characters", p.MinLength))
	}
	if p.RequireUppercase {
		requirements = append(requirements, "one uppercase letter")
	}
	if p.RequireLowercase {
		requirements = append(requirements, "one lowercase letter")
	}
	if p.RequireNumber {
		requirements = append(requirements, "one number")
	}
	if p.RequireSpecial {
		requirements = append(requirements, "one special character")
	}

	return "Password must contain " + strings.Join(requirements, ", ")
}

// HasRequirements returns true if the policy has any requirements.
func (p *PasswordPolicy) HasRequirements() bool {
	return p.MinLength > 0 || p.RequireUppercase || p.RequireLowercase || p.RequireNumber || p.RequireSpecial
}

// containsUppercase checks if string contains at least one uppercase letter.
func containsUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// containsLowercase checks if string contains at least one lowercase letter.
func containsLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

// containsNumber checks if string contains at least one digit.
func containsNumber(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// containsSpecial checks if string contains at least one special character.
func containsSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}
