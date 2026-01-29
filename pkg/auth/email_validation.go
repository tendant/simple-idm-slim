package auth

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// Common disposable email domains to block (can be extended)
var disposableDomains = map[string]bool{
	"tempmail.com":     true,
	"10minutemail.com": true,
	"guerrillamail.com": true,
	"mailinator.com":   true,
	"throwaway.email":  true,
}

// Email validation regex (stricter than RFC 5322 for practical use)
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

const maxEmailLength = 254 // RFC 5321

// ValidateEmail validates an email address for format and length.
func ValidateEmail(email string, strict bool, blockDisposable bool) error {
	if email == "" {
		return fmt.Errorf("email address is required")
	}

	// Check length
	if len(email) > maxEmailLength {
		return fmt.Errorf("email address is too long (max %d characters)", maxEmailLength)
	}

	// Normalize for validation
	normalized := NormalizeEmail(email)

	// Use mail.ParseAddress for basic RFC 5322 compliance
	addr, err := mail.ParseAddress(normalized)
	if err != nil {
		return fmt.Errorf("invalid email address format")
	}

	// Apply stricter validation if requested
	if strict {
		if !emailRegex.MatchString(addr.Address) {
			return fmt.Errorf("invalid email address format")
		}
	}

	// Check for disposable email domains if requested
	if blockDisposable {
		domain := getDomain(addr.Address)
		if disposableDomains[strings.ToLower(domain)] {
			return fmt.Errorf("disposable email addresses are not allowed")
		}
	}

	return nil
}

// NormalizeEmail normalizes an email address by lowercasing and trimming.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// getDomain extracts the domain from an email address.
func getDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
