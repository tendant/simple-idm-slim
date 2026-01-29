package auth

import (
	"fmt"
	"html"
	"strings"
	"unicode"
)

// SanitizeInput sanitizes user input by escaping HTML and removing control characters.
func SanitizeInput(input string) string {
	// Remove control characters (except newline and tab)
	cleaned := removeControlChars(input)

	// HTML escape to prevent XSS
	return html.EscapeString(cleaned)
}

// SanitizeName sanitizes a name field (unicode-friendly, allows letters and spaces).
func SanitizeName(name string) string {
	// Trim whitespace
	name = strings.TrimSpace(name)

	// Remove control characters
	name = removeControlChars(name)

	// HTML escape for safety
	return html.EscapeString(name)
}

// ValidateStringLength validates that a string is within the specified length constraints.
func ValidateStringLength(field, value string, min, max int) error {
	length := len(value)

	if min > 0 && length < min {
		return fmt.Errorf("%s must be at least %d characters long", field, min)
	}

	if max > 0 && length > max {
		return fmt.Errorf("%s must be at most %d characters long", field, max)
	}

	return nil
}

// removeControlChars removes control characters except newline and tab.
func removeControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		// Keep newline, carriage return, and tab
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		// Remove other control characters
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
