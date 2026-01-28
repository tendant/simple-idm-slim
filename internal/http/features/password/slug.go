package password

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// generateTenantSlug creates a unique slug from an email address.
// Format: <sanitized-username>-<random>
// Example: john-abc12345
func generateTenantSlug(email string) string {
	// Extract username part (before @)
	parts := strings.Split(email, "@")
	username := parts[0]

	// Remove special chars, lowercase, and limit length
	reg := regexp.MustCompile(`[^a-z0-9]+`)
	slug := reg.ReplaceAllString(strings.ToLower(username), "")

	// Ensure slug is not empty
	if slug == "" {
		slug = "user"
	}

	// Limit to 20 characters
	if len(slug) > 20 {
		slug = slug[:20]
	}

	// Add random suffix for uniqueness (first 8 chars of UUID)
	random := strings.Replace(uuid.New().String(), "-", "", -1)[:8]
	return fmt.Sprintf("%s-%s", slug, random)
}
