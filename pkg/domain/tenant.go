package domain

import (
	"time"

	"github.com/google/uuid"
)

// Tenant represents an organization or workspace.
type Tenant struct {
	ID        uuid.UUID
	Name      string
	Slug      string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}
