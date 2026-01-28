package domain

import (
	"time"

	"github.com/google/uuid"
)

// MembershipStatus represents the state of a user's membership.
type MembershipStatus string

const (
	MembershipStatusInvited   MembershipStatus = "invited"
	MembershipStatusActive    MembershipStatus = "active"
	MembershipStatusSuspended MembershipStatus = "suspended"
)

// Membership represents a user's membership in a tenant.
type Membership struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	UserID    uuid.UUID
	Status    MembershipStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// IsActive returns true if the membership is active.
func (m *Membership) IsActive() bool {
	return m.Status == MembershipStatusActive && m.DeletedAt == nil
}
