package common

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

// EnsureTenantMembership ensures the user has at least one tenant membership.
// If user has no memberships, creates a personal tenant and active membership.
// Returns the selected membership and tenant, or an error.
func EnsureTenantMembership(
	ctx context.Context,
	userID uuid.UUID,
	userEmail, userName string,
	tenantsRepo *repository.TenantsRepository,
	membershipsRepo *repository.MembershipsRepository,
) (*repository.MembershipWithTenant, error) {
	// Fetch active memberships
	memberships, err := membershipsRepo.GetActiveMembershipsWithTenants(ctx, userID)
	if err != nil {
		return nil, err
	}

	// If user has memberships, return the first one
	if len(memberships) > 0 {
		return memberships[0], nil
	}

	// No memberships - create personal tenant and membership
	tenantID := uuid.New()
	membershipID := uuid.New()
	tenantSlug := generateTenantSlug(userEmail)
	tenantName := userName + "'s Workspace"
	if userName == "" {
		tenantName = "Personal Workspace"
	}

	now := time.Now()
	tenant := &domain.Tenant{
		ID:        tenantID,
		Name:      tenantName,
		Slug:      tenantSlug,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := tenantsRepo.Create(ctx, tenant); err != nil {
		return nil, err
	}

	// Create active membership
	membership := &domain.Membership{
		ID:        membershipID,
		TenantID:  tenantID,
		UserID:    userID,
		Status:    domain.MembershipStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := membershipsRepo.Create(ctx, membership); err != nil {
		return nil, err
	}

	// Return the newly created membership with tenant
	return &repository.MembershipWithTenant{
		Membership: *membership,
		Tenant:     *tenant,
	}, nil
}

// generateTenantSlug creates a unique slug from an email address.
func generateTenantSlug(email string) string {
	// Simple implementation - use first part of email + UUID
	// (same logic as password handler)
	parts := string(email)
	if len(parts) > 20 {
		parts = parts[:20]
	}
	random := uuid.New().String()[:8]
	return parts + "-" + random
}
