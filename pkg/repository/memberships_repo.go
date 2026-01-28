package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// MembershipsRepository handles membership data persistence.
type MembershipsRepository struct {
	db *sql.DB
}

// NewMembershipsRepository creates a new memberships repository.
func NewMembershipsRepository(db *sql.DB) *MembershipsRepository {
	return &MembershipsRepository{db: db}
}

// MembershipWithTenant combines membership and tenant details for login flow.
type MembershipWithTenant struct {
	Membership domain.Membership
	Tenant     domain.Tenant
}

// Create creates a new membership.
func (r *MembershipsRepository) Create(ctx context.Context, membership *domain.Membership) error {
	return r.CreateTx(ctx, r.db, membership)
}

// CreateTx creates a new membership within a transaction.
func (r *MembershipsRepository) CreateTx(ctx context.Context, q Querier, membership *domain.Membership) error {
	query := `
		INSERT INTO memberships (id, tenant_id, user_id, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := q.ExecContext(ctx, query,
		membership.ID,
		membership.TenantID,
		membership.UserID,
		membership.Status,
		membership.CreatedAt,
		membership.UpdatedAt,
	)
	return err
}

// GetByID retrieves a membership by ID.
func (r *MembershipsRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Membership, error) {
	query := `
		SELECT id, tenant_id, user_id, status, created_at, updated_at, deleted_at
		FROM memberships
		WHERE id = $1 AND deleted_at IS NULL
	`

	var membership domain.Membership
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&membership.ID,
		&membership.TenantID,
		&membership.UserID,
		&membership.Status,
		&membership.CreatedAt,
		&membership.UpdatedAt,
		&membership.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrMembershipNotFound
		}
		return nil, err
	}

	return &membership, nil
}

// GetByUserAndTenant retrieves a membership for a user in a tenant.
func (r *MembershipsRepository) GetByUserAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*domain.Membership, error) {
	query := `
		SELECT id, tenant_id, user_id, status, created_at, updated_at, deleted_at
		FROM memberships
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	var membership domain.Membership
	err := r.db.QueryRowContext(ctx, query, userID, tenantID).Scan(
		&membership.ID,
		&membership.TenantID,
		&membership.UserID,
		&membership.Status,
		&membership.CreatedAt,
		&membership.UpdatedAt,
		&membership.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrMembershipNotFound
		}
		return nil, err
	}

	return &membership, nil
}

// GetByUserID retrieves all memberships for a user.
func (r *MembershipsRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Membership, error) {
	query := `
		SELECT id, tenant_id, user_id, status, created_at, updated_at, deleted_at
		FROM memberships
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []*domain.Membership
	for rows.Next() {
		var membership domain.Membership
		err := rows.Scan(
			&membership.ID,
			&membership.TenantID,
			&membership.UserID,
			&membership.Status,
			&membership.CreatedAt,
			&membership.UpdatedAt,
			&membership.DeletedAt,
		)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, &membership)
	}

	return memberships, rows.Err()
}

// GetByTenantID retrieves all members of a tenant.
func (r *MembershipsRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*domain.Membership, error) {
	query := `
		SELECT id, tenant_id, user_id, status, created_at, updated_at, deleted_at
		FROM memberships
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []*domain.Membership
	for rows.Next() {
		var membership domain.Membership
		err := rows.Scan(
			&membership.ID,
			&membership.TenantID,
			&membership.UserID,
			&membership.Status,
			&membership.CreatedAt,
			&membership.UpdatedAt,
			&membership.DeletedAt,
		)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, &membership)
	}

	return memberships, rows.Err()
}

// GetActiveMembershipsWithTenants retrieves active memberships with tenant details for login flow.
func (r *MembershipsRepository) GetActiveMembershipsWithTenants(ctx context.Context, userID uuid.UUID) ([]*MembershipWithTenant, error) {
	query := `
		SELECT
			m.id, m.tenant_id, m.user_id, m.status, m.created_at, m.updated_at, m.deleted_at,
			t.id, t.name, t.slug, t.created_at, t.updated_at, t.deleted_at
		FROM memberships m
		INNER JOIN tenants t ON m.tenant_id = t.id
		WHERE m.user_id = $1
			AND m.status = 'active'
			AND m.deleted_at IS NULL
			AND t.deleted_at IS NULL
		ORDER BY m.created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*MembershipWithTenant
	for rows.Next() {
		var result MembershipWithTenant
		err := rows.Scan(
			&result.Membership.ID,
			&result.Membership.TenantID,
			&result.Membership.UserID,
			&result.Membership.Status,
			&result.Membership.CreatedAt,
			&result.Membership.UpdatedAt,
			&result.Membership.DeletedAt,
			&result.Tenant.ID,
			&result.Tenant.Name,
			&result.Tenant.Slug,
			&result.Tenant.CreatedAt,
			&result.Tenant.UpdatedAt,
			&result.Tenant.DeletedAt,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, &result)
	}

	return results, rows.Err()
}

// UpdateStatus updates the status of a membership.
func (r *MembershipsRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status domain.MembershipStatus) error {
	query := `
		UPDATE memberships
		SET status = $1, updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query, status, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrMembershipNotFound
	}

	return nil
}

// SoftDelete soft deletes a membership.
func (r *MembershipsRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE memberships
		SET deleted_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrMembershipNotFound
	}

	return nil
}
