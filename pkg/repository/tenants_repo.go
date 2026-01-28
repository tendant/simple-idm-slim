package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// TenantsRepository handles tenant data persistence.
type TenantsRepository struct {
	db *sql.DB
}

// NewTenantsRepository creates a new tenants repository.
func NewTenantsRepository(db *sql.DB) *TenantsRepository {
	return &TenantsRepository{db: db}
}

// Create creates a new tenant.
func (r *TenantsRepository) Create(ctx context.Context, tenant *domain.Tenant) error {
	return r.CreateTx(ctx, r.db, tenant)
}

// CreateTx creates a new tenant within a transaction.
func (r *TenantsRepository) CreateTx(ctx context.Context, q Querier, tenant *domain.Tenant) error {
	query := `
		INSERT INTO tenants (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := q.ExecContext(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Slug,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)
	return err
}

// GetByID retrieves a tenant by ID.
func (r *TenantsRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	query := `
		SELECT id, name, slug, created_at, updated_at, deleted_at
		FROM tenants
		WHERE id = $1 AND deleted_at IS NULL
	`

	var tenant domain.Tenant
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
		&tenant.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrTenantNotFound
		}
		return nil, err
	}

	return &tenant, nil
}

// GetBySlug retrieves a tenant by slug.
func (r *TenantsRepository) GetBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	query := `
		SELECT id, name, slug, created_at, updated_at, deleted_at
		FROM tenants
		WHERE slug = $1 AND deleted_at IS NULL
	`

	var tenant domain.Tenant
	err := r.db.QueryRowContext(ctx, query, slug).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
		&tenant.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrTenantNotFound
		}
		return nil, err
	}

	return &tenant, nil
}

// Update updates a tenant.
func (r *TenantsRepository) Update(ctx context.Context, tenant *domain.Tenant) error {
	query := `
		UPDATE tenants
		SET name = $1, slug = $2, updated_at = NOW()
		WHERE id = $3 AND deleted_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query,
		tenant.Name,
		tenant.Slug,
		tenant.ID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrTenantNotFound
	}

	return nil
}

// SoftDelete soft deletes a tenant.
func (r *TenantsRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE tenants
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
		return domain.ErrTenantNotFound
	}

	return nil
}
