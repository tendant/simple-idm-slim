-- +goose Up

-- Add tenant_id to sessions (NOT NULL - clean break, force re-login)
ALTER TABLE sessions
ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE;

-- Add index for tenant-scoped session queries
CREATE INDEX idx_sessions_tenant_id ON sessions(tenant_id) WHERE revoked_at IS NULL;

-- Create composite index for user+tenant session lookups
CREATE INDEX idx_sessions_user_tenant ON sessions(user_id, tenant_id) WHERE revoked_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_user_tenant;
DROP INDEX IF EXISTS idx_sessions_tenant_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS tenant_id;
