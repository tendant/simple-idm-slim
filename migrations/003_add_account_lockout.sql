-- +goose Up
-- Migration: 003_add_account_lockout
-- Description: Add columns for tracking failed login attempts and account lockout

-- Add lockout tracking columns to users table
ALTER TABLE users
ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0,
ADD COLUMN locked_until TIMESTAMPTZ;

-- Create index for finding locked accounts
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;

-- +goose Down
-- Remove lockout tracking
DROP INDEX IF EXISTS idx_users_locked_until;
ALTER TABLE users
DROP COLUMN IF EXISTS failed_login_attempts,
DROP COLUMN IF EXISTS locked_until;
