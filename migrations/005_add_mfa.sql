-- +goose Up
-- Add MFA flag to users table
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- MFA secrets table (encrypted TOTP secrets)
CREATE TABLE mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK (method IN ('totp', 'sms')),
    secret_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE(user_id, method)
);

CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets(user_id);

-- Recovery codes table (hashed)
CREATE TABLE mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);
CREATE INDEX idx_mfa_recovery_codes_code_hash ON mfa_recovery_codes(code_hash);

-- Extend verification tokens to support MFA challenge
ALTER TABLE verification_tokens DROP CONSTRAINT IF EXISTS verification_tokens_kind_check;
ALTER TABLE verification_tokens ADD CONSTRAINT verification_tokens_kind_check
    CHECK (kind IN ('email_verification', 'password_reset', 'mfa_challenge'));

-- +goose Down
-- Remove MFA challenge from verification tokens
ALTER TABLE verification_tokens DROP CONSTRAINT IF EXISTS verification_tokens_kind_check;
ALTER TABLE verification_tokens ADD CONSTRAINT verification_tokens_kind_check
    CHECK (kind IN ('email_verification', 'password_reset'));

-- Drop MFA tables
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_secrets;

-- Remove MFA flag from users
ALTER TABLE users DROP COLUMN IF EXISTS mfa_enabled;
