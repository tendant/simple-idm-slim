-- +goose Up
CREATE TABLE IF NOT EXISTS verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('email_verification', 'password_reset')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    metadata JSONB
);

CREATE INDEX idx_verification_tokens_token_hash ON verification_tokens(token_hash) WHERE consumed_at IS NULL;
CREATE INDEX idx_verification_tokens_user_kind ON verification_tokens(user_id, kind) WHERE consumed_at IS NULL;
CREATE UNIQUE INDEX idx_verification_tokens_active_unique ON verification_tokens(user_id, kind) WHERE consumed_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS verification_tokens;
