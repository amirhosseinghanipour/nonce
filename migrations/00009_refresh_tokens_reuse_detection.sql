-- +goose Up
-- parent_id links to the token this one replaced (rotation chain); NULL for initial token.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES refresh_tokens(id);
-- revoked_at set when token is rotated (used) or when revoking the family on reuse.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS parent_id;
