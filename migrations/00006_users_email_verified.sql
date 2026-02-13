-- +goose Up
-- Add email_verified_at for email verification flow.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
