-- +goose Up
-- Add type to magic_links to support password_reset (and keep magic_link).
ALTER TABLE magic_links ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'magic_link';
CREATE INDEX IF NOT EXISTS idx_magic_links_type ON magic_links(type);

-- +goose Down
DROP INDEX IF EXISTS idx_magic_links_type;
ALTER TABLE magic_links DROP COLUMN IF EXISTS type;
