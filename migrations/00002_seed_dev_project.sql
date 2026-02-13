-- +goose Up
-- Dev project: API key is "dev-key", hash = SHA256("dev-key") = 7e9f8fd111802be56c379d597842e29b2cebd35ff2133d431a49fa556a18704e
INSERT INTO projects (id, name, api_key_hash, created_at, updated_at)
VALUES (
    'a0000000-0000-0000-0000-000000000001'::uuid,
    'Default Dev Project',
    '7e9f8fd111802be56c379d597842e29b2cebd35ff2133d431a49fa556a18704e',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM projects WHERE id = 'a0000000-0000-0000-0000-000000000001'::uuid;
