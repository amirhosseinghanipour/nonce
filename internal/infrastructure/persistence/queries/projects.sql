-- name: GetProjectByID :one
SELECT id, name, api_key_hash, created_at, updated_at
FROM projects
WHERE id = $1;

-- name: GetProjectByAPIKeyHash :one
SELECT id, name, api_key_hash, created_at, updated_at
FROM projects
WHERE api_key_hash = $1;
