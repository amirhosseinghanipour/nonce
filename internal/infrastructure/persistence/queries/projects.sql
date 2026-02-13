-- name: CreateProject :one
INSERT INTO projects (id, name, api_key_hash, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, name, api_key_hash, created_at, updated_at;

-- name: GetProjectByID :one
SELECT id, name, api_key_hash, created_at, updated_at
FROM projects
WHERE id = $1;

-- name: GetProjectByAPIKeyHash :one
SELECT id, name, api_key_hash, created_at, updated_at
FROM projects
WHERE api_key_hash = $1;

-- name: UpdateProjectAPIKeyHash :exec
UPDATE projects SET api_key_hash = $1, updated_at = $2 WHERE id = $3;
