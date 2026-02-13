-- name: CreateUser :one
INSERT INTO users (id, project_id, email, password_hash, created_at, updated_at, is_anonymous)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous;

-- name: GetUserByEmail :one
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous
FROM users
WHERE project_id = $1 AND email = $2;

-- name: GetUserByID :one
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous
FROM users
WHERE project_id = $1 AND id = $2;

-- name: ListUsersByProjectID :many
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous
FROM users
WHERE project_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
