-- name: CreateUser :one
INSERT INTO users (id, project_id, email, password_hash, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, project_id, email, password_hash, created_at, updated_at, email_verified_at;

-- name: GetUserByEmail :one
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at
FROM users
WHERE project_id = $1 AND email = $2;

-- name: GetUserByID :one
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at
FROM users
WHERE project_id = $1 AND id = $2;
