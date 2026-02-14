-- name: CreateUser :one
INSERT INTO users (id, project_id, email, password_hash, created_at, updated_at, is_anonymous, user_metadata, app_metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous, user_metadata, app_metadata, deleted_at;

-- name: GetUserByEmail :one
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous, user_metadata, app_metadata, deleted_at
FROM users
WHERE project_id = $1 AND email = $2 AND deleted_at IS NULL;

-- name: GetUserByID :one
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous, user_metadata, app_metadata, deleted_at
FROM users
WHERE project_id = $1 AND id = $2 AND deleted_at IS NULL;

-- name: ListUsersByProjectID :many
SELECT id, project_id, email, password_hash, created_at, updated_at, email_verified_at, is_anonymous, user_metadata, app_metadata, deleted_at
FROM users
WHERE project_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateUserMetadata :exec
UPDATE users SET user_metadata = $1, updated_at = NOW() WHERE project_id = $2 AND id = $3 AND deleted_at IS NULL;

-- name: UpdateAppMetadata :exec
UPDATE users SET app_metadata = $1, updated_at = NOW() WHERE project_id = $2 AND id = $3 AND deleted_at IS NULL;

-- name: SoftDeleteUser :exec
UPDATE users SET deleted_at = COALESCE(deleted_at, NOW()) WHERE project_id = $1 AND id = $2;

-- name: AnonymizeUser :exec
UPDATE users SET
  email = 'deleted-' || id::text || '@anonymized.local',
  password_hash = '',
  user_metadata = '{}',
  app_metadata = '{}',
  updated_at = NOW(),
  deleted_at = COALESCE(deleted_at, NOW())
WHERE project_id = $1 AND id = $2;

-- name: GetUsersDeletedBefore :many
SELECT id, project_id FROM users WHERE deleted_at IS NOT NULL AND deleted_at <= $1;

-- name: HardDeleteUser :exec
DELETE FROM users WHERE project_id = $1 AND id = $2 AND deleted_at IS NOT NULL;
