-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (id, project_id, user_id, token_hash, expires_at, created_at, parent_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, project_id, user_id, token_hash, expires_at, created_at, parent_id, revoked_at;

-- name: GetRefreshTokenByHash :one
SELECT id, project_id, user_id, token_hash, expires_at, created_at, parent_id, revoked_at
FROM refresh_tokens
WHERE token_hash = $1;

-- name: SetRefreshTokenRevoked :exec
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at <= NOW();
